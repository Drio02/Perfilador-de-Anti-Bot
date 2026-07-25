'''
Motor de detección de vendors.
 
Carga las firmas del YAML (validadas con pydantic), puntúa cada una contra un
ProbeResult, filtra por umbral e intenta identificar al enforcer.
 
Opera sobre UN ProbeResult, no sobre la matriz: "qué vendor hay en esta
respuesta" es una propiedad de una respuesta. La comparación entre perfiles es
trabajo de la Fase 4.
'''

from __future__ import annotations
 
from enum import Enum
from functools import lru_cache
from pathlib import Path
 
import yaml
from pydantic import BaseModel, Field
 
from scout.models import Detection, ProbeResult, VendorMatch, VendorRole
 
_SIGNATURES_PATH = Path(__file__).parent / "signatures.yaml"


_MIN_CONFIDENCE = 0.35

_CONFIDENCE_CAP = 1.0

class SignalType(str, Enum):
    HEADER_PRESENT = "header_present"
    HEADER_VALUE = "header_value"
    COOKIE_PRESENT = "cookie_present"
    BODY_CONTAINS = "body_contains"

class Signal(BaseModel):
    model_config = {'frozen' : True}

    type: SignalType
    weight: float = Field(gt=0.0, le=1.0)
    implies_role: VendorRole
    key: str | None = None
    value: str | None = None
    enforcement: bool = False

    def describe(self) -> str:
        if self.type is SignalType.HEADER_PRESENT:
            return f'header: {self.key}'
        if self.type is SignalType.HEADER_VALUE:
            return f'header {self.key}={self.value}'
        if self.type is SignalType.COOKIE_PRESENT:
            return f'cookie {self.key}'
        return f'body contains {self.value!r}'

class VendorSignature(BaseModel):
    model_config = {"frozen": True}
 
    id: str
    name: str
    signals: tuple[Signal, ...] = Field(min_length=1)
 
 
class SignatureDB(BaseModel):
    model_config = {"frozen": True}
 
    version: int
    vendors: tuple[VendorSignature, ...]

@lru_cache(maxsize=1)
def load_signatures(path: str | None = None) -> SignatureDB:
    p = Path(path) if path else _SIGNATURES_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return SignatureDB.model_validate(data)

def _signal_hits(signal: Signal, result: ProbeResult) -> bool:
    '''
    This signal is present in the result?
    '''
    if signal.type is SignalType.HEADER_PRESENT:
        return result.header(signal.key) is not None
    if signal.type is SignalType.HEADER_VALUE:
        val = result.header(signal.key)
        return val is not None and signal.value.lower() in val.lower()
    if signal.type is SignalType.COOKIE_PRESENT:
        # Las cookies de bloqueo a veces llegan en Set-Cookie, no en el jar.
        # Miramos ambos sitios.
        if signal.key.lower() in result.cookies:
            return True
        set_cookie = result.header("set-cookie") or ""
        return signal.key.lower() in set_cookie.lower()
    if signal.type is SignalType.BODY_CONTAINS:
        return result.body is not None and signal.value.lower() in result.body.lower()
    return False

def _match_vendor(sig: VendorSignature, result: ProbeResult) -> tuple[VendorMatch | None, bool]:
    '''
    
    return [match, has_enforcement].
    has_enforcement define if some blocked signal of any vendor was active
    '''
    total = 0.0
    roles: set[VendorRole] = set()
    evidence: list[str] = []
    has_enforcement = False
 
    for signal in sig.signals:
        if _signal_hits(signal, result):
            total += signal.weight
            roles.add(signal.implies_role)
            evidence.append(signal.describe())
            if signal.enforcement:
                has_enforcement = True
 
    if not evidence:
        return None, False
 
    confidence = min(total / _CONFIDENCE_CAP, 1.0)
    if confidence < _MIN_CONFIDENCE:
        return None, False
 
    return (
        VendorMatch(
            vendor_id=sig.id,
            name=sig.name,
            confidence=round(confidence, 2),
            roles=frozenset(roles),
            evidence=tuple(evidence),
        ),
        has_enforcement,
    )

def detect(result: ProbeResult, db: SignatureDB | None = None) -> Detection:
    '''
    Detect all the vendors present in one ProbeResult
    Identify the enforcer if any blocker existed
    '''
    db = db or load_signatures()
 
    matches: list[VendorMatch] = []
    enforcing: set[str] = set()
    for sig in db.vendors:
        match, has_enforcement = _match_vendor(sig, result)
        if match is not None:
            matches.append(match)
            if has_enforcement:
                enforcing.add(match.vendor_id)
 
    matches.sort(key=lambda m: m.confidence, reverse=True)
    ordered = tuple(matches)
 
    return Detection(
        matches=ordered,
        enforcer_id=_identify_enforcer(ordered, enforcing, result),
    )

def _identify_enforcer(matches: tuple[VendorMatch, ...], enforcing: set[str], result: ProbeResult) -> str | None:
    '''
    If there is any blocker, this function identify which vendors was the responsible
    '''
    if not result.looks_denied:
        return None

    for m in matches:
        if m.vendor_id in enforcing:
            return m.vendor_id
 
    defenses = [m for m in matches if m.is_bot_defense]
    return defenses[0].vendor_id if defenses else None
