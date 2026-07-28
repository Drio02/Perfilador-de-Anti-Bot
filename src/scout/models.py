"""
Contratos de datos que atraviesan todo el pipeline.

    ProbeResult  -> qué pasó cuando UN perfil visitó UNA url
    ProbeMatrix  -> todos los ProbeResult de un objetivo, comparables entre sí

Ningún módulo se pasa diccionarios sueltos: todo lo que cruza una frontera es
uno de estos objetos, validado por pydantic.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ProbeOutcome(str, Enum):


    RESPONSE = "response"
    DNS_ERROR = "dns_error"
    CONNECT_ERROR = "connect_error"
    TLS_ERROR = "tls_error"
    CONNECTION_RESET = "connection_reset"
    TIMEOUT = "timeout"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    UNKNOWN_ERROR = "unknown_error"

    @property
    def reached_application(self) -> bool:
        return self is ProbeOutcome.RESPONSE

    @property
    def blocked_below_http(self) -> bool:
        return self in {
            ProbeOutcome.TLS_ERROR,
            ProbeOutcome.CONNECTION_RESET,
            ProbeOutcome.CONNECT_ERROR,
        }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProbeResult(BaseModel):
    '''
    All we know about a request: a profile, a URL. Immutable.
    '''

    model_config = {"frozen": True}

    profile: str
    url: str
    timestamp: datetime = Field(default_factory=_utcnow)

    outcome: ProbeOutcome
    error_detail: str | None = Field(
        default=None,
        description='Raw message. Just for debug y find cases that need its own ProbeOutcome'
    )

    elapsed_ms: float = 0.0

    status_code: int | None = None
    http_version: str | None = Field(
        default=None,
        description='HTTP/1.1 or HTTP/2. Some webs downgrade to 1.1 the unlike clients'
    )
    final_url: str | None = Field(
        default=None,
        description='URL after follow redirections. If change, the web sent you to a verification page'
    )
    redirect_chain: list[str] = Field(default_factory=list)

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    body_size: int = 0
    body_sha256: str | None = None
    body: str | None = Field(default=None, exclude=True)

    @classmethod
    def from_response(
        cls,
        *,
        profile: str,
        url: str,
        status_code: int,
        headers: dict[str, str],
        cookies: dict[str, str],
        body: str,
        elapsed_ms: float,
        http_version: str | None = None,
        final_url: str | None = None,
        redirect_chain: list[str] | None = None,
    ) -> ProbeResult:
        raw = body.encode("utf-8", errors="replace")
        return cls(
            profile=profile,
            url=url,
            outcome=ProbeOutcome.RESPONSE,
            status_code=status_code,
            http_version=http_version,
            final_url=final_url or url,
            redirect_chain=redirect_chain or [],
            headers={k.lower(): v for k, v in headers.items()},
            cookies={k.lower(): v for k, v in cookies.items()},
            body=body,
            body_size=len(raw),
            body_sha256=hashlib.sha256(raw).hexdigest(),
            elapsed_ms=elapsed_ms,
        )

    @classmethod
    def from_failure(
        cls,
        *,
        profile: str,
        url: str,
        outcome: ProbeOutcome,
        error_detail: str,
        elapsed_ms: float = 0.0,
    ) -> ProbeResult:
        return cls(
            profile=profile,
            url=url,
            outcome=outcome,
            error_detail=error_detail[:500],
            elapsed_ms=elapsed_ms,
        )

    @property
    def looks_allowed(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def looks_denied(self) -> bool:
        return self.status_code in {401, 403, 429, 503}

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class ProbeMatrix(BaseModel):
    """Los resultados de todos los perfiles contra un mismo objetivo."""

    target: str
    results: list[ProbeResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=_utcnow)

    def add(self, result: ProbeResult) -> None:
        self.results.append(result)

    def by_profile(self, profile: str) -> ProbeResult | None:
        return next((r for r in self.results if r.profile == profile), None)

    @property
    def profiles(self) -> list[str]:
        return [r.profile for r in self.results]

    @property
    def allowed_profiles(self) -> list[str]:
        return [r.profile for r in self.results if r.looks_allowed]

    @property
    def all_allowed(self) -> bool:
        return bool(self.results) and all(r.looks_allowed for r in self.results)

    @property
    def none_allowed(self) -> bool:
        return bool(self.results) and not any(r.looks_allowed for r in self.results)

    @property
    def body_hashes(self) -> dict[str, str]:
        return {
            r.profile: r.body_sha256
            for r in self.results
            if r.looks_allowed and r.body_sha256 is not None
        }

class VendorRole(str, Enum):
    '''
    Function the follow a vendor in a answer
    '''

    CDN = 'cdn'
    WAF = 'waf'
    BOT_DEFENSE = 'bot_defense'

class VendorMatch(BaseModel):
    '''
    Vendor detected in a ProbeResult, with confidence and the reason
    '''

    model_config = {"frozen": True}
 
    vendor_id: str
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    roles: frozenset[VendorRole]
    evidence: tuple[str, ...] = Field(min_length=1)
 
    @property
    def is_bot_defense(self) -> bool:
        return VendorRole.BOT_DEFENSE in self.roles

class Detection(BaseModel):
    '''
    All vendors detected in on ProbeResult, plus who blocked
    '''
    model_config = {"frozen": True}
 
    matches: tuple[VendorMatch, ...] = ()
    enforcer_id: str | None = None
 
    @property
    def vendor_ids(self) -> list[str]:
        return [m.vendor_id for m in self.matches]
 
    @property
    def bot_defenses(self) -> list[VendorMatch]:
        return [m for m in self.matches if m.is_bot_defense]
 
    @property
    def enforcer(self) -> VendorMatch | None:
        if self.enforcer_id is None:
            return None
        return next((m for m in self.matches if m.vendor_id == self.enforcer_id), None)

class DefenseType(str, Enum):
    NO_PROTECTION = 'no_protection'
    TLS_FINGERPRINT = 'tls_fingerprint'
    APP_FINGERPRINT = 'app_fingerprint'
    HARD_CHALLENGE = 'hard_challenge'
    SHADOW_BAN = 'shadow_ban'
    INDETERMINATE = 'indeterminate'

    @property
    def solved_by_impersonte(self) -> bool:
        return self in {DefenseType.TLS_FINGERPRINT, DefenseType.APP_FINGERPRINT}

class Diagnosis(BaseModel):
    model_config = {'frozen' : True}

    defense_type: DefenseType

    confidence: float = Field(ge=0.0, le=1.0)

    evidence: tuple[str, ...] = ()

    enforcer_id: str | None = None

    caveats: tuple[str, ...] = ()

    @property
    def _is_actionable(self) -> bool:
        return self.defense_type is not DefenseType.INDETERMINATE

    @property
    def needs_confirmation(self) -> bool:
        return bool(self.caveats)