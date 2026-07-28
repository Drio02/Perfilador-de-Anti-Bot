from __future__ import annotations

from dataclasses import dataclass

from scout.analysis.differ import BodyComparison, compare_bodies
from scout.fingerprints.matcher import detect
from scout.models import (
    DefenseType,
    Detection,
    Diagnosis,
    ProbeMatrix,
    ProbeResult,
)

#: Perfil de control. Su comportamiento frente a los disfraces es la base de
#: casi todo el diagnóstico.
_CONTROL = "naked_python"


@dataclass(frozen=True, slots=True)
class _Context:
    matrix: ProbeMatrix
    control: ProbeResult | None          # el resultado de naked_python, si corrió
    impersonators: list[ProbeResult]     # los perfiles disfrazados
    bodies: BodyComparison               # comparación de cuerpos (los que pasaron)
    enforcer_id: str | None              # quién bloqueó, de la detección Fase 2

    @property
    def all_results(self) -> list[ProbeResult]:
        return self.matrix.results

    @property
    def impersonators_passed(self) -> list[ProbeResult]:
        return [r for r in self.impersonators if r.looks_allowed]

    @property
    def impersonators_failed(self) -> list[ProbeResult]:
        return [r for r in self.impersonators if not r.looks_allowed]


def analyze(matrix: ProbeMatrix) -> Diagnosis:
    """Punto de entrada. Aplica las reglas en orden y devuelve el veredicto."""
    ctx = _build_context(matrix)

    for rule in _RULES:
        result = rule(ctx)
        if result is not None:
            return result

    return Diagnosis(
        defense_type=DefenseType.INDETERMINATE,
        confidence=0.3,
        evidence=(),
        enforcer_id=ctx.enforcer_id,
        caveats=("las señales no encajan en ningún patrón conocido",),
    )


def _build_context(matrix: ProbeMatrix) -> _Context:
    results = matrix.results
    control = next((r for r in results if r.profile == _CONTROL), None)
    impersonators = [r for r in results if r.profile != _CONTROL]

    enforcer_id = None
    for r in results:
        if r.looks_denied:
            det = detect(r)
            if det.enforcer_id:
                enforcer_id = det.enforcer_id
                break

    return _Context(
        matrix=matrix,
        control=control,
        impersonators=impersonators,
        bodies=compare_bodies(results),
        enforcer_id=enforcer_id,
    )


def _rule_insufficient_data(ctx: _Context) -> Diagnosis | None:
    """Sin al menos un control y un disfraz no hay comparación posible."""
    if ctx.control is not None and ctx.impersonators:
        return None  # hay con qué comparar; sigue el análisis normal

    # Un solo perfil (o solo disfraces, o solo control): describimos, no inferimos.
    only = ctx.all_results
    if len(only) <= 1:
        caveat = "solo se sondeó un perfil: no hay comparación posible"
    else:
        caveat = "faltan perfiles para comparar (se necesita control + impersonación)"

    return Diagnosis(
        defense_type=DefenseType.INDETERMINATE,
        confidence=0.2,
        evidence=tuple(f"{r.profile}: {r.outcome.value} {r.status_code or ''}".strip() for r in only),
        enforcer_id=ctx.enforcer_id,
        caveats=(caveat,),
    )


def _rule_tls_fingerprint(ctx: _Context) -> Diagnosis | None:
    if ctx.control is None or not ctx.impersonators_passed:
        return None
    if not ctx.control.outcome.blocked_below_http:
        return None

    passed = ctx.impersonators_passed
    evidence = (
        f"{_CONTROL} cayó en {ctx.control.outcome.value} (por debajo de HTTP)",
        *(f"{r.profile} obtuvo {r.status_code}" for r in passed),
    )
    return Diagnosis(
        defense_type=DefenseType.TLS_FINGERPRINT,
        confidence=0.9,
        evidence=evidence,
        enforcer_id=ctx.enforcer_id,
    )


def _rule_app_fingerprint(ctx: _Context) -> Diagnosis | None:
    if ctx.control is None or not ctx.impersonators_passed:
        return None
    if not ctx.control.looks_denied:
        return None

    passed = ctx.impersonators_passed
    evidence = (
        f"{_CONTROL} recibió {ctx.control.status_code} hablando HTTP",
        *(f"{r.profile} obtuvo {r.status_code}" for r in passed),
    )
    caveats = ()
    return Diagnosis(
        defense_type=DefenseType.APP_FINGERPRINT,
        confidence=0.85,
        evidence=evidence,
        enforcer_id=ctx.enforcer_id,
        caveats=caveats,
    )


def _rule_hard_challenge(ctx: _Context) -> Diagnosis | None:
    if not ctx.matrix.none_allowed:
        return None
    if not ctx.impersonators:
        return None  # sin disfraces no podemos afirmar que "la huella no basta"

    # Confianza mayor si un vendor de bot_defense se identificó como enforcer.
    confidence = 0.85 if ctx.enforcer_id else 0.65
    evidence = tuple(
        f"{r.profile}: {r.outcome.value} {r.status_code or ''}".strip()
        for r in ctx.all_results
    )
    caveats = ["una sola muestra puede ser rate-limiting temporal; confirma repitiendo"]
    if ctx.enforcer_id:
        caveats.insert(0, f"enforcer detectado: {ctx.enforcer_id} (suele requerir navegador real)")

    return Diagnosis(
        defense_type=DefenseType.HARD_CHALLENGE,
        confidence=confidence,
        evidence=evidence,
        enforcer_id=ctx.enforcer_id,
        caveats=tuple(caveats),
    )


def _rule_shadow_ban(ctx: _Context) -> Diagnosis | None:

    if not ctx.matrix.all_allowed:
        return None
    if ctx.bodies.all_equivalent:
        return None  # todos vieron lo mismo: no hay shadow-ban

    grupos = ctx.bodies.groups
    evidence = (
        "todos los perfiles obtuvieron 2xx",
        f"pero el contenido forma {len(grupos)} grupos distintos: "
        + " | ".join(", ".join(g) for g in grupos),
        f"similitud mínima entre perfiles: {ctx.bodies.min_similarity:.2f}",
    )
    return Diagnosis(
        defense_type=DefenseType.SHADOW_BAN,
        confidence=0.75,
        evidence=evidence,
        enforcer_id=ctx.enforcer_id,
        caveats=("verifica que la diferencia no sea contenido legítimo por región/idioma",),
    )


def _rule_no_protection(ctx: _Context) -> Diagnosis | None:
    """Todos pasan con contenido equivalente. No discrimina por presentación."""
    if not ctx.matrix.all_allowed:
        return None
    if not ctx.bodies.all_equivalent:
        return None

    evidence = (
        "todos los perfiles obtuvieron 2xx",
        "el contenido recibido es equivalente entre perfiles",
    )
    return Diagnosis(
        defense_type=DefenseType.NO_PROTECTION,
        confidence=0.8,
        evidence=evidence,
        enforcer_id=ctx.enforcer_id,
        caveats=("la defensa podría no haberse activado en esta petición",),
    )


_RULES = (
    _rule_insufficient_data,
    _rule_tls_fingerprint,
    _rule_app_fingerprint,
    _rule_hard_challenge,
    _rule_shadow_ban,
    _rule_no_protection,
)