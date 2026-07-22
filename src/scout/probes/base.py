"""
Contrato común a todos los perfiles de sondeo.

run() es un método CERRADO: custodia el cronómetro, el rate limiter y la red
de seguridad de excepciones. Las subclases solo rellenan _execute y _classify.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scout.models import ProbeOutcome, ProbeResult
from scout.utils.http import RateLimiter, headers_for, normalize_url


@dataclass(slots=True)
class RawResponse:
    """Respuesta HTTP en forma neutra. El perfil traduce su librería a esto;
    run() la convierte en ProbeResult para centralizar la normalización."""

    status_code: int
    headers: dict[str, str]
    body: str
    cookies: dict[str, str] = field(default_factory=dict)
    http_version: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)


class Probe(ABC):
    """Un perfil de sondeo. Subclasificar: name, family, _execute, _classify."""

    name: str = "abstract"
    family: str = "naked"

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        rate_limiter: RateLimiter | None = None,
        follow_redirects: bool = True,
        proxy: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.rate_limiter = rate_limiter or RateLimiter()

    @abstractmethod
    def _execute(self, url: str, headers: dict[str, str]) -> RawResponse:
        """Lanza la petición. Recibe url y headers ya resueltos. Deja subir
        las excepciones de su librería; _classify las traduce."""

    def _classify(self, exc: Exception) -> tuple[ProbeOutcome, str]:
        """Traduce una excepción de la librería a ProbeOutcome. Por defecto no
        adivina: devuelve UNKNOWN_ERROR."""
        return ProbeOutcome.UNKNOWN_ERROR, f"{type(exc).__name__}: {exc}"

    def run(self, url: str) -> ProbeResult:
        """Ejecuta el sondeo. NO sobrescribir. El cronómetro arranca DESPUÉS
        de la espera del rate limiter, nunca antes."""
        target = normalize_url(url)
        headers = headers_for(self.family)

        self.rate_limiter.wait()

        started = time.perf_counter()
        try:
            raw = self._execute(target, headers)
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.perf_counter() - started) * 1000
            outcome, detail = self._classify(exc)
            return ProbeResult.from_failure(
                profile=self.name,
                url=target,
                outcome=outcome,
                error_detail=detail,
                elapsed_ms=elapsed,
            )

        elapsed = (time.perf_counter() - started) * 1000
        return ProbeResult.from_response(
            profile=self.name,
            url=target,
            status_code=raw.status_code,
            headers=raw.headers,
            cookies=raw.cookies,
            body=raw.body,
            elapsed_ms=elapsed,
            http_version=raw.http_version,
            final_url=raw.final_url,
            redirect_chain=raw.redirect_chain,
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} family={self.family!r}>"
