from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scout.models import ProbeOutcome, ProbeResult
from scout.utils.http import RateLimiter, headersFor, normalizeUrl

###
# Respuesta cruda
###

@dataclass(slots=True)
class RawResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    cookies: dict[str, str] = field(default_factory=dict)
    http_version: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)

###
# Contrato del perfil
###

class Probe(ABC):
    """
    Perfil de sondeo: una "personalidad" de cliente HTTP
    """

    name: str = "abstract"

    family: str = "naked"

    def __init__(self, timeout: float = 20.0, rate_limiter: RateLimiter | None = None, follow_redirects: bool = True, proxy: str | None = None) -> None:
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.proxy = proxy

        self.rate_limiter = rate_limiter

    @abstractmethod
    def _execute(self, url: str, headers: dict[str, str]) -> RawResponse:
        pass

    def _classify(self, exc: Exception) -> tuple[ProbeOutcome, str]:
        """
        Traduce una excepción de la librería concreta a nuestro vocabulario.
        """
        return ProbeOutcome.UNKNOWN_ERROR, f"{type(exc).__name__}: {exc}"
    
    def run(self, url: str) -> ProbeResult:
        """
        Ejecuta el sondeo.
 
        Secuencia, y el orden importa:
 
          1. Normalizar la URL. Antes de nada, para que todos los perfiles
            pidan literalmente la misma cadena.
          2. Resolver las cabeceras de la familia.
          3. Esperar turno en el rate limiter.
          4. ARRANCAR EL CRONÓMETRO -- después de la espera, nunca antes.
          5. Ejecutar la petición.
          6. Parar el cronómetro y envolver el resultado.
        """
        target = normalize_url(url)
        headers = headers_for(self.family)
 
        self.rate_limiter.wait()  # fuera de la medición, a propósito
 
        started = time.perf_counter()
        try:
            raw = self._execute(target, headers)
        except Exception as exc:  # noqa: BLE001 -- ver justificación abajo
            # Capturamos Exception a lo ancho porque, en esta herramienta,
            # que la petición falle NO es un error del programa: es el dato.
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