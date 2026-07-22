"""
Perfil `naked_python`: httpx sin disfraz. El grupo de control.

Solo implementa los dos huecos del contrato: _execute y _classify.
El cronómetro, el rate limiter y la red de seguridad los pone Probe.run().
"""

from __future__ import annotations

import httpx

from scout.models import ProbeOutcome
from scout.probes.base import Probe, RawResponse


class NakedProbe(Probe):
    name = "naked_python"
    family = "naked"

    def _execute(self, url: str, headers: dict[str, str]) -> RawResponse:
        with httpx.Client(
            http2=True,
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            proxy=self.proxy,
            headers=headers,
        ) as client:
            resp = client.get(url)

        return RawResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            cookies=dict(resp.cookies),
            http_version=resp.http_version,
            final_url=str(resp.url),
            redirect_chain=[str(r.url) for r in resp.history],
        )

    def _classify(self, exc: Exception) -> tuple[ProbeOutcome, str]:
        detail = f"{type(exc).__name__}: {exc}"

        if isinstance(exc, httpx.ConnectTimeout | httpx.ReadTimeout | httpx.PoolTimeout):
            return ProbeOutcome.TIMEOUT, detail
        if isinstance(exc, httpx.TooManyRedirects):
            return ProbeOutcome.TOO_MANY_REDIRECTS, detail

        if isinstance(exc, httpx.ConnectError):
            texto = str(exc).lower()
            if any(k in texto for k in ("ssl", "tls", "handshake", "certificate")):
                return ProbeOutcome.TLS_ERROR, detail
            if "name or service not known" in texto or "nodename" in texto:
                return ProbeOutcome.DNS_ERROR, detail
            return ProbeOutcome.CONNECT_ERROR, detail

        if isinstance(exc, httpx.ReadError | httpx.RemoteProtocolError):
            return ProbeOutcome.CONNECTION_RESET, detail

        return ProbeOutcome.UNKNOWN_ERROR, detail
