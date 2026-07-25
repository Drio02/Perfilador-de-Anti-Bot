'''
Impersonate profiles through curl_cffi

TO do
'''

from __future__ import annotations

from curl_cffi import requests
from curl_cffi.requests.exceptions import (
    ConnectionError as CurlConnectionError
)
from curl_cffi.requests.exceptions import (
    RequestException,
    SSLError,
    Timeout,
    TooManyRedirects
)

from scout.models import ProbeOutcome
from scout.probes.base import Probe, RawResponse

def _normalize_http_version(raw: object) -> str | None:
    if raw is None:
        return None
    mapping = {10: "HTTP/1.0", 11: "HTTP/1.1", 2: "HTTP/2", 3: "HTTP/3", 20: "HTTP/2", 30: "HTTP/3"}
    return mapping.get(int(raw), f"HTTP/{raw}")

class ImpersonateProbe(Probe):
    '''
    Base of the impersonates profiles.
    Child classes just define name, family and impersonate
    '''

    impersonte: str = ''

    def _execute(self, url: str, headers: dict[str, str]) -> RawResponse:
        resp = requests.get(
            url,
            impersonate=self.impersonte,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=self.follow_redirects,
            proxies={"https": self.proxy, "http": self.proxy} if self.proxy else None,
        )

        return RawResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            cookies=dict(resp.cookies),
            http_version=_normalize_http_version(getattr(resp, "http_version", None)),
            final_url=str(resp.url),
            redirect_chain=[str(h.url) for h in resp.history],
        )


    def _classify(self, exc: Exception) -> tuple[ProbeOutcome, str]:
        detail = f'{type(exc).__name__}:{exc}'

        # SSL error first. If a impersonate profile still failing due to TLS. FIlter is not by firgerprint

        if isinstance(exc, SSLError):
            return ProbeOutcome.TLS_ERROR, detail
        if isinstance(exc, Timeout):
            return ProbeOutcome.TIMEOUT, detail
        if isinstance(exc, TooManyRedirects):
            return ProbeOutcome.TOO_MANY_REDIRECTS, detail
        if isinstance(exc, CurlConnectionError):
            texto = str(exc).lower()
            if "reset" in texto or "closed" in texto:
                return ProbeOutcome.CONNECTION_RESET, detail
            if "resolve" in texto or "name" in texto:
                return ProbeOutcome.DNS_ERROR, detail
            return ProbeOutcome.CONNECT_ERROR, detail
        if isinstance(exc, RequestException):
            return ProbeOutcome.UNKNOWN_ERROR, detail
 
        return ProbeOutcome.UNKNOWN_ERROR, detail

## Specific profiles

class Chrome131Probe(ImpersonateProbe):
    name = "chrome131"
    family = "chrome"
    impersonate = "chrome131"
 
 
class Safari18Probe(ImpersonateProbe):
    name = "safari18"
    family = "safari"
    impersonate = "safari18_0"
 
 
class Firefox135Probe(ImpersonateProbe):
    name = "firefox135"
    family = "firefox"
    impersonate = "firefox135"
