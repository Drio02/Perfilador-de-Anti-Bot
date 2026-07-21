from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {'http' : '80', 'https' : '443'}

def normalizeUrl(url: str) -> str:
    """
    Funtion that nomralize the URL to mantain the same process for each test
    """
    url_raw = url.strip()
    if not url_raw:
        raise ValueError('Emtpy URL')
    
    if '://' not in url_raw:
        ulr_raw = 'https://' + url_raw

    parts = urlsplit(url_raw)

    if parts.scheme not in ('http', 'https'):
        raise ValueError(f'Not supported scheme: {parts.scheme!r}')
    if not parts.hostname:
        raise ValueError(f'URL whitout host: {url_raw!r}')
    
    host = parts.hostname.lower()

    port = parts.port
    if port is not None and str(port) != _DEFAULT_PORTS[parts.scheme]:
        host = f'{host}:{port}'

    path = parts.path or '/'

    return urlunsplit((parts.scheme, host, path, parts.query, ''))

def registableTarget (url: str) -> str:
    parts = urlsplit(normalizeUrl(url))
    return f'{parts.scheme}://{parts.netloc}'

"""
######## Headers coherents
"""

HeaderSet = dict[str, str]

HEADERS_NAKED: HeaderSet = {}

HEADERS_CHROME: HeaderSet = {
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),

    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-language": "en-US,en;q=0.9",
    "priority": "u=0, i",
}

HEADERS_FIREFOX: HeaderSet = {
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
    ),
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.5",
    "upgrade-insecure-requests": "1",

    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "priority": "u=0, i",
}

HEADERS_SAFARI: HeaderSet = {
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ),
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"
    ),
    "accept-language": "en-US,en;q=0.9",
}

# Families headers
HEADER_FAMILIES: dict[str, HeaderSet] = {
    'naked': HEADERS_NAKED,
    'chrome': HEADERS_CHROME,
    'firefox': HEADERS_FIREFOX,
    'safari': HEADERS_SAFARI,
}

def headersFor(family: str, extra: HeaderSet | None = None) -> HeaderSet:
    if family not in HEADER_FAMILIES:
        raise KeyError(f'Family unknown: {family!r}')
    headers = dict(HEADER_FAMILIES[family])
    if extra:
        headers.update({k.lower(): v for k,v in extra.items()})
    return headers

#
#    RateLimiter
#

class RateLimiter:

    def __init__(self, minInterval: float = 1.5) -> None:
        if minInterval < 0:
            raise ValueError('minInterval cannot be negative')
        self.minInterval = minInterval
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self) -> float:
        with self._lock:
            now = time.monotonic()
            slept = 0.0
            if self._last is not None:
                remaining = self.minInterval - (now - self._last)
                if remaining > 0:
                    time.sleep(remaining)
                    slept = remaining
            self._last = time.monotonic()
            return slept
    
    def reset(self) -> None:
        with self._lock:
            self._last = None