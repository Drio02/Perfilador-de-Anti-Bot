"""
Piezas de red compartidas por todos los perfiles.

Garantizan control experimental: la URL exacta, el ritmo y la coherencia de
las cabeceras se clavan aquí para que lo único que varíe entre perfiles sea
la huella.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_url(raw: str) -> str:
    """Deja una URL en forma canónica. No toca la query (hay sitios que la
    firman) ni las mayúsculas del path (es sensible a ellas)."""
    raw = raw.strip()
    if not raw:
        raise ValueError("URL vacía")

    if "://" not in raw:
        raw = "https://" + raw

    parts = urlsplit(raw)

    if parts.scheme not in ("http", "https"):
        raise ValueError(f"Scheme not supported: {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError(f"URL sin host: {raw!r}")

    host = parts.hostname.lower()

    port = parts.port
    if port is not None and str(port) != _DEFAULT_PORTS[parts.scheme]:
        host = f"{host}:{port}"

    path = parts.path or "/"

    return urlunsplit((parts.scheme, host, path, parts.query, ""))


def registrable_target(url: str) -> str:
    """Clave 'esquema://host' de una URL. Para agrupar y cachear."""
    parts = urlsplit(normalize_url(url))
    return f"{parts.scheme}://{parts.netloc}"


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
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"
    ),
    "accept-language": "en-US,en;q=0.9",
}

HEADER_FAMILIES: dict[str, HeaderSet] = {
    "naked": HEADERS_NAKED,
    "chrome": HEADERS_CHROME,
    "firefox": HEADERS_FIREFOX,
    "safari": HEADERS_SAFARI,
}


def headers_for(family: str, extra: HeaderSet | None = None) -> HeaderSet:
    """Devuelve una COPIA del juego de cabeceras de una familia. Copia para que
    un perfil no pueda mutar el dict del módulo y contaminar a los demás."""
    if family not in HEADER_FAMILIES:
        raise KeyError(f"Familia de cabeceras desconocida: {family!r}")
    headers = dict(HEADER_FAMILIES[family])
    if extra:
        headers.update({k.lower(): v for k, v in extra.items()})
    return headers


class RateLimiter:
    """Impone una pausa mínima entre peticiones. Compartido por todos los
    perfiles para que la pausa sea global. Usa monotonic (no salta con NTP)."""

    def __init__(self, min_interval: float = 1.5) -> None:
        if min_interval < 0:
            raise ValueError("min_interval no puede ser negativo")
        self.min_interval = min_interval
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Bloquea hasta que sea seguro lanzar la siguiente petición. Devuelve
        los segundos dormidos (NO forman parte del elapsed_ms del sondeo)."""
        with self._lock:
            now = time.monotonic()
            slept = 0.0
            if self._last is not None:
                remaining = self.min_interval - (now - self._last)
                if remaining > 0:
                    time.sleep(remaining)
                    slept = remaining
            self._last = time.monotonic()
            return slept

    def reset(self) -> None:
        with self._lock:
            self._last = None
