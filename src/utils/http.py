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