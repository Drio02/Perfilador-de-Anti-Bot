"""
Central configuration.
Just this module read .env
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, '').strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f'{key} must be a number, not {raw!r}') from None

@dataclass(frozen=True, slots=True)
class ScanConfig:
    '''
    Inmutable
    All profiles share the same conditions 
    '''

    timeout: float = 20.0
    probe_delay: float = 1.5
    proxy: str | None = None
    follow_redirects: bool = True

    @classmethod
    def from_env(cls) -> ScanConfig:
        return cls(
            timeout=_env_float('SCOUT_TIMEOUT', 20.0),
            probe_delay = _env_float('SCOUT_PROBE_DELAY', 1.5),
            proxy = os.environ.get('SCOUT_PROXY') or None
        )

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError('timeout must be positive')
        if self.probe_delay < 0:
            raise ValueError('probe delay must be positive')