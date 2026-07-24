'''
name -> profile class
'''

from __future__ import annotations

from scout.probes.base import Probe
from scout.probes.naked import NakedProbe

Registry: dict[str, type[Probe]] = {
    NakedProbe.name: NakedProbe,
}

# If the user does not define profiles, this will be executes
DEFAULT_PROFILES: tuple[str,...] = (NakedProbe.name,)

def available() -> list[str]:
    return sorted(Registry)

def get(name: str) -> type[Probe]:
    try:
        return Registry[name]
    except KeyError:
        raise KeyError(
            f'Unknown profile: {name!r}. Availables {', '.join(available())}'
        ) from None