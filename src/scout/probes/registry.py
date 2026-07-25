'''
name -> profile class
'''

from __future__ import annotations

from scout.probes.base import Probe
from scout.probes.impersonate import (
    Chrome131Probe,
    Firefox135Probe,
    Safari18Probe
)
from scout.probes.naked import NakedProbe

Registry: dict[str, type[Probe]] = {
    NakedProbe.name: NakedProbe,
    Chrome131Probe.name: Chrome131Probe,
    Safari18Probe.name: Safari18Probe,
    Firefox135Probe.name: Firefox135Probe,
}

# If the user does not define profiles, this will be executes
DEFAULT_PROFILES: tuple[str,...] = (NakedProbe.name, Chrome131Probe.name)

def available() -> list[str]:
    return sorted(Registry)

def get(name: str) -> type[Probe]:
    try:
        return Registry[name]
    except KeyError:
        raise KeyError(
            f'Unknown profile: {name!r}. Availables {', '.join(available())}'
        ) from None