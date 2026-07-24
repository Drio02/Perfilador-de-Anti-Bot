'''
Orchestrator this is the only module that has permissions to build new profiles

Ensure that all profiles share the same control variables and rate limit.
Secutential execution, NEVEL parallel
'''

from __future__ import annotations

from collections.abc import Callable, Sequence

from scout.config import ScanConfig
from scout.models import ProbeMatrix, ProbeOutcome, ProbeResult
from scout.probes import registry
from scout.probes.base import Probe
from scout.utils.http import RateLimiter, normalize_url

def build_probes(profiles: Sequence[str], config: ScanConfig, limiter: RateLimiter) -> list[Probe]:
    '''
    Build the profiles with the same configuration
    '''

    if not profiles:
        raise ValueError('must be define at leat one profile')

    return [
        registry.get(name)(
            timeout=config.timeout,
            rate_limiter=limiter,
            follow_redirects=config.follow_redirects,
            proxy=config.proxy
        ) for name in profiles
    ]

def scan(url: str, profiles: Sequence[str] | None = None, config: ScanConfig | None = None, on_result: Callable[[ProbeResult], None] | None = None):
    '''
    Normalize and run the same url with different profiles
    '''

    config = config or ScanConfig.from_env()
    profiles = tuple(profiles or registry.DEFAULT_PROFILES)

    target = normalize_url(url)
    limiter = RateLimiter(min_interval=config.probe_delay)
    probes = build_probes(profiles, config, limiter)

    matrix = ProbeMatrix(target=target)

    for probe in probes:
        result = _run_safely(probe, target)
        matrix.add(result)
        if on_result is not None:
            on_result(result)
    return matrix

def _run_safely(probe: Probe, target: str) -> ProbeResult:
    '''
    Last security resource
    '''

    try:
        return probe.run(target)
    except Exception as exc:
        return ProbeResult.from_failure(
            profile=probe.name,
            url=target,
            outcome=ProbeOutcome.UNKNOWN_ERROR,
            error_detail=f'profile internat issue: {type(exc).__name__}: {exc}',
        )