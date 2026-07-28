from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from scout.models import ProbeResult

_COMPARE_LIMIT = 20_000


@dataclass(frozen=True, slots=True)
class BodyComparison:

    similarity: dict[tuple[str, str], float]
    groups: tuple[tuple[str, ...], ...]

    @property
    def all_equivalent(self) -> bool:
        return len(self.groups) <= 1

    @property
    def min_similarity(self) -> float:
        return min(self.similarity.values(), default=1.0)


def _size_ratio(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 1.0
    lo, hi = sorted((a, b))
    return lo / hi if hi else 0.0


def _text_similarity(a: str, b: str) -> float:
    """Similitud [0,1] entre dos textos, truncados para acotar el coste."""
    return SequenceMatcher(None, a[:_COMPARE_LIMIT], b[:_COMPARE_LIMIT]).ratio()


def _pair_similarity(r1: ProbeResult, r2: ProbeResult) -> float:
    if r1.body is None or r2.body is None:
        if r1.body_sha256 and r1.body_sha256 == r2.body_sha256:
            return 1.0
        return _size_ratio(r1.body_size, r2.body_size)

    if r1.body_sha256 and r1.body_sha256 == r2.body_sha256:
        return 1.0

    size = _size_ratio(r1.body_size, r2.body_size)
    text = _text_similarity(r1.body, r2.body)

    return round((size + text) / 2, 3)


def compare_bodies(
    results: list[ProbeResult],
    *,
    equivalence_threshold: float = 0.9,
) -> BodyComparison:
    passed = [r for r in results if r.looks_allowed]

    similarity: dict[tuple[str, str], float] = {}
    for i, r1 in enumerate(passed):
        for r2 in passed[i + 1 :]:
            similarity[(r1.profile, r2.profile)] = _pair_similarity(r1, r2)

    groups = _cluster(passed, similarity, equivalence_threshold)
    return BodyComparison(similarity=similarity, groups=groups)


def _cluster(
    results: list[ProbeResult],
    similarity: dict[tuple[str, str], float],
    threshold: float,
) -> tuple[tuple[str, ...], ...]:
    def sim(a: str, b: str) -> float:
        return similarity.get((a, b)) or similarity.get((b, a)) or (1.0 if a == b else 0.0)

    names = [r.profile for r in results]
    groups: list[list[str]] = []
    for name in names:
        for g in groups:
            if all(sim(name, member) >= threshold for member in g):
                g.append(name)
                break
        else:
            groups.append([name])

    return tuple(tuple(g) for g in groups)