"""Pure scoring functions for periodic hunts (no database access, unit-testable).

Beacon scoring follows the approach of the open-source RITA project (Active Countermeasures): a
command-and-control implant "checks in" on a timer, so the gaps between its connections are nearly
constant and its payloads nearly the same size. Each property is scored 0..1 and averaged.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from itertools import pairwise


@dataclass
class BeaconScore:
    score: float
    interval_regularity: float
    interval_symmetry: float
    persistence: float
    size_regularity: float | None
    median_interval_s: float
    connections: int
    span_hours: float

    def as_dict(self) -> dict[str, float | int | None]:
        return {
            "score": round(self.score, 3),
            "interval_regularity": round(self.interval_regularity, 3),
            "interval_symmetry": round(self.interval_symmetry, 3),
            "persistence": round(self.persistence, 3),
            "size_regularity": None if self.size_regularity is None else round(self.size_regularity, 3),
            "median_interval_seconds": round(self.median_interval_s, 1),
            "connections": self.connections,
            "span_hours": round(self.span_hours, 2),
        }


def _quartiles(xs: list[float]) -> tuple[float, float, float]:
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], q[1], q[2]


def bowley_skew(xs: list[float]) -> float:
    """Quartile skewness in [-1, 1]; 0 for a symmetric distribution."""
    if len(xs) < 3:
        return 0.0
    q1, q2, q3 = _quartiles(xs)
    if q3 == q1:
        return 0.0
    return (q3 + q1 - 2 * q2) / (q3 - q1)


def madm(xs: list[float]) -> float:
    """Median absolute deviation about the median."""
    med = statistics.median(xs)
    return statistics.median(abs(x - med) for x in xs)


def _regularity(xs: list[float]) -> float:
    med = statistics.median(xs)
    if med <= 0:
        return 0.0
    return max(0.0, 1.0 - madm(xs) / med)


def beacon_score(timestamps: list[float], sizes: list[int] | None = None) -> BeaconScore | None:
    """Score a series of connection start times (epoch seconds, any order) to one destination."""
    ts = sorted(timestamps)
    if len(ts) < 4:
        return None
    deltas = [b - a for a, b in pairwise(ts) if b - a > 0.5]  # merge same-second duplicates
    if len(deltas) < 3:
        return None
    span_h = (ts[-1] - ts[0]) / 3600
    med = statistics.median(deltas)
    regularity = _regularity(deltas)
    symmetry = 1.0 - abs(bowley_skew(deltas))
    # how much of the observed span had at least one connection, in buckets of a few intervals
    bucket = max(med * 3, 60.0)
    filled = len({int((t - ts[0]) // bucket) for t in ts})
    expected = max(1, int((ts[-1] - ts[0]) // bucket) + 1)
    persistence = min(1.0, filled / expected)
    size_reg: float | None = None
    if sizes:
        positive = [float(x) for x in sizes if x and x > 0]
        if len(positive) >= len(ts) // 2 and len(positive) >= 4:
            size_reg = (_regularity(positive) + (1.0 - abs(bowley_skew(positive)))) / 2
    timing = (regularity + symmetry + persistence) / 3
    score = timing if size_reg is None else 0.7 * timing + 0.3 * size_reg
    return BeaconScore(score, regularity, symmetry, persistence, size_reg, med, len(ts), span_h)


def base_domain(domain: str) -> str:
    """Registrable domain (approximation without the public suffix list)."""
    from sentinelx.detection.builtin import _TWO_LEVEL_SUFFIXES

    labels = [x for x in domain.lower().strip(".").split(".") if x]
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
