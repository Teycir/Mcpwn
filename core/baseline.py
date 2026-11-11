"""Behavioral baselines used to validate timing observations."""
from __future__ import annotations

import statistics
from typing import Callable, List, Optional, Tuple


class LatencyBaseline:
    """Robust latency baseline (median + median absolute deviation).

    A single slow response is never evidence.  Callers must compare against a
    baseline collected with the same request shape and require the anomaly to
    exceed both an absolute floor and a robust z-score.
    """

    def __init__(self, min_samples: int = 3):
        self.min_samples = min_samples
        self.samples: List[float] = []

    def add(self, value: float) -> None:
        if value >= 0:
            self.samples.append(float(value))

    def extend(self, values: List[float]) -> None:
        for value in values:
            self.add(value)

    def measure(self, probe: Callable[[], object], iterations: int) -> List[float]:
        values = []
        for _ in range(max(1, iterations)):
            value = probe()
            if isinstance(value, tuple):
                value = value[1]
            if isinstance(value, (int, float)):
                values.append(float(value))
        self.extend(values)
        return values

    @property
    def median(self) -> Optional[float]:
        if not self.samples:
            return None
        return statistics.median(self.samples)

    @property
    def mad(self) -> Optional[float]:
        if len(self.samples) < 2:
            return None
        med = statistics.median(self.samples)
        return statistics.median(abs(value - med) for value in self.samples)

    def anomaly(self, value: float, *, sigma: float = 4.0,
                min_delta: float = 0.5) -> Tuple[bool, float, float]:
        """Return ``(is_anomaly, ratio, robust_z)`` for a new observation."""
        if value < 0:
            return False, 0.0, 0.0
        if len(self.samples) < self.min_samples:
            return False, 0.0, 0.0
        med = self.median or 0.0
        mad = self.mad or 0.0
        if med <= 0:
            return False, 0.0, 0.0
        delta = value - med
        if delta < min_delta:
            return False, value / med, 0.0
        scale = 1.4826 * mad
        if scale <= 0:
            # Constant baseline: require a substantial absolute increase.
            threshold = max(min_delta, med * 3.0)
            return delta > threshold, value / med, float("inf")
        robust_z = delta / scale
        return (delta > max(min_delta, sigma * scale),
                value / med, robust_z)


def repeated(probe: Callable[[], object], attempts: int = 2) -> List[object]:
    """Run ``probe`` repeatedly, returning every result (including errors)."""
    results = []
    for _ in range(max(1, attempts)):
        results.append(probe())
    return results
