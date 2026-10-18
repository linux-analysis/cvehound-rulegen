"""Evaluation metrics: unbiased pass@k, valid@b, bootstrap CIs, Â₁₂."""

import math
import random
from collections.abc import Sequence


def pass_at_k(n: int, c: int, k: int) -> float:
    """Codex's unbiased estimator: 1 - C(n-c, k)/C(n, k) for n samples, c correct."""
    if n < k:
        raise ValueError(f'need at least k={k} samples, got n={n}')
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


def valid_at_b(attempt_outcomes: Sequence[Sequence[bool]], b: int) -> float:
    """Fraction of tasks solved within the first b attempts (pipeline mode)."""
    if not attempt_outcomes:
        return 0.0
    return sum(any(task[:b]) for task in attempt_outcomes) / len(attempt_outcomes)


def bootstrap_ci(
    values: Sequence[float],
    iters: int = 10_000,
    alpha: float = 0.05,
    seed: int = 0,
) -> tuple[float, float, float]:
    """(mean, lo, hi): percentile bootstrap over per-task values.

    Resampling is at task level, which is the clustered form when each value
    already aggregates one CVE's samples.
    """
    if not values:
        return (0.0, 0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    mean = sum(values) / n
    means = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(iters))
    lo = means[int((alpha / 2) * iters)]
    hi = means[min(iters - 1, int((1 - alpha / 2) * iters))]
    return (mean, lo, hi)


def vargha_delaney_a12(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Â₁₂ effect size: P(X > Y) + 0.5·P(X = Y). 0.5 = no effect."""
    if not xs or not ys:
        return 0.5
    greater = sum(1 for x in xs for y in ys if x > y)
    equal = sum(1 for x in xs for y in ys if x == y)
    return (greater + 0.5 * equal) / (len(xs) * len(ys))
