"""pass@k, valid@b, bootstrap intervals and the A12 effect size."""

import pytest

from rulegen.eval import metrics


@pytest.mark.parametrize(
    ('n', 'c', 'k', 'expected'),
    [
        (10, 10, 1, 1.0),
        (10, 10, 5, 1.0),
        (10, 0, 1, 0.0),
        (10, 0, 5, 0.0),
        (5, 1, 1, 0.2),
        (5, 1, 5, 1.0),  # k = n always draws the one correct sample
    ],
)
def test_pass_at_k(n, c, k, expected):
    assert metrics.pass_at_k(n, c, k) == pytest.approx(expected)


def test_pass_at_k_requires_enough_samples():
    with pytest.raises(ValueError):
        metrics.pass_at_k(3, 1, 5)


def test_valid_at_b():
    outcomes = [[False, True, False], [False, False, False], [True, False, False]]
    assert metrics.valid_at_b(outcomes, 1) == pytest.approx(1 / 3)
    assert metrics.valid_at_b(outcomes, 2) == pytest.approx(2 / 3)


def test_bootstrap_ci_brackets_the_mean():
    mean, lo, hi = metrics.bootstrap_ci(
        [1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0], iters=2000, seed=1
    )
    assert 0.0 <= lo <= mean <= hi <= 1.0


@pytest.mark.parametrize(
    ('xs', 'ys', 'a12'),
    [([1, 2, 3], [1, 2, 3], 0.5), ([5, 6], [1, 2], 1.0), ([1, 2], [5, 6], 0.0)],
)
def test_a12(xs, ys, a12):
    assert metrics.vargha_delaney_a12(xs, ys) == pytest.approx(a12)
