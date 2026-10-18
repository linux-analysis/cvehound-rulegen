"""What the model was actually sent: prompt-size statistics from a run's sample log.

The estimator the harness budgets with and the count the server reports are
two different numbers; this is where they meet. Per round: quantiles of both,
their ratio, how many requests could not have fit the slot, how many the
server refused, and which sections the budget trimmed.
"""

from collections import Counter
from collections.abc import Sequence
from typing import Any

from rulegen.tables import Table, quantile

QUANTILES = (0.5, 0.95, 0.99, 1.0)


def _fmt(value: float | None, digits: int = 0) -> str:
    return '' if value is None else (f'{value:.{digits}f}' if digits else str(int(value)))


def prompt_tables(
    rows: Sequence[dict[str, Any]], context_tokens: int, max_tokens: int
) -> list[Table]:
    by_round: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        by_round.setdefault(int(row.get('round') or 0), []).append(row)

    sizes = Table(
        'prompt tokens by round',
        [
            'round',
            'rows',
            'server p50',
            'server p95',
            'server p99',
            'server max',
            'estimate p50',
            'estimate p95',
            'estimate max',
            'ratio p50',
            'ratio p95',
            'ratio max',
        ],
        note='server = tokens_prompt as counted by the model server; estimate = the harness '
        'counter; ratio = server / estimate over rows that have both',
    )
    fit = Table(
        'requests against the slot',
        ['round', 'rows', 'over context (server)', 'refused by server', 'not sent (harness)'],
        note=f'over context = tokens_prompt + max_tokens {max_tokens} > context_tokens '
        f'{context_tokens}; refused = the server answered exceed_context_size_error; '
        'not sent = the harness declined before sending',
    )
    for round_, items in sorted(by_round.items()):
        server = [float(r['tokens_prompt']) for r in items if r.get('tokens_prompt')]
        est = [float(r['prompt_tokens_est']) for r in items if r.get('prompt_tokens_est')]
        ratio = [
            float(r['tokens_prompt']) / float(r['prompt_tokens_est'])
            for r in items
            if r.get('tokens_prompt') and r.get('prompt_tokens_est')
        ]
        sizes.rows.append(
            [
                round_,
                len(items),
                *(_fmt(quantile(server, q)) for q in QUANTILES),
                _fmt(quantile(est, 0.5)),
                _fmt(quantile(est, 0.95)),
                _fmt(quantile(est, 1.0)),
                _fmt(quantile(ratio, 0.5), 2),
                _fmt(quantile(ratio, 0.95), 2),
                _fmt(quantile(ratio, 1.0), 2),
            ]
        )
        errors = [str(r.get('error') or '') for r in items]
        fit.rows.append(
            [
                round_,
                len(items),
                sum(1 for v in server if v + max_tokens > context_tokens),
                sum(1 for e in errors if 'exceed_context' in e),
                sum(1 for e in errors if e.startswith('context:')),
            ]
        )

    trimmed = Table('sections trimmed to the budget (round 0)', ['section', 'rows', '% of round 0'])
    first = by_round.get(0, [])
    counts = Counter(name for row in first for name in str(row.get('truncated') or '').split())
    for name, n in sorted(counts.items()):
        trimmed.rows.append([name, n, round(100 * n / len(first), 1) if first else 0])
    if not counts:
        trimmed.rows.append(['(none)', 0, 0.0])
    return [sizes, fit, trimmed]
