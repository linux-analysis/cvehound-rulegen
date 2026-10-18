"""Prompt-size statistics from a synthetic sample log."""

from rulegen.eval.promptstats import prompt_tables
from rulegen.tables import render_markdown


def row(round_, server, est, error=None, truncated=''):
    return {
        'round': round_,
        'tokens_prompt': server,
        'prompt_tokens_est': est,
        'error': error,
        'truncated': truncated,
    }


def test_tables_count_overflows_refusals_and_trimming():
    rows = [
        row(0, 3000, 2600, truncated='diff'),
        row(0, 15000, 7700, truncated='message-trace diff'),
        row(0, None, 5000, error='context: 17000 tokens'),
        row(1, 16000, 9000, error='exceed_context_size_error'),
        row(1, 4000, 3500),
    ]
    sizes, fit, trimmed = prompt_tables(rows, context_tokens=16384, max_tokens=2048)
    assert sizes.rows[0][:2] == [0, 3] and sizes.rows[0][2] == '3000'  # server p50 of round 0
    assert sizes.rows[0][-1] == '1.95'  # ratio max 15000/7700
    assert fit.rows[0] == [0, 3, 1, 0, 1]  # 15000+2048 > 16384; one not sent
    assert fit.rows[1] == [1, 2, 1, 1, 0]
    assert trimmed.rows == [['diff', 2, 66.7], ['message-trace', 1, 33.3]]
    md = render_markdown([sizes, fit, trimmed])
    assert '| round | rows |' in md and 'not sent (harness)' in md
