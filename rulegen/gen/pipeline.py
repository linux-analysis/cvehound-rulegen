"""The fixed validate–repair pipeline and its self-critique control.

Per CVE, `attempts` independent chains start from the same prompt. A chain that
has not been accepted (`pipeline.accept`: valid, or strong to repair T4-T6 failures too)
gets one more turn per round: the assistant's previous reply, then either the
oracle's structured feedback or the critique checklist.
Both arms see identical budgets (same rounds, same max_tokens); the sample log
carries `tokens_cum` per chain so valid@tokens compares them fairly.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

from rulegen.gen.adapters.base import GenRequest
from rulegen.gen.feedback import feedback_turn
from rulegen.gen.harness import Harness
from rulegen.gen.log import SampleRow, score_counts
from rulegen.gen.prompts import BuiltPrompt, messages_sha
from rulegen.schema import CveRecord, ExampleRecord, Score
from rulegen.tokens import TokenCounter, fit_pieces

log = logging.getLogger(__name__)


# What of a failed reply the next turn carries when the reply parsed as no rule.
RAW_REPLY_CAP = 800


def assistant_turn(row: SampleRow, count: TokenCounter) -> str:
    """The previous attempt as the model sees it on the repair turn.

    A parsed reply is shown as the model's own rule in contract form (after
    the transform, before the harness completed Files: and inserted the
    headers), so the turn is bounded by the rule and the model is never shown
    the Fix:/Fixes: lines it must not emit. An unparsable reply is shown raw,
    capped to its tail.
    """
    body = row.rule_body if row.parsed else None
    if body:
        return f'```\n{body}```\n'
    text = row.completion_text
    if count(text) <= RAW_REPLY_CAP:
        return text
    kept, _dropped = fit_pieces(text.splitlines(keepends=True), RAW_REPLY_CAP, count, from_end=True)
    return '[reply truncated]\n' + ''.join(kept)


def next_turn(
    row: SampleRow,
    example: ExampleRecord,
    kind: str,
    task: list[dict[str, str]],
    count: TokenCounter,
) -> list[dict[str, str]]:
    """The repair turn: the task as first built, the last reply, its feedback.

    Only the last (reply, feedback) pair is kept: the task prompt is the bulk
    of every turn and is resent regardless, and earlier failed replies add
    context without adding information the feedback did not already carry.
    Bounded context is what keeps round three inside the slot.
    """
    score = Score.from_row(row.score)
    # A rewritten rule is not the text the model wrote: the assistant turn
    # carries what was judged, and the feedback says so.
    return [
        *task,
        {'role': 'assistant', 'content': assistant_turn(row, count)},
        {'role': 'user', 'content': feedback_turn(kind, score, example, row.transform_applied)},
    ]


def accept_key(cfg: Any) -> str:
    """The score column that ends a repair chain."""
    return 'strong_valid' if cfg.pipeline.accept == 'strong' else 'valid'


@dataclass
class Chain:
    """One attempt chain: its example and first prompt, and its latest turn."""

    example: ExampleRecord
    built: BuiltPrompt
    messages: list[dict[str, str]]  # what the latest turn sent
    row: SampleRow  # what it got back


def run_pipeline(harness: Harness, resume: bool = False, dry_run: bool = False) -> dict[str, Any]:
    cfg = harness.cfg
    started = time.monotonic()
    examples, records, classes = harness.prepare()
    log.info(
        'pipeline %s: %d CVEs x b=%d attempts x %d repair rounds (%s feedback, accept=%s) -> %s',
        cfg.run_id,
        len(examples),
        cfg.pipeline.attempts,
        cfg.pipeline.rounds,
        cfg.pipeline.feedback,
        cfg.pipeline.accept,
        harness.run_dir,
    )
    if dry_run:
        return harness.dry_run(examples)
    done_cves = {cve for cve, _i, _r in harness.log.done_keys()} if resume else set()
    examples = [ex for ex in examples if ex.cve not in done_cves]
    key = accept_key(cfg)
    totals = {
        'n_rows': 0,
        'n_cves': len(examples),
        'accept': cfg.pipeline.accept,
        'n_valid_chains': 0,
        'n_accepted_chains': 0,
        'n_cves_valid': 0,
        'n_cves_accepted': 0,
        'n_truncated_legs': 0,
    }
    with harness.finishing(totals, started):
        for start in range(0, len(examples), cfg.chunk_cves):
            chunk = examples[start : start + cfg.chunk_cves]
            rows = _run_chunk(harness, chunk, records, classes)
            harness.log.append(rows)
            totals['n_rows'] += len(rows)
            totals['n_truncated_legs'] += score_counts(rows)['n_truncated_legs']
            for column, chains, cves in (
                ('valid', 'n_valid_chains', 'n_cves_valid'),
                (key, 'n_accepted_chains', 'n_cves_accepted'),
            ):
                hits = {(r.cve, r.sample_index) for r in rows if r.score.get(column)}
                totals[chains] += len(hits)
                totals[cves] += len({cve for cve, _i in hits})
            log.info(
                '  %d/%d CVEs, %d rows, %d CVEs with an accepted rule (%.0fs)',
                min(start + cfg.chunk_cves, len(examples)),
                len(examples),
                totals['n_rows'],
                totals['n_cves_accepted'],
                time.monotonic() - started,
            )
    return totals


def _run_chunk(
    harness: Harness,
    chunk: list[ExampleRecord],
    records: dict[str, CveRecord],
    classes: dict[str, str],
) -> list[SampleRow]:
    """Every chain of the chunk's CVEs, round by round until accepted or out of rounds."""
    key = accept_key(harness.cfg)
    chains: list[Chain] = []
    tasks: list[tuple[SampleRow, GenRequest]] = []
    for example in chunk:
        built = harness.build(example)
        for index in range(harness.cfg.pipeline.attempts):
            row, req = harness.first_task(example, classes.get(example.cve, ''), built, index)
            tasks.append((row, req))
            chains.append(Chain(example, built, built.messages, row))
    rows = _generate_and_score(harness, tasks, records)
    for round_ in range(1, harness.cfg.pipeline.rounds + 1):
        live = [chain for chain in chains if not chain.row.score.get(key)]
        if not live:
            break
        tasks = [_repair_task(harness, chain, round_) for chain in live]
        rows += _generate_and_score(harness, tasks, records)
    return rows


def _repair_task(harness: Harness, chain: Chain, round_: int) -> tuple[SampleRow, GenRequest]:
    """The chain's next turn; the chain moves on to it."""
    prev = chain.row
    # A transport failure produced no reply to critique: retry the same turn.
    if not prev.error:
        chain.messages = next_turn(
            prev, chain.example, harness.cfg.pipeline.feedback, chain.built.messages, harness.count
        )
    row = harness.new_row(chain.example, prev.cls, chain.built, prev.sample_index, round_=round_)
    row.parent_attempt_id = prev.attempt_id
    row.messages_sha = messages_sha(chain.messages)
    row.tokens_cum = prev.tokens_cum
    row.prompt_tokens_est = harness.count('\n'.join(m['content'] for m in chain.messages))
    chain.row = row
    return row, GenRequest(
        chain.messages, harness.params, row.seed, example=chain.example, round=round_
    )


def _generate_and_score(
    harness: Harness, tasks: list[tuple[SampleRow, GenRequest]], records: dict[str, CveRecord]
) -> list[SampleRow]:
    comps = harness.generate(tasks)
    rows = [row for row, _req in tasks]
    harness.score_rows(rows, comps, records)
    return rows
