"""The per-attempt sample log: append-only JSONL during the run, parquet at the end.

One row per generated attempt. Score fields are flattened with an `s_` prefix
so a row is self-contained: prompt identity, sampling parameters, the
completion, the finalized rule and its verdicts.
"""

import dataclasses
import json
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from rulegen import tables
from rulegen.promptbuild import Finalized
from rulegen.schema import Score

log = logging.getLogger(__name__)


@dataclass
class SampleRow:
    run_id: str
    config_sha: str
    cve: str
    split: str
    cls: str  # context tier class of the gold rule ('' when unknown)
    mode: str
    policy: str
    prompt_sha: str
    messages_sha: str
    system_prompt_id: str
    system_sha: str
    adapter: str
    model_id: str
    temperature: float
    top_p: float
    max_tokens: int
    thinking: bool | None
    seed: int
    sample_index: int
    round: int = 0
    parent_attempt_id: str = ''
    attempt_id: str = ''
    completion_text: str = ''
    reasoning_text: str | None = None
    finish_reason: str = ''
    tokens_prompt: int | None = None
    tokens_completion: int | None = None
    tokens_reasoning: int | None = None
    tokens_cum: int = 0  # prompt + completion along the attempt chain (pipelines)
    prompt_tokens_est: int = 0
    truncated: str = ''  # prompt sections trimmed to the budget, space-separated
    latency_s: float = 0.0
    error: str | None = None
    parsed: bool = False
    rule_text: str | None = None  # what was scored (after cfg.transform, if any)
    # The model's own rule in contract form (after cfg.transform, before the
    # harness completed Files: and inserted the commit headers): the SFT target.
    rule_body: str | None = None
    rule_sha: str = ''
    transform_applied: bool = False  # the transform rewrote the model's rule
    dedup_of: str = ''  # attempt_id whose Score this row reuses
    server_timings: str | None = None  # llama-server / vLLM timing block as JSON, for tok/s
    # Vendor-CLI adapters: the session/thread id, cache reads, the provider's
    # own cost figure, and whether the sampling parameters above were honored
    # (a CLI samples at the provider default; the row says so rather than
    # pretending the config's temperature applied).
    request_id: str | None = None
    tokens_cached: int | None = None
    cost_usd: float | None = None
    sampling_honored: bool = True
    tool_calls: int = 0  # tools that ran; 0 in a direct-response cell (such replies are retried)
    tool_attempts_denied: int = 0  # tool calls the CLI refused before this reply (kept)
    # Agent sessions: the agent's final message, the rule file it left
    # behind, and what it did along the way.
    agent_message: str | None = None
    agent_rule_text: str | None = None
    num_turns: int | None = None
    duration_ms: int | None = None
    pytest_ran: bool = False
    pytest_passed: bool | None = None
    validator_ran: bool = False
    kernel_clean: bool | None = None
    timed_out: bool = False
    score: dict[str, Any] = field(default_factory=dict)  # Score.to_row(); flattened on write

    def as_record(self) -> dict[str, Any]:
        row = dataclasses.asdict(self)
        score = row.pop('score')
        for key, value in score.items():
            row[f's_{key}'] = value
        return row

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> 'SampleRow':
        """Inverse of as_record() minus the score: `s_*` columns and unknown keys are dropped."""
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(
            **{
                k: v
                for k, v in rec.items()
                if k in fields and k != 'score' and not k.startswith('s_')
            }
        )

    def attach(self, score: Score) -> None:
        self.score = score.to_row()

    def record_rule(self, done: Finalized) -> None:
        """What the completion became: the rule the oracle scores, and the model's own body."""
        self.parsed = done.rule is not None
        self.rule_text = done.rule
        self.rule_body = done.body
        self.rule_sha = done.sha

    @classmethod
    def from_record_with_score(cls, rec: dict[str, Any]) -> 'SampleRow':
        """from_record() plus the `s_*` columns folded back into `score`."""
        row = cls.from_record(rec)
        row.score = {k[len('s_') :]: v for k, v in rec.items() if k.startswith('s_')}
        return row


def score_counts(rows: Iterable[SampleRow]) -> dict[str, int]:
    """The verdict totals every run reports: valid and strong-valid rows, and the
    legs whose scan spatch did not finish (the environment's, never a silence)."""
    rows = list(rows)
    return {
        'n_valid': sum(1 for r in rows if r.score.get('valid')),
        'n_strong_valid': sum(1 for r in rows if r.score.get('strong_valid')),
        'n_truncated_legs': sum(r.score.get('truncated_legs') or 0 for r in rows),
    }


def attempt_id(cve: str, sample_index: int, round_: int) -> str:
    return f'{cve}:{sample_index}:{round_}'


def attempt_seed(seed: int, sample_index: int, round_: int) -> int:
    """The request seed: chains differ in the thousands, repair rounds by a small offset."""
    return seed * 1000 + sample_index + 7 * round_


class SampleLog:
    def __init__(self, run_dir: str) -> None:
        self.run_dir = run_dir
        os.makedirs(run_dir, exist_ok=True)
        self.jsonl = os.path.join(run_dir, 'samples.jsonl')
        self.parquet = os.path.join(run_dir, 'samples.parquet')

    def append(self, rows: Iterable[SampleRow]) -> int:
        self._drop_partial_tail()
        count = 0
        with open(self.jsonl, 'a') as fh:
            for row in rows:
                fh.write(json.dumps(row.as_record(), ensure_ascii=False) + '\n')
                count += 1
            fh.flush()
            os.fsync(fh.fileno())
        return count

    def _drop_partial_tail(self) -> None:
        """Cut a partial last line (a kill mid-append) so the next append starts a fresh line.

        Without this the next record would be glued onto the partial one, turning a
        tolerable truncation into corruption that rows() can no longer read past.
        """
        if not os.path.exists(self.jsonl):
            return
        with open(self.jsonl, 'rb+') as fh:
            size = fh.seek(0, os.SEEK_END)
            if size == 0:
                return
            fh.seek(size - 1)
            if fh.read(1) == b'\n':
                return
            cut, pos = 0, size
            while pos > 0:
                start = max(0, pos - 65536)
                fh.seek(start)
                index = fh.read(pos - start).rfind(b'\n')
                if index >= 0:
                    cut = start + index + 1
                    break
                pos = start
            log.warning('%s: dropping %d bytes of partial final line', self.jsonl, size - cut)
            fh.truncate(cut)

    def rows(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.jsonl):
            return []
        rows = []
        with open(self.jsonl) as fh:
            for number, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    # A kill mid-append leaves a partial last line; anything earlier is
                    # real corruption.
                    if fh.read().strip():
                        raise
                    log.warning('%s: dropping truncated final line %d', self.jsonl, number)
        return rows

    def done_keys(self) -> set[tuple[str, int, int]]:
        """(cve, sample_index, round) already logged — the resume set."""
        return {(r['cve'], r['sample_index'], r['round']) for r in self.rows()}

    def finalize(self) -> str:
        rows = self.rows()
        if rows:
            tables.write_rows(rows, self.parquet)
        return self.parquet


def read_samples(run_dir: str) -> list[dict[str, Any]]:
    parquet = os.path.join(run_dir, 'samples.parquet')
    if os.path.exists(parquet):
        return tables.read_rows(parquet)
    return SampleLog(run_dir).rows()


def export_rules(
    run_dir: str, out_dir: str, column: str = 'rule_text', key: str = 's_valid'
) -> list[str]:
    """One <CVE>.cocci per CVE from a run's rows (a valid row first), for the suite audit."""
    os.makedirs(out_dir, exist_ok=True)
    best: dict[str, dict[str, Any]] = {}
    for row in read_samples(run_dir):
        text = row.get(column)
        if not text:
            continue
        current = best.get(row['cve'])
        if current is None or (bool(row.get(key)) and not bool(current.get(key))):
            best[row['cve']] = row
    return [
        tables.write_text(os.path.join(out_dir, f'{cve}.cocci'), best[cve][column])
        for cve in sorted(best)
    ]
