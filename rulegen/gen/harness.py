"""The sample → parse → finalize → score loop, logged per attempt.

Generation and scoring overlap: while the oracle scores chunk k, the adapter
is already sampling chunk k+1. Identical rule texts within a run are scored
once (content-addressed), and a completion with no rule in it never reaches
the oracle (fail_class='contract'). Every attempt becomes a row, resumable by
(cve, sample_index, round).
"""

import concurrent.futures as cf
import contextlib
import json
import logging
import os
import time
from collections.abc import Callable, Iterator
from concurrent.futures.process import BrokenProcessPool
from typing import Any, Protocol

from rulegen import corpus, extract, tables, tiers
from rulegen.gen import canon, prompts
from rulegen.gen import manifest as manifest_mod
from rulegen.gen.adapters.base import (
    AbortRun,
    Adapter,
    Completion,
    GenRequest,
    SamplingParams,
    make_adapter,
)
from rulegen.gen.config import (
    RunConfig,
    config_sha,
    context_error,
    context_needed,
    counter_safety,
    resolve_subset,
    to_dict,
    to_oracle_config,
)
from rulegen.gen.log import SampleLog, SampleRow, attempt_id, attempt_seed, score_counts
from rulegen.oracle.service import OracleService
from rulegen.promptbuild import finalize_completion
from rulegen.schema import CveRecord, ExampleRecord, Score, ScoreRequest
from rulegen.tokens import make_counter

log = logging.getLogger(__name__)


class Scorer(Protocol):
    def score_batch(self, reqs: list[ScoreRequest]) -> list[Score]: ...

    def close(self) -> None: ...


ScorerFactory = Callable[[], Scorer]


def load_split(
    data_dir: str, split: str, subset: set[str] | None, limit: int
) -> tuple[list[ExampleRecord], dict[str, CveRecord], dict[str, str]]:
    """Examples of a split joined to their corpus rows, plus gold tier classes."""
    records = corpus.load_records(data_dir)
    examples = extract.load_split_examples(data_dir, split)
    unanchored = [ex.cve for ex in examples if not ex.fixes]
    if unanchored:
        raise ValueError(
            f'{len(unanchored)} {split} examples have no introducing commit (e.g. '
            f'{", ".join(unanchored[:3])}): their prompts lack every range-derived section and '
            'the oracle cannot bound the vulnerable range. Rebuild with `rulegen build-dataset`.'
        )
    # The examples were extracted from the corpus of their day; the oracle
    # judges against today's. A commit that moved (a rebuilt cvemeta, a
    # re-agreed introducing commit) would silently mismatch prompt and verdict.
    stale = [
        ex.cve
        for ex in examples
        if ex.cve in records
        and (ex.fix != records[ex.cve].fix or ex.fixes != records[ex.cve].fixes)
    ]
    if stale:
        raise ValueError(
            f'{len(stale)} {split} examples disagree with data/cves.parquet on the fix or '
            f'introducing commit (e.g. {", ".join(stale[:3])}); rebuild with `rulegen build-dataset`.'
        )
    if subset is not None:
        examples = [ex for ex in examples if ex.cve in subset]
    examples.sort(key=lambda ex: ex.cve)
    if limit:
        examples = examples[:limit]
    return examples, records, tiers.load_classes(data_dir)


def served_model_error(model_file: str | None, adapter_desc: dict[str, Any]) -> str | None:
    """Why the server is not serving the weights the config names, or None.

    llama-server answers whatever model it has loaded and ignores the model id in
    the request, so a config naming one GGUF would happily run against whatever
    another job had loaded. Its /props report the loaded file; a run refuses to
    start when that is a different file. A server that reports
    nothing (vLLM, an API) cannot be checked and is let through.
    """
    if not model_file:
        return None
    served = (adapter_desc.get('props') or {}).get('model_path')
    if not served:
        return None
    if os.path.realpath(served) == os.path.realpath(model_file) or os.path.basename(
        served
    ) == os.path.basename(model_file):
        return None
    return f'the server is serving {served}, but the config names {model_file}'


class Harness:
    def __init__(
        self,
        cfg: RunConfig,
        kernel: str,
        data_dir: str = 'data',
        adapter: Adapter | None = None,
        scorer_factory: ScorerFactory | None = None,
    ) -> None:
        self.cfg = cfg
        self.kernel = os.path.abspath(kernel)
        self.data_dir = data_dir
        self.config_sha = config_sha(cfg)
        self.run_dir = os.path.join(cfg.out, cfg.run_id)
        self.adapter = adapter or make_adapter(cfg.model)
        self.scorer_factory = scorer_factory or self._oracle_factory
        self._scorer: Scorer | None = None
        self.counter_id, self.count = make_counter(cfg.model.tokenizer_json)
        self.safety = counter_safety(cfg.model.tokenizer_json)
        self.system_sha = prompts.system_sha(cfg.prompt.system_prompt)
        self.transform = canon.transform_fn(cfg.transform)
        self.adapter_id = getattr(self.adapter, 'id', cfg.model.adapter)
        self.log = SampleLog(self.run_dir)
        self.memo: dict[
            tuple[str, str], tuple[str, Score]
        ] = {}  # (cve, rule_sha) -> (attempt, Score)
        # cve -> the example's historical file names: build() records them so
        # finalize can complete Files: without the example in hand.
        self.renames: dict[str, dict[str, list[str]]] = {}
        # cve -> the corpus split, so a row of a merged split (`gold`) still says
        # which temporal split its CVE belongs to.
        self.splits: dict[str, str] = {}
        self.honors_sampling = bool(getattr(self.adapter, 'honors_sampling', True))
        self.params = SamplingParams(
            temperature=cfg.sampling.temperature,
            top_p=cfg.sampling.top_p,
            max_tokens=cfg.sampling.max_tokens,
            thinking=cfg.model.thinking,
        )

    # -- setup -------------------------------------------------------------

    def _oracle_factory(self) -> Scorer:
        return OracleService(
            to_oracle_config(self.cfg.oracle, self.kernel), jobs=self.cfg.oracle.jobs
        )

    def scorer(self) -> Scorer:
        if self._scorer is None:
            self._scorer = self.scorer_factory()
        return self._scorer

    def reset_scorer(self) -> None:
        if self._scorer is not None:
            # A broken pool may refuse to close cleanly; the replacement matters, not the goodbye.
            with contextlib.suppress(Exception):
                self._scorer.close()
        self._scorer = None

    def prepare(self) -> tuple[list[ExampleRecord], dict[str, CveRecord], dict[str, str]]:
        """The run's examples (those whose fix is known), their corpus rows and tier
        classes. Writes the opening manifest, which refuses a server serving other weights."""
        subset = resolve_subset(self.cfg.data, self.data_dir)
        examples, records, classes = load_split(
            self.data_dir, self.cfg.data.split, subset, self.cfg.data.limit
        )
        examples = [ex for ex in examples if ex.cve in records and records[ex.cve].fix]
        self.splits = {ex.cve: records[ex.cve].split for ex in examples}
        self.write_manifest()
        return examples, records, classes

    def build(self, example: ExampleRecord) -> prompts.BuiltPrompt:
        self.renames[example.cve] = example.historical_names
        p = self.cfg.prompt
        return prompts.build_messages(
            example,
            p.policy,
            p.budget_tokens,
            system_prompt=p.system_prompt,
            hide_cve_id=p.hide_cve_id,
            count=self.count,
            counter_id=self.counter_id,
        )

    def write_manifest(self, totals: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = self.cfg
        try:
            adapter_desc = self.adapter.describe()
        except Exception as err:  # noqa: BLE001 — a dead server must not block the manifest
            adapter_desc = {'error': repr(err)}
        man = manifest_mod.build_manifest(
            to_dict(cfg),
            self.config_sha,
            to_oracle_config(cfg.oracle, self.kernel),
            adapter_desc,
            self.data_dir,
            prompt_extra={
                'policy': cfg.prompt.policy,
                'budget_tokens': cfg.prompt.budget_tokens,
                'counter_id': self.counter_id,
                'system_prompt_id': cfg.prompt.system_prompt,
                'system_sha': self.system_sha,
                'hide_cve_id': cfg.prompt.hide_cve_id,
                'context_tokens': cfg.model.context_tokens,
                'safety': self.safety,
                'context_needed': context_needed(cfg),
            },
            cvehound_repo=manifest_mod.cvehound_path(self.kernel),
        )
        if totals is not None:
            man['totals'] = totals
        manifest_mod.write_manifest(self.run_dir, man)
        why = served_model_error(cfg.model.model_file, adapter_desc) if totals is None else None
        if why:
            raise ValueError(f'{why}: load the right model, or fix model.model_file')
        return man

    # -- one attempt -------------------------------------------------------

    def new_row(
        self,
        example: ExampleRecord,
        cls: str,
        built: prompts.BuiltPrompt,
        index: int,
        round_: int = 0,
    ) -> SampleRow:
        cfg = self.cfg
        return SampleRow(
            run_id=cfg.run_id,
            config_sha=self.config_sha,
            cve=example.cve,
            split=self.splits.get(example.cve, cfg.data.split)
            if cfg.data.split in extract.MERGED_SPLITS
            else cfg.data.split,
            cls=cls,
            mode=cfg.mode,
            policy=cfg.prompt.policy,
            prompt_sha=built.prompt_sha,
            messages_sha=built.messages_sha,
            system_prompt_id=cfg.prompt.system_prompt,
            system_sha=self.system_sha,
            adapter=self.adapter_id,
            model_id=cfg.model.model or self.adapter_id,
            temperature=cfg.sampling.temperature,
            top_p=cfg.sampling.top_p,
            max_tokens=cfg.sampling.max_tokens,
            thinking=cfg.model.thinking,
            seed=attempt_seed(cfg.sampling.seed, index, round_),
            sample_index=index,
            round=round_,
            attempt_id=attempt_id(example.cve, index, round_),
            prompt_tokens_est=built.token_estimate,
            truncated=' '.join(built.truncated) if round_ == 0 else '',
            sampling_honored=self.honors_sampling,
        )

    def first_task(
        self, example: ExampleRecord, cls: str, built: prompts.BuiltPrompt, index: int
    ) -> tuple[SampleRow, GenRequest]:
        """Round 0 of attempt `index`: the row to log, and the request that fills it."""
        row = self.new_row(example, cls, built, index)
        return row, GenRequest(built.messages, self.params, row.seed, example=example)

    def record_completion(self, row: SampleRow, comp: Completion, rec: CveRecord) -> None:
        row.completion_text = comp.text
        row.reasoning_text = comp.reasoning
        row.finish_reason = comp.finish_reason
        row.tokens_prompt = comp.tokens_prompt
        row.tokens_completion = comp.tokens_completion
        row.tokens_reasoning = comp.tokens_reasoning
        row.latency_s = comp.latency_s
        row.error = comp.error
        row.request_id = comp.request_id
        row.tokens_cached = comp.tokens_cached
        row.cost_usd = comp.cost_usd
        row.tool_calls = int(comp.raw.get('tool_calls') or 0) if comp.raw else 0
        row.tool_attempts_denied = int(comp.raw.get('tool_attempts_denied') or 0) if comp.raw else 0
        timings = comp.raw.get('timings') if comp.raw else None
        row.server_timings = json.dumps(timings) if timings else None
        if comp.tokens_prompt is not None:
            prompt_tokens = comp.tokens_prompt
        else:
            # No server-reported usage: estimate, unless the request never got processed.
            prompt_tokens = row.prompt_tokens_est if comp.error is None else 0
        completion_tokens = (
            comp.tokens_completion if comp.tokens_completion is not None else self.count(comp.text)
        )
        row.tokens_cum += prompt_tokens + completion_tokens
        done = finalize_completion(comp.text, rec, self.transform, self.renames.get(rec.cve))
        row.record_rule(done)
        row.transform_applied = done.changed

    def context_error(self, estimate: int, max_tokens: int) -> str | None:
        """Why a request of `estimate` prompt tokens must not be sent: it cannot fit the slot."""
        return context_error(estimate, self.safety, max_tokens, self.cfg.model.context_tokens)

    def generate(self, tasks: list[tuple[SampleRow, GenRequest]]) -> list[Completion]:
        """Sample every task, `concurrency` requests in flight; completions in task order.

        A request that cannot fit the slot is logged as its own error row
        rather than sent to fail there (llama-server answers 400 and the
        chain would lose the turn either way).
        """
        workers = max(1, self.cfg.model.concurrency)
        out: list[Completion | None] = [None] * len(tasks)
        with cf.ThreadPoolExecutor(workers) as pool:
            futures = {}
            for i, (row, req) in enumerate(tasks):
                # The row already carries the prompt's estimate (build or repair turn).
                why = self.context_error(row.prompt_tokens_est, req.params.max_tokens)
                if why is not None:
                    out[i] = Completion(error=why)
                    continue
                futures[pool.submit(self.adapter.complete, req)] = i
            for future in cf.as_completed(futures):
                index = futures[future]
                try:
                    out[index] = future.result()
                except AbortRun:
                    # The run must stop here and this chunk must not be logged:
                    # an error row would count as done on --resume.
                    raise
                except Exception as err:  # noqa: BLE001 — adapters should not raise, but if one does
                    out[index] = Completion(error=f'adapter raised: {err!r}')
        return [comp or Completion(error='no completion') for comp in out]

    # -- scoring -----------------------------------------------------------

    def score_rows(
        self,
        rows: list[SampleRow],
        comps: list[Completion],
        records: dict[str, CveRecord],
    ) -> list[SampleRow]:
        """Attach a Score to every row: contract failures inline, unique rules via the oracle."""
        pending: list[tuple[SampleRow, ScoreRequest]] = []
        first_of: dict[tuple[str, str], SampleRow] = {}
        for row, comp in zip(rows, comps, strict=True):
            rec = records[row.cve]
            self.record_completion(row, comp, rec)
            if row.rule_text is None:
                row.attach(
                    Score.unscored(row.cve, row.completion_text, 'contract', comp.error or '')
                )
                continue
            key = (row.cve, row.rule_sha)
            if key in self.memo:
                prior, score = self.memo[key]
                row.dedup_of = prior
                row.attach(score)
                continue
            if key in first_of:
                row.dedup_of = first_of[key].attempt_id
                continue  # scored once the first copy comes back
            first_of[key] = row
            pending.append((row, ScoreRequest.for_record(rec, row.rule_text)))
        if pending:
            scores = self._score_batch([req for _row, req in pending])
            for (row, _req), score in zip(pending, scores, strict=True):
                row.attach(score)
                # A crash inside the oracle is the harness's verdict on that
                # moment, not on the rule: a later copy gets scored afresh.
                if score.fail_class != 'harness':
                    self.memo[(row.cve, row.rule_sha)] = (row.attempt_id, score)
        for row in rows:
            if not row.score and row.dedup_of:
                row.score = dict(first_of[(row.cve, row.rule_sha)].score)
        return rows

    def _score_batch(self, reqs: list[ScoreRequest]) -> list[Score]:
        try:
            return self.scorer().score_batch(reqs)
        except BrokenProcessPool as err:
            log.error('oracle pool died (%r); recreating it and retrying the chunk once', err)
            self.reset_scorer()
            return self.scorer().score_batch(reqs)

    # -- the run -----------------------------------------------------------

    @contextlib.contextmanager
    def finishing(self, totals: dict[str, Any], started: float) -> Iterator[None]:
        """Run the body, then always: drop the scorer, turn the log into parquet, and
        close the manifest with the totals and the wall clock since `started`."""
        try:
            yield
        finally:
            self.reset_scorer()
            self.log.finalize()
            totals['wall_s'] = round(time.monotonic() - started, 1)
            self.write_manifest(totals)
        log.info('done: %s', totals)

    def run_sample(self, resume: bool = False, dry_run: bool = False) -> dict[str, Any]:
        cfg = self.cfg
        started = time.monotonic()
        examples, records, classes = self.prepare()
        log.info(
            'run %s: %d CVEs x n=%d, policy %s, adapter %s -> %s',
            cfg.run_id,
            len(examples),
            cfg.sampling.n,
            cfg.prompt.policy,
            self.adapter_id,
            self.run_dir,
        )
        if dry_run:
            return self.dry_run(examples)
        done = self.log.done_keys() if resume else set()
        n = 1 if cfg.mode == 'mechanical' else cfg.sampling.n
        totals = dict.fromkeys(
            (
                'n_rows',
                'n_scored',
                'n_valid',
                'n_strong_valid',
                'n_contract',
                'n_harness',
                'n_truncated_legs',
            ),
            0,
        )
        scoring: cf.Future | None = None

        def flush() -> None:
            """Log the in-flight chunk's scores, if any; a no-op once it has been taken."""
            nonlocal scoring
            future, scoring = scoring, None
            if future is None:
                return
            rows = future.result()
            self.log.append(rows)
            classes = [r.score.get('fail_class') for r in rows]
            n_contract, n_harness = classes.count('contract'), classes.count('harness')
            totals['n_rows'] += len(rows)
            totals['n_scored'] += len(rows) - n_contract - n_harness
            totals['n_contract'] += n_contract
            totals['n_harness'] += n_harness
            for key, count in score_counts(rows).items():
                totals[key] += count
            if n_harness and n_harness + n_contract == len(rows):
                log.warning(
                    'every scored row of this chunk failed inside the oracle (%d rows): '
                    'systematic scoring failure, check the oracle setup',
                    n_harness,
                )
            log.info(
                '  %d rows logged, %d valid so far (%.0fs)',
                totals['n_rows'],
                totals['n_valid'],
                time.monotonic() - started,
            )

        with self.finishing(totals, started), cf.ThreadPoolExecutor(1) as score_pool:
            try:
                for start in range(0, len(examples), cfg.chunk_cves):
                    tasks: list[tuple[SampleRow, GenRequest]] = []
                    for example in examples[start : start + cfg.chunk_cves]:
                        built = self.build(example)
                        cls = classes.get(example.cve, '')
                        tasks += [
                            self.first_task(example, cls, built, index)
                            for index in range(n)
                            if (example.cve, index, 0) not in done
                        ]
                    if not tasks:
                        continue
                    comps = self.generate(tasks)
                    flush()  # previous chunk's scores, before we queue the next
                    rows = [row for row, _req in tasks]
                    scoring = score_pool.submit(self.score_rows, rows, comps, records)
                flush()
            finally:
                # A chunk is still in flight only when the try body raised: drain it so its
                # rows are not lost, but never let that mask the original exception.
                try:
                    flush()
                except Exception:  # noqa: BLE001
                    log.exception('could not log the last chunk while unwinding')
        return totals

    def dry_run(self, examples: list[ExampleRecord]) -> dict[str, Any]:
        """Build every prompt and write them to prompts.parquet; no model, no oracle."""
        rows = []
        for example in examples:
            built = self.build(example)
            rows.append(
                {
                    'cve': example.cve,
                    'policy': self.cfg.prompt.policy,
                    'prompt_sha': built.prompt_sha,
                    'messages_sha': built.messages_sha,
                    'token_estimate': built.token_estimate,
                    'truncated': ','.join(built.truncated),
                    'text': built.messages[-1]['content'],
                }
            )
        path = os.path.join(self.run_dir, 'prompts.parquet')
        if rows:
            tables.write_rows(rows, path)
        estimates = [r['token_estimate'] for r in rows] or [0]
        totals = {
            'n_prompts': len(rows),
            'tokens_median': tables.quantile(estimates, 0.5),
            'tokens_max': max(estimates),
            'n_truncated': sum(1 for r in rows if r['truncated']),
            'dry_run': True,
        }
        self.write_manifest(totals)
        log.info('dry run: %s -> %s', totals, path)
        return totals


def run(
    cfg: RunConfig,
    kernel: str,
    data_dir: str = 'data',
    adapter: Adapter | None = None,
    scorer_factory: ScorerFactory | None = None,
    resume: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    harness = Harness(
        cfg, kernel, data_dir=data_dir, adapter=adapter, scorer_factory=scorer_factory
    )
    if cfg.mode == 'pipeline':
        from rulegen.gen.pipeline import run_pipeline

        return run_pipeline(harness, resume=resume, dry_run=dry_run)
    return harness.run_sample(resume=resume, dry_run=dry_run)
