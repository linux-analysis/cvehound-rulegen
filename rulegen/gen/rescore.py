"""Re-score a run's completions offline, optionally after canonicalization.

The generation cost is the expensive half; scoring is cheap and cached. So a
second reading of the same completions — e.g. patch-to-detect canonicalization
of `-`/`+` transformation rules — is a derived run written next to the
original, with the transform recorded in its manifest.
"""

import dataclasses
import json
import logging
import os
import time
from typing import Any

from rulegen import corpus, promptbuild
from rulegen.gen import canon
from rulegen.gen.harness import Scorer
from rulegen.gen.log import SampleLog, SampleRow, read_samples, score_counts
from rulegen.gen.manifest import read_manifest, write_manifest
from rulegen.promptbuild import Finalized, finalize_completion
from rulegen.schema import Score, ScoreRequest

log = logging.getLogger(__name__)


def _describe_oracle(scorer: Scorer) -> dict[str, Any]:
    """How the rows were scored: the oracle's config and epochs, as the run manifest records them."""
    from rulegen.oracle import reward

    cfg = getattr(scorer, 'cfg', None)
    return {
        **reward.EPOCHS,
        **(dataclasses.asdict(cfg) if dataclasses.is_dataclass(cfg) else {}),
    }


AUTO = 'auto'  # reuse whatever transform the parent run scored with


def inherited_transform(manifest: dict[str, Any]) -> str | None:
    """The transform the parent run applied, so a rescore re-derives the same rules.

    A run with `transform: canon` scored canonicalized text; re-reading its
    completions without the transform would score different rules and quietly
    answer a different question. A manifest without the key cannot say which
    transform applied: name it explicitly.
    """
    config = manifest.get('config') or {}
    if 'transform' not in config:  # absent key != null value
        raise ValueError('manifest has no config.transform; pass --canonicalize explicitly')
    return config['transform']


def rescore(
    run_dir: str | list[str],
    out_dir: str,
    data_dir: str,
    scorer: Scorer,
    transform: str | None = AUTO,
    subset: set[str] | None = None,
) -> dict[str, Any]:
    """Several parents concatenate (the manifest comes from the first); `subset`
    keeps only those CVEs, for re-reading a handful of rows without paying for a
    shard."""
    started = time.monotonic()
    run_dirs = [run_dir] if isinstance(run_dir, str) else list(run_dir)
    rows = [row for d in run_dirs for row in read_samples(d)]
    if subset is not None:
        rows = [row for row in rows if row['cve'] in subset]
    manifest = read_manifest(run_dirs[0])
    records = corpus.load_records(data_dir)
    if transform == AUTO:
        transform = inherited_transform(manifest)
    fn = canon.transform_fn(transform)
    log.info('transform: %s', transform or 'none')

    pending: dict[tuple[str, str], ScoreRequest] = {}
    prepared: list[tuple[dict[str, Any], Finalized]] = []
    for row in rows:
        rec = records.get(row['cve'])
        text = row.get('completion_text') or ''
        # Same reading as the harness gave the original run: an empty completion is
        # a transport failure, not a rule, and hashes to ''. The Files: line is the
        # parent's own -- its paths plus whatever completion it applied -- since a
        # transform never touches it: the rescored rule is the bytes the parent judged.
        files = promptbuild.rule_files(row['rule_text']) if row.get('rule_text') else None
        done = finalize_completion(text, rec, fn, files=files)
        prepared.append((row, done))
        if done.rule is not None and rec is not None:
            pending.setdefault((rec.cve, done.sha), ScoreRequest.for_record(rec, done.rule))

    keys = list(pending)
    log.info(
        'rescoring %d rows: %d unique rules (%s)', len(rows), len(keys), transform or 'no transform'
    )
    scores = scorer.score_batch([pending[k] for k in keys]) if keys else []
    by_key = dict(zip(keys, scores, strict=True))

    run_id = os.path.basename(os.path.abspath(out_dir))
    out_log = SampleLog(out_dir)
    if os.path.exists(out_log.jsonl):
        os.remove(out_log.jsonl)
    new_rows: list[SampleRow] = []
    for row, done in prepared:
        srow = SampleRow.from_record(row)
        srow.run_id = run_id
        srow.config_sha = ''  # like the manifest below: not a row of the parent's cell
        srow.record_rule(done)
        srow.dedup_of = ''
        score = by_key.get((row['cve'], done.sha)) if done.rule is not None else None
        srow.attach(
            score
            or Score.unscored(
                row['cve'], row.get('completion_text') or '', 'contract', row.get('error') or ''
            )
        )
        srow.score['canonicalized'] = done.changed
        new_rows.append(srow)
    out_log.append(new_rows)
    out_log.finalize()
    totals = {
        'n_rows': len(new_rows),
        'n_canonicalized': sum(1 for r in new_rows if r.score.get('canonicalized')),
        **score_counts(new_rows),
        'wall_s': round(time.monotonic() - started, 1),
    }
    manifest = dict(manifest)
    manifest['run_id'] = run_id
    manifest['derived_from'] = [os.path.abspath(d) for d in run_dirs]
    if subset is not None:
        manifest['subset'] = sorted(subset)
    manifest['transform'] = transform
    # The parent's config describes how the completions were generated, not how these
    # rows were scored; a derived run must not pass for a run of that config.
    manifest['config_sha'] = None
    manifest['rescore'] = {'oracle': _describe_oracle(scorer)}
    manifest['totals'] = totals
    write_manifest(out_dir, manifest)
    log.info('wrote %s: %s', out_dir, json.dumps(totals))
    return totals
