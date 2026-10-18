"""The oracle commands: replay the gold rules, score one candidate."""

import argparse
import json
import logging
import os
import time
from typing import Any

from rulegen import tables
from rulegen.cli import common
from rulegen.oracle import reward
from rulegen.oracle.service import OracleService
from rulegen.schema import (
    FIRE,
    LEG_BP,
    LEG_HEAD,
    SILENT,
    TRUNCATED,
    CveRecord,
    Score,
    ScoreRequest,
    branch_of_ref,
)

log = logging.getLogger('rulegen')

# The replay statuses that fail the command: a rule the oracle rejected, or a
# scan the engine never finished.
UNEXPECTED = ('FAIL', 'TRUNCATED')


def replay_status(score: Score) -> tuple[str, list[str], list[str]]:
    """(status, failing gating legs, head refs that fired) for a gold rule's Score.

    Anything but 'ok' and the two head-fire statuses is unexpected. Head legs
    are information: a fire on today's head of a branch whose backport leg was
    silent is the one shape that can mean a regression rather than a missing
    backport, and gets its own status.
    """
    bad = [leg.name for leg in score.legs if leg.gating and not leg.ok]
    head_fires = [leg.ref for leg in score.legs_of(LEG_HEAD) if leg.verdict == FIRE]
    silent_bp = {branch_of_ref(leg.ref) for leg in score.legs_of(LEG_BP) if leg.verdict == SILENT}
    truncated = {leg.name for leg in score.legs if leg.verdict == TRUNCATED}
    if score.fail_class == TRUNCATED or (bad and set(bad) <= truncated):
        # Still unexpected -- the replay must fail on a broken environment --
        # but named for what it is: spatch did not finish, the rule was not judged.
        status = 'TRUNCATED'
    elif score.fail_class != 'none' or bad:
        status = 'FAIL'
    elif any(branch_of_ref(ref) in silent_bp for ref in head_fires):
        status = 'head-fire-after-backport'
    elif head_fires:
        status = 'head-fire'
    else:
        status = 'ok'
    return status, bad, head_fires


def _gold_records(args: argparse.Namespace) -> list[CveRecord]:
    records = [
        rec
        for rec in common.load_corpus(args)
        # .grep gold rules are in the corpus but not scorable by this oracle.
        if rec.has_rule and rec.cocci_rule and (not args.split or rec.split == args.split)
    ]
    if args.cve:
        wanted = set(args.cve)
        records = [rec for rec in records if rec.cve in wanted]
    # Ineligible gold CVEs (rejected upstream, unresolvable or non-ancestor
    # commits) are in no split and judged nowhere; say which, do not score them.
    ineligible = [rec for rec in records if not rec.eligible]
    if ineligible:
        log.info(
            'skipping %d ineligible gold rule(s): %s',
            len(ineligible),
            ' '.join(f'{rec.cve}[{",".join(rec.meta_issues[:2])}]' for rec in ineligible[:12]),
        )
        records = [rec for rec in records if rec.eligible]
    return records[: args.limit] if args.limit else records


def cmd_replay_gold(args: argparse.Namespace) -> int:
    records = _gold_records(args)
    log.info('replaying %d gold rules through the oracle', len(records))
    reqs: list[tuple[CveRecord, ScoreRequest]] = []
    gone = []
    for rec in records:
        # The corpus is a snapshot of the checkout's rules. A rule missing from
        # the checkout means the corpus is stale, not that the rule fails.
        if not os.path.exists(rec.rule_path):
            gone.append(rec.cve)
            continue
        with open(rec.rule_path) as fh:
            reqs.append((rec, ScoreRequest.for_record(rec, fh.read())))
    if gone:
        log.error(
            '%d gold rule(s) are in the corpus but not in the checkout (%s); '
            'rebuild with `rulegen build-corpus`',
            len(gone),
            ', '.join(gone[:5]),
        )

    started = time.monotonic()
    with OracleService(common.oracle_config(args), jobs=args.jobs) as svc:
        scores = svc.score_batch([req for _rec, req in reqs])
    elapsed = time.monotonic() - started

    results = []
    for (rec, _req), score in zip(reqs, scores, strict=True):
        status, bad, head_fires = replay_status(score)
        results.append(
            {
                'cve': rec.cve,
                'split': rec.split,
                'status': status,
                'fail_class': score.fail_class,
                'reward': score.reward,
                'valid': score.valid,
                'strong_valid': score.strong_valid,
                'bad_legs': bad,
                'head_fires': head_fires,
                't4_unrelated_files': score.t4_unrelated_files,
                't5_points': score.t5_points,
                't5_fired': score.t5_fired,
                't6_trees': score.t6_trees,
                't6_fired': score.t6_fired,
                'cost_prefilter_files': score.cost_prefilter_files,
                'cost_cpu_seconds': score.cost_cpu_seconds,
                'cost_wall_seconds': score.cost_wall_seconds,
                'wall_s': score.wall_seconds,
            }
        )
        if status != 'ok' or args.verbose:
            log.info(
                '%s %-16s reward=%.3f valid=%s %s',
                status.ljust(9),
                rec.cve,
                score.reward,
                score.valid,
                ('bad=' + ','.join(bad)) if bad else '',
            )
    if args.report:
        tables.write_json(args.report, results, indent=2)
        log.info('wrote %s', args.report)
    unexpected = sum(1 for r in results if r['status'] in UNEXPECTED)
    _log_replay_summary(args, len(records), scores, results, elapsed)
    return 1 if unexpected or gone else 0


def _log_replay_summary(
    args: argparse.Namespace,
    n_records: int,
    scores: list[Score],
    results: list[dict[str, Any]],
    elapsed: float,
) -> None:
    checks = sum(len(score.legs) for score in scores)
    log.info('---')
    log.info(
        '%d gold rules, %d unexpected (%d truncated), %d oracle checks',
        n_records,
        sum(1 for r in results if r['status'] in UNEXPECTED),
        sum(1 for r in results if r['status'] == 'TRUNCATED'),
        checks,
    )
    log.info(
        'valid %d, strong-valid %d',
        sum(1 for s in scores if s.valid),
        sum(1 for s in scores if s.strong_valid),
    )
    if args.selectivity:
        t4 = [s.t4_unrelated_files for s in scores]
        log.info(
            'T4 lib/ survivors: 0 -> %d, 1-5 -> %d, >5 -> %d, unanswered -> %d',
            sum(1 for v in t4 if v == 0),
            sum(1 for v in t4 if v is not None and 1 <= v <= 5),
            sum(1 for v in t4 if v is not None and v > 5),
            sum(1 for v in t4 if v is None),
        )
    if args.range:
        pts = [s.t5_points for s in scores if s.t5_points is not None]
        misses = sum(1 for s in scores if s.t5_points and s.t5_fired != s.t5_points)
        log.info(
            'T5 range: %d rules swept, %d points, %d rules miss a point', len(pts), sum(pts), misses
        )
    if args.tree:
        log.info(
            'T6 whole-tree: %d rules scanned, %d fire on a branch head',
            sum(1 for s in scores if s.t6_trees),
            sum(1 for s in scores if s.t6_fired),
        )
    cpu = [s.cost_cpu_seconds for s in scores if s.cost_cpu_seconds is not None]
    if args.cost and cpu:
        log.info(
            'cost (CPU-s per whole-tree scan at %s): median %.1f, p90 %.1f, max %.1f',
            reward.COST_REF,
            tables.quantile(cpu, 0.5),
            tables.quantile(cpu, 0.9),
            max(cpu),
        )
    log.info(
        'wall %.1fs (%.2f rules/s, %.1f checks/s)',
        elapsed,
        n_records / elapsed if elapsed else 0,
        checks / elapsed if elapsed else 0,
    )


def cmd_score(args: argparse.Namespace) -> int:
    rec = common.records_by_cve(args).get(args.cve)
    if rec is None or not rec.fix:
        log.error('no fix commit known for %s', args.cve)
        return 2
    with open(args.rule) as fh:
        req = ScoreRequest.for_record(rec, fh.read())
    with OracleService(common.oracle_config(args), jobs=1) as svc:
        score = svc.score(req)
    print(json.dumps(score.to_row(), indent=2))
    return 0 if score.valid else 1


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        'replay-gold',
        help='score the gold rules through the oracle; fails on an unexpected verdict',
    )
    common.add_oracle_args(p)
    p.add_argument('--split', default='')
    p.add_argument('--cve', action='append', default=[])
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--report', default='')
    p.set_defaults(func=cmd_replay_gold)

    p = sub.add_parser('score', help='score one candidate rule file for one CVE')
    common.add_oracle_args(p)
    p.add_argument('--cve', required=True)
    p.add_argument('--rule', required=True)
    p.set_defaults(func=cmd_score)
