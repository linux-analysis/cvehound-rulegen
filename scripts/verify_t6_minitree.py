#!/usr/bin/env python3
"""Does the prefiltered mini-tree scan agree with a real whole-tree scan?

The oracle's T6 and head legs scan the files `git grep` selects with spatch's
own grep query, linked into a per-commit directory, instead of a worktree
(rulegen/oracle/prefilter.py). This script is the equivalence check behind
that: for N gold rules and the branch heads, run both a whole-tree scan of a
real checkout (test_06 as written) and `reward.prefilter_scan`, and report
every verdict that differs. Zero is the only acceptable count.

    uv run python scripts/verify_t6_minitree.py --limit 50 [--branch REF ...]

Cost: one worktree per branch (the store keeps them) and two scans per (rule,
branch); with a warm verdict cache the worktree half is free.
"""

import argparse
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cvehound.oracle.kerneltree import cached_all_files_check, hound_at  # noqa: E402

from rulegen import corpus  # noqa: E402
from rulegen.oracle import prefilter, reward  # noqa: E402
from rulegen.schema import DEFAULT_BRANCHES, FIRE, LEG_TREE, NO_FILES, SILENT, Leg  # noqa: E402


def worktree_scan(ctx: reward.OracleCtx, cve: str, ref: str, jobs: int = 1) -> Leg:
    """The reference whole-tree scan over a real checkout of `ref`."""

    def check() -> str:
        fired = cached_all_files_check(
            ctx.hound,
            lambda: hound_at(ctx.hound, ctx.worktree(ref)),
            ctx.cache,
            ctx.materializer.whole_tree_sig(ref),
            cve,
            jobs,
        )
        return FIRE if fired else SILENT

    return reward.judge(f'{LEG_TREE}:{ref}', SILENT, check, cve)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        '--kernel', default=os.environ.get('CVEHOUND_KERNEL', '../cvehound/tests/linux')
    )
    ap.add_argument('--work', default='runs/oracle')
    ap.add_argument('--data', default='data')
    ap.add_argument('--limit', type=int, default=20)
    ap.add_argument('--branch', action='append', default=[])
    ap.add_argument('--tree-jobs', type=int, default=4)
    # Off by default it would let one cached verdict answer both scans -- the
    # comparison would test the store, not the two scans.
    ap.add_argument(
        '--no-cache', action='store_true', help='scan afresh; read and write no verdicts'
    )
    ap.add_argument('--zygote', default=None, help="cvehound's zygote mode (auto, on, off)")
    ap.add_argument(
        '--address-space-limit',
        type=int,
        default=0,
        help='RLIMIT_AS in bytes, as the oracle workers run under (0 = none)',
    )
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()
    if args.address_space_limit:
        reward.limit_address_space(args.address_space_limit)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format='%(message)s'
    )

    branches = tuple(args.branch) or DEFAULT_BRANCHES
    records = sorted(corpus.load_records(args.data).values(), key=lambda rec: rec.cve)
    records = [rec for rec in records if rec.has_rule and rec.cocci_rule and rec.eligible]
    records = records[: args.limit]
    ctx = reward.make_ctx(
        args.kernel,
        args.work,
        branches,
        use_cache=not args.no_cache,
        zygote=args.zygote,
        worktrees_root=os.path.join(args.work, 'worktrees'),
    )
    differences = []
    compared = 0
    started = time.monotonic()
    for rec in records:
        with open(rec.rule_path) as fh:
            rule_text = fh.read()
        rule_path, sha = reward.write_candidate(ctx, rec.cve, rule_text)
        parsed, query, _err = reward.parse_and_query(ctx, rule_path, sha)
        if not parsed or not query:
            print(f'{rec.cve}: skipped (parse={parsed}, query={query!r})')
            continue
        ctx.hound.add_rule(rec.cve, rule_path)
        words = prefilter.query_words(query)
        for ref in branches:
            commit = ctx.resolve(ref)
            if not commit:
                continue
            full = worktree_scan(ctx, rec.cve, ref, jobs=args.tree_jobs)
            mini = reward.prefilter_scan(
                ctx,
                rec.cve,
                f'{LEG_TREE}:{ref}@{commit}',
                commit,
                SILENT,
                words,
                jobs=args.tree_jobs,
            )
            compared += 1
            # The verdicts, not .ok: a fire and a truncated scan are both not-ok
            # and would hide each other. no-files is a silence (Leg.ok's own rule).
            if _answer(full.verdict) != _answer(mini.verdict):
                differences.append((rec.cve, ref, full.verdict, mini.verdict))
                print(f'DIFF {rec.cve} {ref}: worktree={full.verdict} minitree={mini.verdict}')
            elif args.verbose:
                print(
                    f'ok   {rec.cve} {ref}: {full.verdict} ({full.seconds:.1f}s vs {mini.seconds:.1f}s)'
                )
    print(
        f'{compared} scans compared over {len(records)} rules and {len(branches)} refs in '
        f'{time.monotonic() - started:.0f}s: {len(differences)} differences'
    )
    return 1 if differences else 0


def _answer(verdict: str) -> str:
    return SILENT if verdict == NO_FILES else verdict


if __name__ == '__main__':
    sys.exit(main())
