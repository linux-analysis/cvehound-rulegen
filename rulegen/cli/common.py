"""What the commands share: the default layout, the oracle flags, the corpus tables."""

import argparse
import json
import logging
import os
from collections import Counter
from collections.abc import Callable
from typing import Any

from rulegen import corpus, sources
from rulegen.oracle import reward
from rulegen.oracle.service import OracleConfig
from rulegen.schema import DEFAULT_BRANCHES, CveMeta, CveRecord

log = logging.getLogger('rulegen')

DEFAULT_KERNEL = os.environ.get('CVEHOUND_KERNEL', '../cvehound/tests/linux')
DEFAULT_DATA = 'data'
DEFAULT_WORK = 'runs/oracle'


def kernel(args: argparse.Namespace) -> str:
    return os.path.abspath(args.kernel)


def print_json(data: Any, indent: int = 1) -> None:
    print(json.dumps(data, indent=indent, default=str))


def add_oracle_args(
    p: argparse.ArgumentParser, *, jobs: int = 1, selectivity: bool = False
) -> None:
    """The oracle knobs every scoring subcommand shares (one place to extend)."""
    p.add_argument('--work', default=DEFAULT_WORK)
    p.add_argument('--branch', action='append', default=[])
    p.add_argument('--jobs', type=int, default=jobs)
    p.add_argument('--zygote', default=None)
    p.add_argument('--no-cache', action='store_true')
    p.add_argument('--no-decoys', action='store_true')
    p.add_argument(
        '--selectivity',
        action=argparse.BooleanOptionalAction,
        default=selectivity,
        help='T4: lib/ prefilter survivors',
    )
    p.add_argument('--range', action='store_true', help='T5: fire at every point in Fixes..Fix~')
    p.add_argument(
        '--range-mode',
        choices=reward.RANGE_MODES,
        default='tags',
        help="T5 enumeration, like the suite's --between-mode (default: tags)",
    )
    p.add_argument(
        '--range-max-points',
        type=int,
        default=reward.RANGE_MAX_POINTS,
        help='T5 signatures to check; 0 = every distinct one',
    )
    p.add_argument(
        '--tree', action='store_true', help='T6: whole-tree scan at each backport commit'
    )
    p.add_argument(
        '--heads',
        action='store_true',
        help="informational whole-tree scans at today's branch heads (never gating)",
    )
    p.add_argument(
        '--cost', action='store_true', help='CPU-s and prefilter files for one tree scan'
    )
    p.add_argument('--tree-jobs', type=int, default=1, help='spatch -j for whole-tree scans')
    p.add_argument('--worktrees', default=None, help='worktree root (default <work>/worktrees)')
    p.add_argument(
        '--heavy-slots',
        type=int,
        default=0,
        help='workers allowed inside a whole-tree scan at once (0 = all)',
    )
    p.add_argument(
        '--address-space-limit',
        type=int,
        default=reward.SPATCH_ADDRESS_SPACE_LIMIT,
        help='RLIMIT_AS per oracle worker, bytes (0 = off). Bounds whole-tree scans.',
    )


def oracle_config(args: argparse.Namespace) -> OracleConfig:
    """The OracleConfig the add_oracle_args flags describe."""
    return OracleConfig(
        kernel=kernel(args),
        work_root=os.path.abspath(args.work),
        branches=tuple(args.branch) if args.branch else DEFAULT_BRANCHES,
        use_cache=not args.no_cache,
        zygote=args.zygote,
        worktrees=args.worktrees,
        heavy_slots=args.heavy_slots,
        address_space_limit=args.address_space_limit,
        run_decoys=not args.no_decoys,
        run_selectivity=args.selectivity,
        run_range=args.range,
        run_tree=args.tree,
        run_heads=args.heads,
        run_cost=args.cost,
        tree_jobs=args.tree_jobs,
        range_max_points=args.range_max_points,
        range_mode=args.range_mode,
    )


# -- the data tables, built on first use ------------------------------------------


def _load_or_build(path: str, load: Callable[[str], Any], build: Callable[[], Any]) -> Any:
    if os.path.exists(path):
        return load(path)
    log.info('no %s yet; building it', os.path.basename(path))
    return build()


def build_cvemeta(
    args: argparse.Namespace, vulns: str | None = None, cip: str | None = None
) -> list[CveMeta]:
    """Every metadata source side by side -> data/cvemeta.parquet (rulegen.sources)."""
    from cvehound.util import get_rule_cves

    vulns_dir, cip_dir = sources.default_source_dirs()
    vulns_dir, cip_dir = vulns or vulns_dir, cip or cip_dir
    for path in (vulns_dir, cip_dir):
        if not os.path.isdir(path):
            raise SystemExit(
                f'{path} is missing; run `cvehound_update_metadata <kernel> <archive>` '
                '(or pass --vulns/--cip)'
            )
    all_rules, _assigned, _disputed = get_rule_cves()
    headers = sources.header_views(all_rules)
    metas = sources.build_cvemeta(kernel(args), vulns_dir, cip_dir, headers)
    out = os.path.join(args.data, sources.CVEMETA)
    sources.save_cvemeta(metas, out)
    log.info('wrote %s (%d CVEs, %d eligible)', out, len(metas), sum(m.eligible for m in metas))
    codes = Counter(sources.issue_code(issue) for m in metas for issue in m.issues)
    for code, num in sorted(codes.items()):
        log.info('  %-28s %d', code, num)
    return metas


def load_cvemeta(args: argparse.Namespace) -> list[CveMeta]:
    path = os.path.join(args.data, sources.CVEMETA)
    return _load_or_build(path, sources.load_cvemeta, lambda: build_cvemeta(args))


def build_corpus(args: argparse.Namespace) -> list[CveRecord]:
    records = corpus.build_corpus(load_cvemeta(args), args.metadata)
    corpus.save_corpus(records, os.path.join(args.data, corpus.CORPUS))
    return records


def load_corpus(args: argparse.Namespace) -> list[CveRecord]:
    path = os.path.join(args.data, corpus.CORPUS)
    return _load_or_build(path, corpus.load_corpus, lambda: build_corpus(args))


def records_by_cve(args: argparse.Namespace) -> dict[str, CveRecord]:
    return {rec.cve: rec for rec in load_corpus(args)}
