"""The expert-iteration commands: the teacher's pool, and the rules it keeps."""

import argparse
import logging
import os
from collections import Counter

from rulegen import shapes, sources, synthetic, tables
from rulegen.cli import common
from rulegen.schema import GOLD_SPLITS

log = logging.getLogger('rulegen')


def cmd_clean_pool(args: argparse.Namespace) -> int:
    """The unruled CVEs the teacher may generate on, sharded for resumable runs."""
    rows = shapes.load_table(args.data)
    records = common.records_by_cve(args)
    # Every gold split by default: the baselines are evaluated over every gold
    # rule, so the exclusion cannot be test-only.
    against = set(args.against) or set(GOLD_SPLITS)
    gold = {rec.cve for rec in records.values() if rec.split in against}
    ineligible = {cve for cve, rec in records.items() if not rec.eligible}
    ids = synthetic.clean_pool(rows, args.split, gold, ineligible)
    in_split = [r for r in rows if r.split == args.split]
    # Why the ineligible ones are out, by issue code (a CVE can carry several).
    out_ineligible = [r for r in in_split if r.cve in ineligible]
    by_code = Counter(
        code
        for r in out_ineligible
        for code in map(sources.issue_code, records[r.cve].meta_issues)
        if code in sources.GATING
    )
    log.info(
        '%s: %d of %d CVEs survive exclusion against %s (%d gold); %d of the split were '
        'ineligible: %s',
        args.split,
        len(ids),
        len(in_split),
        sorted(against),
        len(gold),
        len(out_ineligible),
        dict(sorted(by_code.items())),
    )
    stem, ext = os.path.splitext(args.out)
    header = (
        f'{len(ids)} CVEs of split={args.split}, excluding fixes touching a '
        f'(file, function) of {sorted(against)}'
    )
    _write_ids(args.out, ids, header)
    parts = synthetic.shards(ids, args.shards) if args.shards > 1 else []
    for i, part in enumerate(parts):
        _write_ids(f'{stem}.{i}{ext}', part, f'shard {i}/{len(parts)} of {args.out}')
    kept = [r for r in rows if r.cve in set(ids)]
    summary = [
        f'# {os.path.basename(stem)}',
        '',
        f'{len(ids)} of {len(in_split)} `{args.split}` CVEs, excluded against {sorted(against)}.',
        '',
        *synthetic.counts_table('By fix shape', 'shape', Counter(r.shape for r in kept), 'CVEs'),
        *synthetic.counts_table('By year', 'year', Counter(r.year for r in kept), 'CVEs'),
        f'Shards: {[len(p) for p in parts]}' if parts else '',
    ]
    tables.write_text(f'{stem}.md', '\n'.join(summary).rstrip() + '\n')
    common.print_json(
        {'split': args.split, 'kept': len(ids), 'of': len(in_split), 'out': args.out}, None
    )
    return 0


def _write_ids(path: str, ids: list[str], header: str) -> None:
    tables.write_ids(path, ids, [header])
    log.info('wrote %s (%d CVEs)', path, len(ids))


def cmd_select_synthetic(args: argparse.Namespace) -> int:
    """Oracle-proven rules from teacher runs -> the round's training parquet."""
    from rulegen.gen.log import read_samples

    rows: list[dict] = []
    for run in args.run:
        run_rows = read_samples(run)
        # A run that scored nothing is a failed rescore, not an empty result: it
        # would silently shrink the dataset by a whole shard.
        if not run_rows:
            raise SystemExit(f'{run}: no samples — did its rescore fail?')
        log.info('%s: %d rows', run, len(run_rows))
        rows.extend(run_rows)
    shape_by_cve = {}
    if os.path.exists(os.path.join(args.data, shapes.SHAPES)):
        shape_by_cve = {r.cve: r for r in shapes.load_table(args.data)}
    selected = synthetic.select(
        rows,
        shape_by_cve,
        per_cve=synthetic.PER_CVE if args.per_cve is None else args.per_cve,
        cost_cap=synthetic.COST_CAP if args.cost_cap is None else args.cost_cap,
    )
    tables.write_rows(selected, args.out)
    classes = {}
    if args.classes and selected:
        out_dir = os.path.dirname(args.out) or '.'
        classes = synthetic.context_classes(common.kernel(args), selected, out_dir, jobs=args.jobs)
    stem = os.path.splitext(args.out)[0]
    summary = synthetic.summary_md(rows, selected, classes, title=os.path.basename(stem))
    tables.write_text(f'{stem}.md', summary + '\n')
    common.print_json(
        {
            'rows_in': len(rows),
            'cves_accepted': len({r['cve'] for r in selected}),
            'rules': len(selected),
            'out': args.out,
        }
    )
    return 0


def cmd_export_synthetic(args: argparse.Namespace) -> int:
    """A synthetic dataset back out as <CVE>.cocci files, for the suite audit."""
    written = synthetic.export(tables.read_rows(args.dataset), args.out, per_cve=args.per_cve)
    cves = sorted({os.path.basename(p).removesuffix('.cocci') for p in written})
    if args.id_list:
        tables.write_ids(args.id_list, cves)
    log.info('wrote %d rules for %d CVEs to %s', len(written), len(cves), args.out)
    common.print_json({'rules': len(written), 'cves': len(cves), 'out': args.out}, None)
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        'clean-pool', help='unruled CVEs the teacher may run on, minus gold-function overlap'
    )
    p.add_argument('--split', default='pool')
    p.add_argument(
        '--against',
        action='append',
        default=[],
        help='splits whose functions are excluded (default: train val test)',
    )
    p.add_argument('--shards', type=int, default=4, help='interleaved id lists to also write')
    p.add_argument('--out', default='data/pool-clean.txt')
    p.set_defaults(func=cmd_clean_pool)

    p = sub.add_parser(
        'select-synthetic', help='oracle-proven rules from teacher runs -> training parquet'
    )
    p.add_argument('--run', action='append', required=True, help='teacher run dir; repeatable')
    p.add_argument('--out', default='data/synthetic/round1.parquet')
    p.add_argument('--per-cve', type=int, default=None, help='rules kept per CVE (default 4)')
    p.add_argument(
        '--cost-cap',
        type=float,
        default=None,
        help='CPU-s ceiling of one whole-tree scan (default 60; calibrate to the host)',
    )
    p.add_argument(
        '--classes',
        action=argparse.BooleanOptionalAction,
        default=True,
        help='context tier class of each kept rule',
    )
    p.add_argument('--jobs', type=int, default=8)
    p.set_defaults(func=cmd_select_synthetic)

    p = sub.add_parser(
        'export-synthetic', help='a synthetic dataset -> <CVE>.cocci files (suite audit input)'
    )
    p.add_argument('--dataset', default='data/synthetic/round1.parquet')
    p.add_argument('--out', required=True, help='directory to write the rules into')
    p.add_argument('--per-cve', type=int, default=1, help='ranks to export; >1 uses subdirs')
    p.add_argument('--id-list', default='', help='also write the CVE ids, one per line')
    p.set_defaults(func=cmd_export_synthetic)
