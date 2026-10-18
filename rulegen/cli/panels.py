"""The panel commands: fixed, seeded CVE samples for the evaluation cells."""

import argparse
import logging
import math
import os
from collections import Counter
from typing import Any

from rulegen import panel, shapes, tables, tiers
from rulegen.cli import common
from rulegen.schema import SPLIT_TEST

log = logging.getLogger('rulegen')


def cmd_sample_newrule(args: argparse.Namespace) -> int:
    """Stratified (year x subsystem x fix shape) sample of unruled >=2025 CVEs."""
    rows = shapes.load_table(args.data)
    records = common.records_by_cve(args)
    pool = [r for r in rows if r.split == args.split and records[r.cve].eligible]
    exclude = shapes.test_overlap(rows, {r.cve for r in rows if r.split == SPLIT_TEST})
    picked = panel.stratified_sample(pool, n=args.n, seed=args.seed, exclude=exclude)
    header = f'{len(picked)} CVEs from split={args.split}, seed={args.seed}, stratified by year x subsystem x shape'
    tables.write_ids(args.out, picked, [header])
    chosen = [r for r in pool if r.cve in set(picked)]
    log.info(
        'wrote %s: %d CVEs (excluded %d overlapping test functions)',
        args.out,
        len(picked),
        len(exclude),
    )
    log.info(
        '  by shape %s; by year %s',
        dict(Counter(r.shape for r in chosen)),
        dict(sorted(Counter(r.year for r in chosen).items())),
    )
    return 0


def cmd_sample_panel(args: argparse.Namespace) -> int:
    """A fixed, seeded panel of CVEs for the frontier cells (see rulegen/panel.py)."""
    classes = tiers.load_classes(args.data)
    if args.from_panel:
        picked, report, header, title = _nested_panel(args, classes)
    elif args.by == 'shape':
        picked, report, header, title = _shape_panel(args)
    else:
        picked, report, header, title = _gold_panel(args, classes)
    tables.write_ids(args.out, picked, [f'seed={args.seed}', *header])
    md_path = os.path.splitext(args.out)[0] + '.md'
    text = panel.strata_markdown(title, report)
    tables.write_text(md_path, text)
    log.info('wrote %s (%d CVEs) and %s', args.out, len(picked), md_path)
    print(text)
    return 0


Panel = tuple[list[str], list[dict[str, Any]], list[str], str]  # picked, strata, header, title


def _nested_panel(args: argparse.Namespace, classes: dict[str, str]) -> Panel:
    ids = sorted(tables.read_ids(args.from_panel))
    n = math.ceil(len(ids) / 2) if args.half else args.n
    picked = panel.nested_subset(ids, classes, n, seed=args.seed)
    report = [
        {
            'class': cls,
            'era': '',
            'available': sum(1 for c in ids if classes.get(c) == cls),
            'picked': sum(1 for c in picked if classes.get(c) == cls),
        }
        for cls in tiers.CLASSES
    ]
    header = [f'{len(picked)} of the {len(ids)} CVEs of {args.from_panel}, class-stratified']
    return picked, report, header, f'{args.out}: nested subset of {args.from_panel}'


def _shape_panel(args: argparse.Namespace) -> Panel:
    eligible = {r.cve for r in common.load_corpus(args) if r.eligible and r.split == args.split}
    if args.candidates:
        eligible &= tables.read_ids(args.candidates)
    picked, report = panel.shape_panel(
        shapes.load_table(args.data), eligible, args.n, seed=args.seed
    )
    source = f' from {args.candidates}' if args.candidates else ''
    header = [
        f'{len(picked)} of {len(eligible)} eligible {args.split} CVEs{source}, stratified by fix shape'
    ]
    return picked, report, header, f'{args.out}: {args.split} panel by fix shape'


def _gold_panel(args: argparse.Namespace, classes: dict[str, str]) -> Panel:
    from rulegen.gen.manifest import cvehound_path

    header = []
    exclude: set[str] = set()
    if args.exclude_doc_cited:
        exclude = panel.doc_cited_cves(args.cvehound or cvehound_path(common.kernel(args)))
        header.append(f'{len(exclude)} CVE ids cited in the cvehound docs excluded')
    quotas = panel.parse_quota(args.quota)
    picked, report = panel.sample_panel(
        common.load_corpus(args), classes, quotas, seed=args.seed, exclude=exclude
    )
    header.append(
        f'{len(picked)} gold CVEs (train+val+test), class quotas {args.quota}, era-stratified'
    )
    return picked, report, header, f'{args.out}: gold panel'


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        'sample-newrule', help='stratified sample of unruled CVEs for oracle-only eval'
    )
    p.add_argument('--split', default='newrule')
    p.add_argument('--n', type=int, default=200)
    p.add_argument('--seed', type=int, default=0)
    p.add_argument('--out', default='data/newrule200.txt')
    p.set_defaults(func=cmd_sample_newrule)

    p = sub.add_parser(
        'sample-panel', help='a fixed, seeded CVE panel for the frontier cells (rulegen/panel.py)'
    )
    p.add_argument('--quota', default='A=11,B=40,C=25,C2=9,D=15,E=20', help='per-class counts')
    p.add_argument('--seed', type=int, default=0)
    p.add_argument(
        '--exclude-doc-cited',
        action='store_true',
        help="drop CVEs named in cvehound's public docs, skill and templates",
    )
    p.add_argument('--cvehound', default='', help='cvehound checkout (default: beside the kernel)')
    p.add_argument('--from-panel', default='', help='draw a class-stratified subset of this panel')
    p.add_argument(
        '--n', type=int, default=25, help='subset size (with --from-panel or --by shape)'
    )
    p.add_argument('--half', action='store_true', help='with --from-panel: half of each class')
    p.add_argument('--by', default='', choices=['', 'shape'], help='shape: a fix-shape panel')
    p.add_argument('--split', default='newrule', help='with --by shape: the split to draw from')
    p.add_argument('--candidates', default='', help='with --by shape: an id list to draw from')
    p.add_argument('--out', required=True, help='data/panel-<name>.txt (+ .md strata table)')
    p.set_defaults(func=cmd_sample_panel)
