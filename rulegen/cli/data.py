"""The data commands: metadata, corpus, shapes, tiers, model inputs, prompt coverage."""

import argparse
import contextlib
import dataclasses
import logging
import os
from collections import Counter
from typing import Any

from rulegen import corpus, extract, sources, tables, tiers
from rulegen.cli import common
from rulegen.schema import CveRecord, ExampleRecord

log = logging.getLogger('rulegen')


def cmd_build_cvemeta(args: argparse.Namespace) -> int:
    common.build_cvemeta(args, args.vulns, args.cip)
    return 0


def cmd_audit_metadata(args: argparse.Namespace) -> int:
    """The metadata audit: disagreements, multi-commit and rejected CVEs, backport coverage."""
    metas = common.load_cvemeta(args)
    splits = {rec.cve: rec.split for rec in common.load_corpus(args)}
    tables.write_text(args.report, '# Metadata audit\n\n' + sources.audit_markdown(metas, splits))
    rows = sources.audit_rows(metas, splits)
    out = os.path.join(args.data, 'cvemeta-audit.parquet')
    if rows:
        tables.write_rows(rows, out)
    log.info('wrote %s and %s (%d issue rows)', args.report, out, len(rows))
    return 0


def cmd_build_corpus(args: argparse.Namespace) -> int:
    records = common.build_corpus(args)
    log.info('wrote %s (%d CVEs)', os.path.join(args.data, corpus.CORPUS), len(records))
    for split, num in sorted(Counter(rec.split for rec in records).items()):
        log.info('  %-8s %d', split, num)
    return 0


def cmd_shape_corpus(args: argparse.Namespace) -> int:
    """Fix shape, subsystem and touched functions per CVE -> data/shapes.parquet.

    The stratification keys for the new-rule sample and the overlap key that
    keeps pool CVEs away from test CVEs' functions. Cheap: two git show per CVE.
    """
    from rulegen import shapes

    splits = set(args.split)
    records = [rec for rec in common.load_corpus(args) if rec.split in splits and rec.fix]
    log.info('classifying %d CVEs in %s (jobs=%d)', len(records), sorted(splits), args.jobs)
    rows = shapes.classify_shapes(common.kernel(args), records, jobs=args.jobs)
    out = os.path.join(args.data, shapes.SHAPES)
    if os.path.exists(out):  # merge: keep other splits' rows
        keep = [r for r in shapes.load_shapes(out) if r.split not in splits]
        rows = sorted(keep + rows, key=lambda r: r.cve)
    shapes.save_shapes(rows, out)
    counts = dict(Counter(r.shape for r in rows if r.split in splits))
    log.info('wrote %s (%d rows); shapes in %s: %s', out, len(rows), sorted(splits), counts)
    return 0


def cmd_tier_corpus(args: argparse.Namespace) -> int:
    """Which git context window at Fix: already contains every literal token of the rule.

    The stratification input for input-policy design, and the before/after
    scoreboard for rule-simplification passes over the corpus.
    """
    rows = tiers.classify_corpus(common.kernel(args), common.load_corpus(args), jobs=args.jobs)
    out = os.path.join(args.data, tiers.TIERS)
    tiers.save_tiers(rows, out)

    counts = tiers.summarize(rows)
    total = len(rows) or 1
    log.info('wrote %s (%d gold rules)', out, len(rows))
    cumulative = 0
    for tier in tiers.CLASSES:
        cumulative += counts[tier]
        log.info(
            '  %-3s %4d  %5.1f%%  cum %5.1f%%',
            tier,
            counts[tier],
            100 * counts[tier] / total,
            100 * cumulative / total,
        )
    unresolved = [row.cve for row in rows if row.unresolved]
    if unresolved:
        log.info('  unresolved Fix: %s', ' '.join(unresolved))
    if args.report:
        tables.write_json(args.report, [dataclasses.asdict(row) for row in rows])
        log.info('report: %s', args.report)
    return 0


def _extract_one(payload: tuple[str, CveRecord]) -> tuple[str, object]:
    """(cve, ExampleRecord) on success, (cve, error message) on failure.

    Extraction is per-CVE independent and git-subprocess-bound (the survival
    map alone is ~150 `git grep` invocations), so a process pool is the whole
    speedup — see cmd_build_dataset's --jobs.
    """
    kernel, rec = payload
    try:
        return rec.cve, extract.build_example(kernel, rec)
    except (ValueError, RuntimeError) as err:
        return rec.cve, str(err)


def cmd_build_dataset(args: argparse.Namespace) -> int:
    import multiprocessing

    records = [rec for rec in common.load_corpus(args) if rec.split == args.split]
    unanchored = [rec.cve for rec in records if not rec.fixes]
    if unanchored:
        # build_example() refuses these; say so once here rather than per CVE.
        log.warning(
            'skipping %d %s CVEs with no introducing commit (e.g. %s): no anchor means no '
            'range context in the prompt, no fixes/T5 legs in the oracle, and a rule the '
            'suite rejects',
            len(unanchored),
            args.split,
            ', '.join(unanchored[:3]),
        )
        records = [rec for rec in records if rec.fixes]
    if args.subset:
        wanted = tables.read_ids(args.subset)
        records = [rec for rec in records if rec.cve in wanted]
    if args.limit:
        records = records[: args.limit]
    log.info('extracting %d examples for split=%s (jobs=%d)', len(records), args.split, args.jobs)

    payloads = [(common.kernel(args), rec) for rec in records]
    examples: list[ExampleRecord] = []
    failures = 0
    with contextlib.ExitStack() as stack:
        if args.jobs <= 1:
            results = map(_extract_one, payloads)
        else:
            pool = stack.enter_context(multiprocessing.get_context('spawn').Pool(args.jobs))
            results = pool.imap_unordered(_extract_one, payloads)
        for pos, (cve, result) in enumerate(results, 1):
            if isinstance(result, ExampleRecord):
                examples.append(result)
            else:
                failures += 1
                log.debug('%s: skipped (%s)', cve, result)
            if pos % 50 == 0:
                log.info('  %d/%d (%d skipped)', pos, len(records), failures)

    examples.sort(key=lambda ex: ex.cve)
    out = extract.examples_path(args.data, args.name or args.split)
    extract.save_examples(examples, out)
    log.info('wrote %s (%d examples, %d skipped)', out, len(examples), failures)
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """What fraction of a gold rule's literal tokens the built prompt already carries.

    The upper bound on what any model could write from a given input policy: a
    token the prompt never mentions has to be invented or retrieved. Uses the same
    token definition and the same word-boundary rule as the tier measurement, so
    the two are directly comparable -- P-B coverage should track the A+B share.

    Needs no kernel and no oracle; everything comes off disk.
    """
    from rulegen import promptbuild

    records = common.records_by_cve(args)
    examples = extract.load_examples(extract.examples_path(args.data, args.split))
    policies = args.policy or list(promptbuild.POLICIES)
    rows = _coverage_rows(examples, records, policies, args.budget_tokens)

    log.info(
        'coverage over %d %s rules (budget %d tokens)', len(rows), args.split, args.budget_tokens
    )
    log.info('  %-7s %14s %16s', 'policy', 'fully covered', 'mean coverage')
    for name in policies:
        full = sum(1 for r in rows if not r[name]['missing'])
        mean = sum(r[name]['fraction'] for r in rows) / (len(rows) or 1)
        log.info(
            '  %-7s %8d %4.0f%% %15.0f%%', name, full, 100 * full / (len(rows) or 1), 100 * mean
        )
    if 'P-B' in policies:
        _tier_cross_check(rows, tiers.load_classes(args.data))
    if args.report:
        tables.write_json(args.report, rows)
        log.info('report: %s', args.report)
    return 0


def _coverage_rows(
    examples: list[ExampleRecord],
    records: dict[str, CveRecord],
    policies: list[str],
    budget: int,
) -> list[dict[str, Any]]:
    """Per gold rule: its literal tokens, and how many each policy's prompt carries."""
    from rulegen import promptbuild

    rows: list[dict[str, Any]] = []
    for example in examples:
        rec = records.get(example.cve)
        if not rec or not rec.cocci_rule:
            continue
        with open(rec.rule_path, errors='replace') as fh:
            tokens, _ = tiers.literal_tokens(fh.read())
        if not tokens:
            continue
        row: dict[str, Any] = {'cve': example.cve, 'ntok': len(tokens)}
        for name in policies:
            prompt = promptbuild.build_prompt(example, name, budget_tokens=budget)
            missing = tiers.absent_tokens(tokens, prompt.text)
            row[name] = {
                'covered': len(tokens) - len(missing),
                'fraction': (len(tokens) - len(missing)) / len(tokens),
                'missing': missing,
            }
        rows.append(row)
    return rows


def _tier_cross_check(rows: list[dict[str, Any]], classes: dict[str, str]) -> None:
    """A rule whose tier is A or B has every literal token inside the -U3 diff,
    which is exactly what P-B puts in the prompt. The two numbers are measured
    independently and should agree; a gap means the prompt carries tokens the
    diff does not (candidate file paths, the subject line) or drops some (the
    budget truncated the diff)."""
    seen = [r for r in rows if r['cve'] in classes]
    if not seen:
        return
    ab = sum(1 for r in seen if classes[r['cve']] in ('A', 'B'))
    pb = sum(1 for r in seen if not r['P-B']['missing'])
    log.info(
        '  cross-check: tier A+B %d/%d (%.0f%%) vs P-B fully covered %d/%d (%.0f%%)',
        ab,
        len(seen),
        100 * ab / len(seen),
        pb,
        len(seen),
        100 * pb / len(seen),
    )


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        'build-cvemeta', help='vulns.git + CIP + rule headers -> data/cvemeta.parquet'
    )
    p.add_argument(
        '--vulns', default=None, help='vulns.git clone (default: ~/.cache/cvehound/kernel-vulns)'
    )
    p.add_argument(
        '--cip',
        default=None,
        help='CIP kernel-sec clone (default: ~/.cache/cvehound/cip-kernel-sec)',
    )
    p.set_defaults(func=cmd_build_cvemeta)

    p = sub.add_parser(
        'audit-metadata', help='source disagreements, multi-commit/rejected CVEs, backport coverage'
    )
    p.add_argument('--report', default='reports/metadata-audit.md')
    p.set_defaults(func=cmd_audit_metadata)

    p = sub.add_parser('build-corpus', help='every CVE with its split -> data/cves.parquet')
    p.set_defaults(func=cmd_build_corpus)

    p = sub.add_parser('shape-corpus', help='fix shape / subsystem / functions per CVE')
    p.add_argument(
        '--split', action='append', default=[], help='repeatable; e.g. newrule pool test'
    )
    p.add_argument('--jobs', type=int, default=8)
    p.set_defaults(func=cmd_shape_corpus)

    p = sub.add_parser(
        'tier-corpus', help="each gold rule's minimal context tier -> data/tiers.parquet"
    )
    p.add_argument('--jobs', type=int, default=8)
    p.add_argument('--report', default='', help='also write the per-rule rows as JSON')
    p.set_defaults(func=cmd_tier_corpus)

    p = sub.add_parser(
        'build-dataset', help='model inputs for a split -> data/examples/<split>.parquet'
    )
    p.add_argument('--split', default='train')
    p.add_argument('--subset', default='', help='file of CVE ids to keep (one per line)')
    p.add_argument('--name', default='', help='output name (default: the split)')
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--jobs', type=int, default=1)
    p.set_defaults(func=cmd_build_dataset)

    p = sub.add_parser('coverage', help='how much of each gold rule a prompt already carries')
    p.add_argument('--split', default='train')
    p.add_argument('--policy', action='append', default=[], help='repeatable; default all')
    p.add_argument('--budget-tokens', type=int, default=8192)
    p.add_argument('--report', default='')
    p.set_defaults(func=cmd_coverage)
