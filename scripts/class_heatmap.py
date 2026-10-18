#!/usr/bin/env python3
"""Per-context-class heatmaps, assembled from the per-run report tables.

    scripts/class_heatmap.py --policy P-M --reading canon
    scripts/class_heatmap.py --model qwen3.8-27b        # policy x class
    scripts/class_heatmap.py --policy P-M --out reports/sample-class-heatmap

`rulegen report` writes one per-class table per run, which answers "how did this
cell do per class" but not "where does every model stop". This assembles that
view from the by-context-class CSVs the cells already wrote; it computes nothing
the oracle did not.

Two heatmaps, from the same files:
  --policy   model x class, one policy held fixed
  --model    policy x class, one model held fixed (does richer input buy anything
             on the classes that are actually hard)

Denominators travel with the rates. A held-out split has a handful of CVEs per
class, so a val or test heatmap says so; the rows pooled over all three splits
carry a per-class claim. A cell whose denominator is below --min-cves is printed
in parentheses rather than silently read as a rate.
"""

import argparse
import csv
import os
import re

CLASSES = ('A', 'B', 'C', 'C2', 'D', 'E')  # rulegen.tiers.CLASSES; this script runs without rulegen
READINGS = ('strict', 'canon', 'full')


def reading_of(filename: str) -> str:
    stem = filename[len('by-context-class-s-valid-') : -len('.csv')]
    for suffix in ('-canon', '-full'):
        if stem.endswith(suffix):
            return suffix.lstrip('-')
    return 'strict'


def cell_classes(report_dir: str, reading: str) -> dict[str, tuple[float | None, int]]:
    """{class: (valid@n, CVEs)} for one cell at one reading."""
    out: dict[str, tuple[float | None, int]] = {}
    if not os.path.isdir(report_dir):
        return out
    for name in sorted(os.listdir(report_dir)):
        if not name.startswith('by-context-class-') or not name.endswith('.csv'):
            continue
        if reading_of(name) != reading:
            continue
        with open(os.path.join(report_dir, name)) as fh:
            for row in csv.DictReader(fh):
                try:
                    rate = float(row['valid@n'])
                except (TypeError, ValueError, KeyError):
                    rate = None
                out[row['class']] = (rate, int(float(row.get('CVEs') or 0)))
    return out


def merge_cells(dirs: list[str], reading: str) -> dict[str, tuple[float | None, int]]:
    """Pool several cells (the splits of one model x policy) into one row.

    CVE-weighted, because the splits are very different sizes: train is many
    times larger than test, and an unweighted mean would let the smallest split
    speak loudest.
    """
    acc: dict[str, list[float]] = {c: [0.0, 0.0] for c in CLASSES}
    for d in dirs:
        for cls, (rate, n) in cell_classes(d, reading).items():
            if cls in acc and rate is not None and n:
                acc[cls][0] += rate * n
                acc[cls][1] += n
    return {c: ((acc[c][0] / acc[c][1]) if acc[c][1] else None, int(acc[c][1])) for c in CLASSES}


def discover(reports: str, family: str) -> list[tuple[str, str, str, str]]:
    """(cell, model, policy, split) for every report directory of a family."""
    pat = re.compile(rf'^{re.escape(family)}-(.+)-(pb|pm|ph)-(train|val|test)$')
    found = []
    for name in sorted(os.listdir(reports)):
        m = pat.match(name)
        if m:
            found.append(
                (
                    name,
                    m.group(1),
                    {'pb': 'P-B', 'pm': 'P-M', 'ph': 'P-H'}[m.group(2)],
                    m.group(3),
                )
            )
    return found


def render(rows: list[tuple[str, dict]], title: str, min_cves: int) -> str:
    out = [
        f'### {title}',
        '',
        '| ' + ' | '.join(['', *CLASSES]) + ' |',
        '| ' + ' | '.join(['---'] * (len(CLASSES) + 1)) + ' |',
    ]
    for label, cells in rows:
        vals = []
        for c in CLASSES:
            rate, n = cells.get(c, (None, 0))
            if rate is None or not n:
                vals.append('—')
            elif n < min_cves:
                vals.append(f'({rate:.2f})')  # too few CVEs to read as a rate
            else:
                vals.append(f'{rate:.2f}')
        out.append('| ' + ' | '.join([label, *vals]) + ' |')
    counts = rows[0][1] if rows else {}
    out += [
        '',
        '| CVEs | ' + ' | '.join(str(counts.get(c, (None, 0))[1]) for c in CLASSES) + ' |',
        '| --- | ' + ' | '.join(['---'] * len(CLASSES)) + ' |',
        '',
        f'_Rates in parentheses rest on fewer than {min_cves} CVEs and are shown for '
        'completeness, not as measurements._',
    ]
    sizes = {tuple(cells.get(c, (None, 0))[1] for c in CLASSES) for _label, cells in rows}
    if len(sizes) > 1:
        out.append(
            '_The rows pool different CVE sets (a model without every split); '
            'the per-row counts are in the CSV._'
        )
    return '\n'.join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--reports', default='reports')
    ap.add_argument('--family', default='sample', help='run-id prefix of the cells')
    ap.add_argument('--reading', default='canon', choices=READINGS)
    ap.add_argument('--policy', default='', help='model x class at this policy')
    ap.add_argument('--model', default='', help='policy x class for this model')
    ap.add_argument('--splits', default='train,val,test', help='which splits to pool')
    ap.add_argument('--min-cves', type=int, default=5)
    ap.add_argument('--out', default='', help='directory for the markdown + CSV')
    args = ap.parse_args()

    want = set(args.splits.split(','))
    found = [f for f in discover(args.reports, args.family) if f[3] in want]
    if not found:
        print(f'no {args.family}-* reports under {args.reports}')
        return 1

    if args.model:
        keys = sorted({p for _, m, p, _ in found if m == args.model})

        def group(key):  # one row per policy, the model held fixed
            return [(n, m, p, s) for n, m, p, s in found if m == args.model and p == key]

        title = f'{args.model} — policy x context class ({args.reading} valid@n)'
    else:
        policy = args.policy or 'P-M'
        keys = sorted({m for _, m, p, _ in found if p == policy})

        def group(key):  # one row per model, the policy held fixed
            return [(n, m, p, s) for n, m, p, s in found if m == key and p == policy]

        title = f'{policy} — model x context class ({args.reading} valid@n)'

    rows = []
    for key in keys:
        members = group(key)
        rows.append(
            (
                key,
                merge_cells([os.path.join(args.reports, n) for n, *_ in members], args.reading),
            )
        )
    text = render(rows, title, args.min_cves)
    print(text)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, 'class-heatmap.md'), 'w') as fh:
            fh.write(text + '\n')
        with open(os.path.join(args.out, 'class-heatmap.csv'), 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['row', *CLASSES, *[f'{c}_cves' for c in CLASSES]])
            for label, cells in rows:
                w.writerow(
                    [
                        label,
                        *[cells.get(c, (None, 0))[0] for c in CLASSES],
                        *[cells.get(c, (None, 0))[1] for c in CLASSES],
                    ]
                )
        print(f'\nwrote {args.out}/class-heatmap.{{md,csv}}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
