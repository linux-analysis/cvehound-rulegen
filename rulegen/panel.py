"""Fixed evaluation panels for the frontier baselines.

A frontier cell cannot afford the whole gold corpus, so it runs on a panel
drawn once, with a seed, and written under `data/`: class quotas with the
hard context classes oversampled, era-stratified inside each class so no
panel is secretly the easy recent slice, and every CVE whose gold rule
appears in cvehound's public documentation left out -- a worked example in
`docs/WRITING_RULES.md` is training data for any model that has read GitHub. The local anchor runs on the same panel, so
comparisons are paired per CVE.
"""

import datetime as dt
import glob
import os
import random
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

from rulegen.schema import CVE_ID_RE, GOLD_SPLITS, CveRecord
from rulegen.shapes import UNJUDGED_SHAPES, ShapeRecord
from rulegen.tiers import CLASSES

# Eras: the pre-2019 rules are the hard, hand-crafted ones; 2023+ is the
# self-contained recent slice a temporal val/test split overweights.
ERAS: tuple[tuple[str, int, int], ...] = (
    ('<=2018', 0, 2018),
    ('2019-2020', 2019, 2020),
    ('2021-2022', 2021, 2022),
    ('2023+', 2023, 9999),
)
# The public files of the cvehound checkout that quote or discuss rules.
DOC_GLOBS = (
    'docs/*.md',
    'AGENTS.md',
    'CLAUDE.md',
    'README.md',
    'contrib/*',
    '.agents/skills/*/SKILL.md',
    '.agents/skills/*/scripts/*',
)


def year_of(fix_date: int) -> int:
    """The calendar year of a corpus fix_date (epoch seconds, as corpus.py stores them)."""
    if not fix_date:
        return 0
    return dt.datetime.fromtimestamp(fix_date, tz=dt.UTC).year


def era_of(year: int) -> str:
    for name, lo, hi in ERAS:
        if lo <= year <= hi:
            return name
    return ERAS[0][0]


def parse_quota(text: str) -> dict[str, int]:
    """`A=11,B=40,...` -> {'A': 11, 'B': 40, ...}; every class must be a known one."""
    quotas: dict[str, int] = {}
    for item in filter(None, (part.strip() for part in text.split(','))):
        cls, _, count = item.partition('=')
        if cls not in CLASSES or not count.isdigit():
            raise ValueError(
                f'bad quota {item!r}; expected <class>=<count> with class in {CLASSES}'
            )
        quotas[cls] = int(count)
    return quotas


def largest_remainder(sizes: dict[Any, int], n: int, keys: Sequence[Any]) -> dict[Any, int]:
    """Per-stratum quotas summing to at most `n`: proportional to the sizes, at
    least one each, the leftover to the largest remainders. Ties go to the
    earlier key, so the order of `keys` is part of the answer."""
    total = sum(sizes.values())
    quotas = {k: max(1, int(n * sizes[k] / total)) for k in keys}
    while sum(quotas.values()) > n:  # too many singleton strata: trim the largest quotas
        biggest = max(keys, key=lambda k: (quotas[k], -sizes[k]))
        if quotas[biggest] <= 1:
            break
        quotas[biggest] -= 1
    remainders = sorted(
        keys, key=lambda k: (n * sizes[k] / total - quotas[k], sizes[k]), reverse=True
    )
    for key in remainders:
        if sum(quotas.values()) >= n:
            break
        if quotas[key] < sizes[key]:
            quotas[key] += 1
    return quotas


def _take(strata: dict[Any, list[str]], n: int, keys: Sequence[Any]) -> list[str]:
    """The head of each (already shuffled) stratum, by largest-remainder quota, sorted."""
    quotas = largest_remainder({k: len(strata[k]) for k in keys}, n, keys)
    picked = [cve for key in keys for cve in strata[key][: quotas[key]]]
    return sorted(picked[:n])


def allocate(strata: dict[Any, list[str]], n: int, rng: random.Random) -> list[str]:
    """Largest-remainder allocation over already-populated strata, floor one each.

    `strata` maps a key to the ids in it; each list is shuffled with `rng`
    (after sorting, so the seed is the whole story). Returns the picked ids,
    sorted. When the strata hold no more than `n` ids, all of them.
    """
    if sum(len(v) for v in strata.values()) <= n:
        return sorted(cve for v in strata.values() for cve in v)
    keys = sorted(strata, key=str)
    for key in keys:
        strata[key].sort()
        rng.shuffle(strata[key])
    return _take(strata, n, keys)


def stratified_sample(
    shapes: list[ShapeRecord], n: int = 200, seed: int = 0, exclude: set[str] = frozenset()
) -> list[str]:
    """Proportional allocation over (year, subsystem, shape) strata, at least one
    per non-empty stratum, deterministic under `seed`; CVEs no rule can be judged
    on (UNJUDGED_SHAPES) or listed in `exclude` are never sampled."""
    pool = [r for r in shapes if r.shape not in UNJUDGED_SHAPES and r.cve not in exclude]
    if len(pool) <= n:
        return sorted(r.cve for r in pool)
    strata: dict[tuple[int, str, str], list[str]] = {}
    for r in pool:
        strata.setdefault((r.year, r.subsystem, r.shape), []).append(r.cve)
    # Shuffled in first-seen order, unlike allocate(): the seed's picks are what
    # the published new-rule lists were drawn with.
    rng = random.Random(seed)
    for cves in strata.values():
        cves.sort()
        rng.shuffle(cves)
    return _take(strata, n, sorted(strata))


def doc_cited_cves(cvehound_repo: str) -> set[str]:
    """Every CVE id named in cvehound's public docs, skill and templates."""
    cited: set[str] = set()
    for pattern in DOC_GLOBS:
        for path in glob.glob(os.path.join(cvehound_repo, pattern)):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, errors='replace') as fh:
                    cited.update(CVE_ID_RE.findall(fh.read()))
            except OSError:
                continue
    return cited


def gold_pool(
    records: Iterable[CveRecord], classes: dict[str, str], exclude: set[str] = frozenset()
) -> dict[str, list[CveRecord]]:
    """Eligible gold CVEs per context class, minus the exclusions."""
    pool: dict[str, list[CveRecord]] = {cls: [] for cls in CLASSES}
    for rec in records:
        if rec.split not in GOLD_SPLITS or not rec.eligible or rec.cve in exclude:
            continue
        cls = classes.get(rec.cve)
        if cls in pool:
            pool[cls].append(rec)
    return pool


def sample_panel(
    records: Iterable[CveRecord],
    classes: dict[str, str],
    quotas: dict[str, int],
    seed: int = 0,
    exclude: set[str] = frozenset(),
) -> tuple[list[str], list[dict[str, Any]]]:
    """Class quotas, era-stratified inside each class. Returns (ids, strata rows)."""
    pool = gold_pool(records, classes, exclude)
    rng = random.Random(seed)
    picked: list[str] = []
    report: list[dict[str, Any]] = []
    for cls in CLASSES:
        quota = quotas.get(cls, 0)
        if not quota:
            continue
        strata: dict[str, list[str]] = {}
        for rec in pool[cls]:
            strata.setdefault(era_of(year_of(rec.fix_date)), []).append(rec.cve)
        chosen = allocate(strata, quota, rng)
        chosen_set = set(chosen)
        for era, _lo, _hi in ERAS:
            available = strata.get(era, [])
            report.append(
                {
                    'class': cls,
                    'era': era,
                    'available': len(available),
                    'picked': sum(1 for cve in available if cve in chosen_set),
                }
            )
        picked.extend(chosen)
    return sorted(picked), report


def nested_subset(ids: Sequence[str], classes: dict[str, str], n: int, seed: int = 1) -> list[str]:
    """A class-stratified subset of a panel (the half panel, a smaller one for costlier arms)."""
    strata: dict[str, list[str]] = {}
    for cve in ids:
        strata.setdefault(classes.get(cve, 'E'), []).append(cve)
    return allocate(strata, n, random.Random(seed))


def shape_panel(
    shapes: Iterable[Any], candidates: set[str], n: int, seed: int = 0
) -> tuple[list[str], list[dict[str, Any]]]:
    """A fix-shape-stratified subset of `candidates` (the new-rule panel)."""
    strata: dict[str, list[str]] = {}
    for rec in shapes:
        if rec.cve in candidates and rec.shape not in UNJUDGED_SHAPES:
            strata.setdefault(rec.shape, []).append(rec.cve)
    picked = allocate(strata, n, random.Random(seed))
    picked_set = set(picked)
    report = [
        {
            'class': shape,
            'era': '',
            'available': len(strata[shape]),
            'picked': sum(1 for cve in strata[shape] if cve in picked_set),
        }
        for shape in sorted(strata)
    ]
    return picked, report


def strata_markdown(title: str, report: Sequence[dict[str, Any]]) -> str:
    lines = [
        f'# {title}',
        '',
        '| class | era | available | picked |',
        '| --- | --- | ---: | ---: |',
    ]
    for row in report:
        lines.append(f'| {row["class"]} | {row["era"]} | {row["available"]} | {row["picked"]} |')
    by_class: Counter[str] = Counter()
    for row in report:
        by_class[row['class']] += row['picked']
    lines += ['', 'Picked per class: ' + ', '.join(f'{k} {v}' for k, v in by_class.items()), '']
    return '\n'.join(lines)
