"""Expert iteration: the pool the teacher runs on, and what it keeps.

Generation is the expensive half and the oracle is the judge, so this module
holds only the two decisions around it: which unruled CVEs the teacher may see
(`clean_pool`, `shards`) and which of its proven rules become training data
(`select`). Acceptance itself is `Score.strong_valid` — the oracle raised to
suite parity — plus the audit flags the eval driver already computes and a cap
on deployment cost, so nothing degenerate or unaffordable enters the dataset.
"""

import hashlib
import os
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from rulegen import promptbuild, tiers
from rulegen.eval import driver
from rulegen.schema import CveRecord
from rulegen.shapes import UNJUDGED_SHAPES, ShapeRecord, test_overlap

# Deployment cost a synthetic rule may not exceed: one whole-tree scan, in CPU
# seconds. CPU seconds depend on the host: calibrate the cap against the gold
# replay's cost on the same host (`rulegen replay-gold --cost`).
COST_CAP = 60.0
PER_CVE = 4  # distinct rules kept per CVE; more would just re-weight one fix


def clean_pool(
    shapes: Sequence[ShapeRecord],
    split: str,
    gold_cves: set[str],
    ineligible: set[str] = frozenset(),
) -> list[str]:
    """CVE ids of `split` the teacher may generate on.

    Out: anything whose fix touches a (file, function) a gold CVE touches — the
    exclusion is global rather than test-only because the baselines evaluate
    every gold rule — plus fixes that touch no
    C source or only delete it (a retired subsystem leaves no fixed code to be
    silent on), and every CVE the metadata audit marked ineligible (rejected, no
    or several fix/introducing commits, sources that disagree, an introducing
    commit that is not an ancestor of the fix). None of that is a formality:
    without an agreed anchor the oracle cannot run the `fixes`/`fixes~` legs or
    the range sweep, and the suite rejects the rule outright.
    """
    overlap = test_overlap(list(shapes), gold_cves)
    return sorted(
        r.cve
        for r in shapes
        if r.split == split
        and r.shape not in UNJUDGED_SHAPES
        and r.cve not in overlap
        and r.cve not in gold_cves
        and r.cve not in ineligible
    )


def shards(ids: Sequence[str], k: int) -> list[list[str]]:
    """`k` interleaved slices of a sorted id list, so each finished shard is a
    representative sample of the whole pool rather than one end of it."""
    if k < 1:
        raise ValueError('k must be >= 1')
    ordered = sorted(ids)
    return [ordered[i::k] for i in range(k)]


@dataclass(frozen=True)
class Candidate:
    """One accepted rule, with what ranks it against its siblings."""

    row: dict[str, Any]
    stars: int  # starred lines: the tightest expression of the vulnerability wins
    cost: float
    round: int

    @property
    def key(self) -> tuple[int, float, int, str]:
        return (self.stars, self.cost, self.round, self.row.get('rule_sha') or '')


def star_count(rule_text: str) -> int:
    return sum(1 for line in rule_text.splitlines() if line.startswith('*'))


_DECL_RE = re.compile(
    r'^(' + '|'.join(k.replace(' ', r'\s+') for k in tiers.METAVAR_KINDS) + r')\s+(.+);\s*$'
)
_RULE_NAME_RE = re.compile(r'@[A-Za-z_]\w*')


def _canonical_lines(rule_text: str) -> list[str]:
    """Headers dropped, metavariables renamed positionally, rule names normalized.

    Positions follow first use in the pattern, not declaration order, so two
    siblings that declare `e` and `f` in opposite order still meet. The
    declarations themselves are dropped: once the names are positional the
    pattern carries everything the declarations said.
    """
    lines = [line for line in rule_text.split('\n') if not line.startswith('///')]
    kind_of: dict[str, str] = {}
    pattern: list[str] = []
    for line in lines:
        match = _DECL_RE.match(line.strip())
        if match and match.group(1) != 'typedef':
            for name in match.group(2).split(','):
                kind_of.setdefault(name.split('=')[0].strip(), match.group(1))
        else:
            pattern.append(line)
    body = '\n'.join(pattern)
    first_use = {
        name: (m.start() if (m := re.search(rf'\b{re.escape(name)}\b', body)) else len(body))
        for name in kind_of
    }
    ordered = sorted(first_use, key=lambda n: (first_use[n], n))
    for i, name in enumerate(ordered):
        body = re.sub(rf'\b{re.escape(name)}\b', f'M{i}', body)
    # The kinds, in positional order, are what the dropped declarations said;
    # without them `identifier f; expression e; f(e)` and its mirror would meet.
    kinds = ' '.join(kind_of[name] for name in ordered)
    return [f'kinds: {kinds}', *_RULE_NAME_RE.sub('@R', body).split('\n')]


def canonical_form(rule_text: str) -> str:
    """Two rules with the same form say the same thing.

    Exact-text dedupe misses a sibling that only renamed `e` to `E`; this is the
    dedupe key instead. It is deliberately conservative — it never merges rules
    whose pattern lines differ — so what survives is structurally distinct.
    """
    return re.sub(r'\s+', ' ', '\n'.join(_canonical_lines(rule_text))).strip()


def report_lines(rule_text: str) -> tuple[str, ...]:
    """The starred lines in canonical form: what the rule would actually report.

    Siblings for one CVE often star the same statement inside different context;
    this is the key that says so, metavariable spelling aside.
    """
    return tuple(
        sorted(
            re.sub(r'\s+', ' ', line[1:]).strip()
            for line in _canonical_lines(rule_text)
            if line.startswith('*')
        )
    )


_ANCHOR_RE = re.compile(r'^///\s*(Fixes|Detect-To):\s*\S', re.MULTILINE)


def is_anchored(rule_text: str) -> bool:
    """Does the rule name an introducing commit (`Fixes:`) or a `Detect-To:` bound?

    cvehound's suite requires one (test_00_metadata: 'no "Fixes:" or "Detect-To:"
    tag'), and so does the oracle's evidence: without it the `fixes`/`fixes~`
    legs and the whole T5 range sweep never run, so the rule is checked at the
    fix and at backports but never at any state that introduced the bug.
    """
    return bool(_ANCHOR_RE.search(rule_text))


def is_accepted(row: dict[str, Any], cost_cap: float = COST_CAP) -> bool:
    """Proven, anchored, non-degenerate and affordable: the gate for training data."""
    if not row.get('s_strong_valid') or not row.get('rule_text'):
        return False
    if not is_anchored(row['rule_text']):
        return False
    if any(driver.degenerate_flags(row).values()):
        return False
    cost = row.get('s_cost_cpu_seconds')
    # An unmeasured cost is not a licence to skip the cap.
    return cost is not None and cost <= cost_cap


def _out_row(row: dict[str, Any], shape: ShapeRecord | None) -> dict[str, Any]:
    """One dataset row: the rule exactly as the oracle scored it.

    `rule_sha` names those bytes — the file under `runs/oracle/rules/` — and
    export() ships them unchanged, so the suite audits what was judged.
    """
    rule_text = row['rule_text']
    return {
        'cve': row['cve'],
        # The SFT target: the model's own rule in contract form, before the harness
        # completed Files: with names a P-B/P-M prompt never shows (it completes
        # them again at inference).
        'rule_body': row.get('rule_body'),
        # What ships as a rule file: exactly what the oracle scored.
        'rule_text': rule_text,
        'rule_sha': row.get('rule_sha', ''),
        'files': ' '.join(promptbuild.rule_files(rule_text)),
        'stars': star_count(rule_text),
        # Siblings for one CVE often re-express the same report with different
        # context; this key lets SFT sample per report rather than per phrasing.
        'report_key': hashlib.sha256('\n'.join(report_lines(rule_text)).encode()).hexdigest()[:16],
        # Provenance: which run, which chain, how many repair rounds it took.
        'run_id': row.get('run_id', ''),
        'attempt_id': row.get('attempt_id', ''),
        'round': row.get('round', 0),
        'policy': row.get('policy', ''),
        'model_id': row.get('model_id', ''),
        'transform_applied': bool(row.get('transform_applied')),
        'tokens_cum': row.get('tokens_cum', 0),
        # Verdicts worth carrying into training-set analysis.
        'reward': row.get('s_reward'),
        'cost_cpu_seconds': row.get('s_cost_cpu_seconds'),
        'cost_prefilter_files': row.get('s_cost_prefilter_files'),
        't5_mode': row.get('s_t5_mode', ''),
        't5_points': row.get('s_t5_points'),
        't6_trees': row.get('s_t6_trees'),
        # Stratification keys, from data/shapes.parquet.
        'shape': shape.shape if shape else '',
        'year': shape.year if shape else 0,
        'subsystem': shape.subsystem if shape else '',
    }


def select(
    rows: Iterable[dict[str, Any]],
    shapes: dict[str, ShapeRecord] | None = None,
    per_cve: int = PER_CVE,
    cost_cap: float = COST_CAP,
) -> list[dict[str, Any]]:
    """The dataset rows: accepted, deduped by canonical form, best `per_cve` per CVE."""
    by_cve: dict[str, dict[str, Candidate]] = {}
    for row in rows:
        if not is_accepted(row, cost_cap):
            continue
        text = row['rule_text']
        candidate = Candidate(
            row=row,
            stars=star_count(text),
            cost=float(row['s_cost_cpu_seconds']),
            round=int(row.get('round') or 0),
        )
        siblings = by_cve.setdefault(row['cve'], {})
        # The same rule can be reached by several chains, and by several spellings
        # of its metavariables: keep the cheapest path to each canonical form.
        form = canonical_form(text)
        prior = siblings.get(form)
        if prior is None or candidate.key < prior.key:
            siblings[form] = candidate
    out: list[dict[str, Any]] = []
    for cve in sorted(by_cve):
        best = sorted(by_cve[cve].values(), key=lambda c: c.key)[:per_cve]
        out.extend(_out_row(c.row, (shapes or {}).get(cve)) for c in best)
    return out


def export(rows: list[dict[str, Any]], out_dir: str, per_cve: int = 1) -> list[str]:
    """Write the dataset back out as `<CVE>.cocci` files — a usable rule set.

    CVEhound addresses a rule by its CVE id, so one directory holds one rule per
    CVE: `per_cve=1` exports the best, and the runners-up need their own pass
    (`rank=2`, ...). `select()` already emits a CVE's rules best-first.

    """
    os.makedirs(out_dir, exist_ok=True)
    seen: dict[str, int] = {}
    written = []
    for row in rows:
        rank = seen.get(row['cve'], 0)
        seen[row['cve']] = rank + 1
        if rank >= per_cve:
            continue
        # Ranks past the first would collide on the file name, so they get their own
        # subdirectory: <out>/2/<CVE>.cocci is that CVE's runner-up.
        directory = out_dir if rank == 0 else os.path.join(out_dir, str(rank + 1))
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f'{row["cve"]}.cocci')
        with open(path, 'w') as fh:
            fh.write(row['rule_text'])
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# Summary


def _counts(rows: Iterable[dict[str, Any]], key: str) -> Counter:
    return Counter(row.get(key) for row in rows)


def counts_table(title: str, header: str, counts: dict[Any, int], unit: str = 'rules') -> list[str]:
    """A markdown count table, as lines: one row per key, keys in text order."""
    lines = [f'### {title}', '', f'| {header} | {unit} |', '| --- | ---: |']
    lines += [f'| {key} | {count} |' for key, count in sorted(counts.items(), key=str)]
    return [*lines, '']


def summary_md(
    all_rows: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    classes: dict[str, str] | None = None,
    title: str = 'Synthetic set',
) -> str:
    """The yield funnel and the mix, as the markdown that lands next to the parquet."""
    attempted = {row['cve'] for row in all_rows}
    valid = {row['cve'] for row in all_rows if row.get('s_valid')}
    strong = {row['cve'] for row in all_rows if row.get('s_strong_valid')}
    accepted = {row['cve'] for row in selected}
    rounds = _counts(selected, 'round')
    pct = f'{100 * len(accepted) / len(attempted):.1f}%' if attempted else 'n/a'
    lines = [
        f'# {title}',
        '',
        '### Yield',
        '',
        '| stage | CVEs | rows |',
        '| --- | ---: | ---: |',
        f'| attempted | {len(attempted)} | {len(all_rows)} |',
        f'| >=1 valid rule | {len(valid)} | {sum(1 for r in all_rows if r.get("s_valid"))} |',
        f'| >=1 strong rule | {len(strong)} | '
        f'{sum(1 for r in all_rows if r.get("s_strong_valid"))} |',
        f'| accepted (kept) | {len(accepted)} | {len(selected)} |',
        '',
        f'Accepted CVEs: {pct} of attempted; {len(selected)} rules.',
        '',
    ]
    reports = len({(r['cve'], r.get('report_key')) for r in selected})
    lines += [
        f'Distinct reports (rules that star different lines): {reports} — the rest are '
        'siblings re-expressing a report with different context; sample one per CVE per '
        'epoch in SFT.',
        '',
    ]
    lines += counts_table('Repair rounds to the kept rule', 'round', rounds)
    lines += counts_table('By fix shape', 'shape', _counts(selected, 'shape'))
    lines += counts_table('By year', 'year', _counts(selected, 'year'))
    lines += counts_table('By subsystem', 'subsystem', _counts(selected, 'subsystem'))
    if classes:
        counts = Counter(classes.get(cve, '?') for cve in sorted(accepted))
        lines += counts_table('Context class of the kept rules', 'class', counts)
    return '\n'.join(lines)


def _header_value(rule_text: str, key: str) -> str | None:
    for line in rule_text.splitlines():
        if line.startswith(f'/// {key}:'):
            return line.split(':', 1)[1].strip()
        if not line.startswith('///'):
            break
    return None


def context_classes(
    kernel: str, selected: list[dict[str, Any]], work_dir: str, jobs: int = 8
) -> dict[str, str]:
    """Context tier class per CVE, from the best kept rule: the set's context mix.

    Reuses the gold-corpus classifier: it wants rules on disk with a Fix: header,
    which is what the oracle scored, so the rules are written back out here.
    """
    rules_dir = os.path.join(work_dir, 'rules')
    os.makedirs(rules_dir, exist_ok=True)
    records = []
    seen: set[str] = set()
    for row in selected:  # select() emits the best rule of a CVE first
        if row['cve'] in seen:
            continue
        seen.add(row['cve'])
        path = os.path.join(rules_dir, f'{row["cve"]}.cocci')
        with open(path, 'w') as fh:
            fh.write(row['rule_text'])
        records.append(
            CveRecord(
                cve=row['cve'],
                fix=_header_value(row['rule_text'], 'Fix'),
                rule_path=path,
                files_gold=row['files'].split(),
            )
        )
    return {rec.cve: rec.cls for rec in tiers.classify_corpus(kernel, records, jobs=jobs)}
