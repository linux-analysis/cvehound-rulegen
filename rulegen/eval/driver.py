"""Turn run logs into the paper's tables: pass@k, valid@b, the tier funnel,
degenerate flags, per-class breakdowns, and side-by-side comparisons.

Everything reads the flattened sample rows (`s_*` = Score columns) and the run
manifest; nothing here touches spatch or a model.
"""

import copy
import json
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from rulegen.eval.metrics import bootstrap_ci, pass_at_k, valid_at_b
from rulegen.gen.config import cell_identity
from rulegen.gen.log import read_samples
from rulegen.gen.manifest import read_manifest
from rulegen.schema import (
    ERROR,
    FIRE,
    LEG_BP,
    LEG_BP_PRE,
    LEG_CORE,
    LEG_DECOY,
    LEG_HEAD,
    LEG_RANGE,
    LEG_TREE,
    NO_FILES,
    SILENT,
    TIMEOUT,
    TRUNCATED,
    UNSUPPORTED,
    Leg,
    legs_from_json,
)
from rulegen.tables import Table, quantile
from rulegen.tiers import CLASSES

FUNNEL_STAGES = (
    'attempts',
    'rule emitted',
    'T0 structure',
    'T1 parses',
    'T1 grep query',
    'fix~ fires',
    'fix silent',
    'fixes legs',
    'init silent',
    'backports',
    'decoys silent',
    'VALID',
    'T4 selective',
    'T5 range',
    'T6 tree@backport',
    'STRONG',
)


@dataclass
class Run:
    run_dir: str
    manifest: dict[str, Any]
    rows: list[dict[str, Any]]

    @property
    def run_id(self) -> str:
        # The directory name wins: an archived run keeps its manifest but is
        # renamed on disk, and the table must say which directory a row came from.
        return os.path.basename(self.run_dir.rstrip('/')) or str(self.manifest.get('run_id', ''))

    @property
    def mode(self) -> str:
        return str(self.manifest.get('config', {}).get('mode', 'sample'))

    def config(self, section: str) -> dict[str, Any]:
        """One section of the run's config (model, prompt, data, ...); {} when absent."""
        return self.manifest.get('config', {}).get(section) or {}


def load_run(run_dir: str) -> Run:
    return Run(run_dir=run_dir, manifest=read_manifest(run_dir), rows=read_samples(run_dir))


def row_legs(row: dict[str, Any]) -> list[Leg]:
    """The row's legs as Leg objects, so `.ok` and `.kind` mean one thing bench-wide."""
    return legs_from_json(row.get('s_legs'))


def _legs_ok(legs: Iterable[Leg], kind: str) -> bool | None:
    picked = [leg for leg in legs if leg.kind == kind and leg.gating]
    if not picked:
        return None
    return all(leg.ok for leg in picked)


def head_fire_rate(rows: Sequence[dict[str, Any]]) -> float | None:
    """Share of VALID rows whose informational head scans fired anywhere; None when none ran."""
    checked = [row for row in rows if row.get('s_valid') and row.get('s_head_checked')]
    if not checked:
        return None
    return sum(1 for row in checked if row.get('s_head_fires')) / len(checked)


def outcomes_by_cve(rows: Sequence[dict[str, Any]], key: str = 's_valid') -> dict[str, list[bool]]:
    """Sample mode: per CVE, one boolean per round-0 sample, in sample order."""
    grouped: dict[str, list[tuple[int, bool]]] = {}
    for row in rows:
        if row.get('round', 0) != 0:
            continue
        grouped.setdefault(row['cve'], []).append((row['sample_index'], bool(row.get(key))))
    return {cve: [ok for _i, ok in sorted(items)] for cve, items in grouped.items()}


def attempt_costs(
    rows: Sequence[dict[str, Any]], key: str = 's_valid'
) -> dict[str, list[tuple[int, bool]]]:
    """Per CVE, attempt chains as (tokens spent, succeeded) in attempt order."""
    grouped: dict[str, dict[int, tuple[int, bool]]] = {}
    for row in rows:
        chain = grouped.setdefault(row['cve'], {})
        tokens, ok = chain.get(row['sample_index'], (0, False))
        chain[row['sample_index']] = (
            max(tokens, int(row.get('tokens_cum') or 0)),
            ok or bool(row.get(key)),
        )
    return {cve: [chain[i] for i in sorted(chain)] for cve, chain in grouped.items()}


def attempt_outcomes(rows: Sequence[dict[str, Any]], key: str = 's_valid') -> dict[str, list[bool]]:
    """Pipelines: per CVE, one boolean per attempt chain (any round succeeded)."""
    return {cve: [ok for _tokens, ok in chain] for cve, chain in attempt_costs(rows, key).items()}


def _solved(outcomes: dict[str, list[bool]]) -> int:
    """How many CVEs got at least one success."""
    return sum(1 for chain in outcomes.values() if any(chain))


def _pass_at_k(outcomes: dict[str, list[bool]], k: int) -> list[float]:
    """The unbiased pass@k of every CVE with at least k samples."""
    return [pass_at_k(len(v), sum(v), k) for v in outcomes.values() if len(v) >= k]


def _outcomes(run: Run, key: str = 's_valid') -> dict[str, list[bool]]:
    """Per-CVE outcome chains for the run's mode: round-0 samples, or attempt chains for pipelines."""
    return (
        attempt_outcomes(run.rows, key)
        if run.mode == 'pipeline'
        else outcomes_by_cve(run.rows, key)
    )


def valid_at_tokens(costs: dict[str, list[tuple[int, bool]]], budget: int) -> float:
    """Fraction of CVEs with a valid rule before `budget` generated+prompt tokens run out,
    spending attempts in order — the equal-budget comparison across modes."""
    if not costs:
        return 0.0
    hits = 0
    for chain in costs.values():
        spent = 0
        for tokens, ok in chain:
            spent += tokens
            if spent > budget:
                break
            if ok:
                hits += 1
                break
    return hits / len(costs)


def pass_at_k_table(
    run: Run, ks: Sequence[int] = (1, 5, 10), key: str = 's_valid', iters: int = 2000, seed: int = 0
) -> Table:
    outcomes = outcomes_by_cve(run.rows, key)
    table = Table(
        f'pass@k ({key}) — {run.run_id}',
        ['k', 'CVEs', 'pass@k', 'CI95 lo', 'CI95 hi'],
        note='unbiased estimator per CVE (n samples, c valid); CI = percentile bootstrap over CVEs',
    )
    for k in ks:
        per_cve = _pass_at_k(outcomes, k)
        if not per_cve:
            table.rows.append([k, 0, None, None, None])
            continue
        mean, lo, hi = bootstrap_ci(per_cve, iters=iters, seed=seed)
        table.rows.append([k, len(per_cve), round(mean, 4), round(lo, 4), round(hi, 4)])
    return table


def valid_at_b_table(
    run: Run,
    bs: Sequence[int] = (1, 4, 8),
    budgets: Sequence[int] = (4_000, 8_000, 16_000, 32_000, 64_000),
    key: str = 's_valid',
) -> Table:
    chains = list(_outcomes(run, key).values())
    table = Table(
        f'valid@b and valid@tokens ({key}) — {run.run_id}',
        ['budget', 'CVEs', 'valid'],
        note='valid@b: any of the first b attempts; valid@tokens: attempts in order until the token budget is spent',
    )
    for b in bs:
        usable = [chain for chain in chains if len(chain) >= b]
        table.rows.append(
            [f'b={b}', len(usable), round(valid_at_b(usable, b), 4) if usable else None]
        )
    costs = attempt_costs(run.rows, key)
    for budget in budgets:
        table.rows.append(
            [f'{budget // 1000}K tokens', len(costs), round(valid_at_tokens(costs, budget), 4)]
        )
    return table


def furthest_stage(row: dict[str, Any]) -> int:
    """Index into FUNNEL_STAGES of the last stage this attempt passed."""
    fail = row.get('s_fail_class')
    if fail == 'contract' or not row.get('parsed'):
        return 0
    if fail in ('structure', 'harness'):
        return 1
    if not row.get('s_t1_parse'):
        return 2
    legs = row_legs(row)  # only the rows that reached the oracle pay for this
    stage = 3
    if row.get('s_t1_grep_query'):
        stage = 4
    # One stage per leg family, in the order the oracle judges them: the core
    # pairs by name, then whole families by kind.
    checks: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        ((LEG_CORE,), ('fix~',)),
        ((LEG_CORE,), ('fix',)),
        ((LEG_CORE,), ('fixes', 'fixes~')),
        ((LEG_CORE,), ('init',)),
        ((LEG_BP_PRE, LEG_BP), ()),
        ((LEG_DECOY,), ()),
    )
    for kinds, names in checks:
        picked = [leg for leg in legs if leg.kind in kinds and (not names or leg.name in names)]
        if picked and not all(leg.ok for leg in picked):
            return stage
        stage += 1
    if not row.get('s_valid'):
        return stage - 1
    stage = FUNNEL_STAGES.index('VALID')
    t4 = row.get('s_t4_unrelated_files')
    if t4 is not None and t4 > 0:
        return stage
    stage += 1
    if _legs_ok(legs, LEG_RANGE) is False:
        return stage
    stage += 1
    if _legs_ok(legs, LEG_TREE) is False:
        return stage
    stage += 1
    return FUNNEL_STAGES.index('STRONG') if row.get('s_strong_valid') else stage


def funnel(rows: Sequence[dict[str, Any]], title: str = 'tier funnel') -> Table:
    reached = [furthest_stage(row) for row in rows]
    table = Table(title, ['stage', 'attempts', '% of attempts'])
    total = len(rows) or 1
    for i, stage in enumerate(FUNNEL_STAGES):
        count = sum(1 for r in reached if r >= i)
        table.rows.append([stage, count, round(100 * count / total, 1)])
    return table


VERDICT_COLUMNS = (FIRE, SILENT, NO_FILES, ERROR, TIMEOUT, TRUNCATED, UNSUPPORTED)
VERDICT_KINDS = (LEG_CORE, LEG_BP_PRE, LEG_BP, LEG_DECOY, LEG_RANGE, LEG_TREE, LEG_HEAD)


def verdict_table(run: Run) -> Table:
    """How every leg of the run ended, by leg kind.

    The funnel says where attempts stopped; this says whether the oracle answered
    at all. An error, a timeout or a truncated scan is the engine not finishing --
    never a silence -- and a truncated one is the environment's, so a run with
    many of them says more about the environment than about the rules.
    """
    counts: dict[str, dict[str, int]] = {kind: {} for kind in VERDICT_KINDS}
    for row in run.rows:
        for leg in row_legs(row):
            per = counts.setdefault(leg.kind, {})
            per[leg.verdict] = per.get(leg.verdict, 0) + 1
    table = Table(f'leg verdicts — {run.run_id}', ['kind', *VERDICT_COLUMNS, 'legs'])
    for kind, per in counts.items():
        if per:
            table.rows.append([kind, *(per.get(v, 0) for v in VERDICT_COLUMNS), sum(per.values())])
    return table


def degenerate_flags(row: dict[str, Any]) -> dict[str, bool]:
    """Reward-hacking audit flags for a VALID rule.

    over_broad: spatch has no grep query for it, or unrelated lib/ files survive
    the prefilter. trivial_echo: no literal name anywhere in the rule -- every
    identifier is a metavariable or vocabulary. wildcard_star: a metavariable
    stands where a name belongs on a report line. Both read the text terms the
    oracle recorded (`s_t0_anchored`, `s_t0_wildcards`, tiers.text_terms), so the
    audit and the reward cannot disagree. era_matched: T5 found a range point it
    misses.
    """
    t4 = row.get('s_t4_unrelated_files')
    over_broad = row.get('s_t1_grep_query') is False or (t4 is not None and t4 > 0)
    anchored, wildcards = row.get('s_t0_anchored'), row.get('s_t0_wildcards')
    if isinstance(wildcards, str):
        wildcards = json.loads(wildcards)
    points, fired = row.get('s_t5_points'), row.get('s_t5_fired')
    era_matched = points is not None and fired is not None and fired < points
    return {
        'over_broad': bool(over_broad),
        'trivial_echo': anchored is False,
        'wildcard_star': bool(wildcards),
        'era_matched': bool(era_matched),
    }


DEGENERATE_FLAGS = tuple(degenerate_flags({}))


def valid_unique_rows(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """VALID rows, the first per distinct rule: a rule sampled ten times is one
    rule in the audit, as it is in the cost table. Keyed on (cve, rule_sha)
    rather than `dedup_of`, which a rescore clears."""
    seen: set[tuple[str, str]] = set()
    out = []
    for row in rows:
        key = (row['cve'], row.get('rule_sha') or '')
        if row.get('s_valid') and key not in seen:
            seen.add(key)
            out.append(row)
    return out


def degenerate_table(run: Run) -> Table:
    valid_rows = valid_unique_rows(run.rows)
    table = Table(
        f'degenerate% among VALID — {run.run_id}',
        ['flag', 'count', '% of valid (unique rules)'],
        note='over_broad: no grep query or T4 survivors; trivial_echo: no literal name anywhere in the rule; wildcard_star: a metavariable as a starred callee or the reporting anchor; era_matched: T5 misses range points',
    )
    total = len(valid_rows) or 1
    counts = Counter(
        flag for row in valid_rows for flag, hit in degenerate_flags(row).items() if hit
    )
    for flag in DEGENERATE_FLAGS:
        table.rows.append([flag, counts[flag], round(100 * counts[flag] / total, 1)])
    table.rows.append(['valid rules', len(valid_rows), 100.0])
    return table


def by_class(run: Run, key: str = 's_valid') -> Table:
    outcomes = _outcomes(run, key)
    cls_of = {row['cve']: row.get('cls') or '?' for row in run.rows}
    table = Table(
        f'by context class ({key}) — {run.run_id}', ['class', 'CVEs', 'pass@1', 'valid@n']
    )
    for cls in (*CLASSES, '?'):
        cves = [cve for cve in outcomes if cls_of.get(cve) == cls]
        if not cves:
            continue
        p1 = sum(sum(outcomes[c]) / len(outcomes[c]) for c in cves) / len(cves)
        any_valid = sum(1 for c in cves if any(outcomes[c])) / len(cves)
        table.rows.append([cls, len(cves), round(p1, 4), round(any_valid, 4)])
    return table


def summary(run: Run, key: str = 's_valid') -> dict[str, Any]:
    outcomes = _outcomes(run, key)
    strong = _outcomes(run, 's_strong_valid')
    n_cves = len(outcomes)
    valid_rows = valid_unique_rows(run.rows)
    flags = [degenerate_flags(row) for row in valid_rows]
    degenerate = sum(1 for f in flags if any(f.values()))

    def pk(k: int) -> float | None:
        per = _pass_at_k(outcomes, k)
        return round(sum(per) / len(per), 4) if per else None

    model_cfg = run.config('model')
    model = str(
        model_cfg.get('model')
        or run.manifest.get('model', {}).get('adapter_describe', {}).get('adapter')
        or ''
    )
    if model_cfg.get('effort'):
        model = f'{model}@{model_cfg["effort"]}'
    return {
        'run': run.run_id,
        'mode': run.mode,
        'model': model,
        'policy': str(run.config('prompt').get('policy', '')),
        'split': str(run.config('data').get('split', '')),
        'CVEs': n_cves,
        'attempts': len(run.rows),
        'pass@1': pk(1),
        'pass@5': pk(5),
        'pass@10': pk(10),
        'valid@n': round(_solved(outcomes) / n_cves, 4) if n_cves else None,
        'strong@n': round(_solved(strong) / n_cves, 4) if n_cves else None,
        'degenerate%': round(100 * degenerate / len(valid_rows), 1) if valid_rows else None,
        'head_fire%': None if (rate := head_fire_rate(run.rows)) is None else round(100 * rate, 1),
        'truncated_legs': sum(row.get('s_truncated_legs') or 0 for row in run.rows),
        'wall_s': run.manifest.get('totals', {}).get('wall_s'),
    }


def compare(runs: Sequence[Run], key: str = 's_valid') -> Table:
    summaries = [summary(run, key) for run in runs]
    columns = list(summaries[0]) if summaries else []
    return Table('runs side by side', columns, [[s[c] for c in columns] for s in summaries])


def _cell(run: Run) -> dict[str, Any]:
    cell = cell_identity(run.manifest.get('config', {}))
    cell.pop('data', None)
    cell['transform'] = run.manifest.get('transform')
    return cell


def merge_runs(runs: Sequence[Run], name: str) -> Run:
    """One Run over several directories (e.g. the train/val/test runs of one cell)."""
    rows = [row for run in runs for row in run.rows]
    # Every run must come from the same cell: the same config identity (config_sha's
    # definition, minus the data split) under the same rescore transform.
    cells = [_cell(run) for run in runs]
    for run, cell in zip(runs[1:], cells[1:], strict=True):
        differing = sorted(
            k for k in cells[0].keys() | cell.keys() if cells[0].get(k) != cell.get(k)
        )
        if differing:
            raise ValueError(
                f'cannot merge {run.run_id} with {runs[0].run_id}: differs in {", ".join(differing)}'
            )
    manifest = copy.deepcopy(runs[0].manifest) if runs else {}
    manifest['run_id'] = name
    manifest['merged_from'] = [run.run_dir for run in runs]
    manifest.pop('config_sha', None)
    splits = [s for run in runs if (s := str(run.config('data').get('split', '')))]
    if splits:
        manifest.setdefault('config', {}).setdefault('data', {})['split'] = '+'.join(splits)
    manifest['totals'] = {
        'wall_s': sum(float(r.manifest.get('totals', {}).get('wall_s') or 0) for r in runs)
    }
    merged = Run(run_dir=name, manifest=manifest, rows=rows)
    return merged


def _quantiles(xs: Sequence[float]) -> list[float | None]:
    """p10, median, p90 and max, rounded; Nones for no values."""
    if not xs:
        return [None] * 4
    return [round(quantile(xs, q), 2) for q in (0.1, 0.5, 0.9, 1.0)]


def cost_table(run: Run, gold_path: str) -> Table:
    """Deployment cost of the run's VALID rules against the gold distribution
    (CPU-s per whole-tree scan, prefilter survivors), with Vargha-Delaney A12."""
    from rulegen.eval.metrics import vargha_delaney_a12

    with open(gold_path) as fh:
        gold = json.load(fh)
    gold_cpu = [r['cost_cpu_seconds'] for r in gold if r.get('cost_cpu_seconds') is not None]
    gold_files = [
        r['cost_prefilter_files'] for r in gold if r.get('cost_prefilter_files') is not None
    ]
    valid = valid_unique_rows(run.rows)
    cpu = [row['s_cost_cpu_seconds'] for row in valid if row.get('s_cost_cpu_seconds') is not None]
    files = [
        row['s_cost_prefilter_files']
        for row in valid
        if row.get('s_cost_prefilter_files') is not None
    ]
    table = Table(
        f'rule cost vs gold — {run.run_id}',
        ['metric', 'set', 'n', 'p10', 'median', 'p90', 'max', 'A12 vs gold'],
        note='A12 > 0.5: generated rules cost more than gold; needs the -full (T5/T6/cost) run',
    )
    for name, ours, theirs in (
        ('CPU-s / whole-tree scan', cpu, gold_cpu),
        ('prefilter files', files, gold_files),
    ):
        table.rows.append([name, 'gold', len(theirs), *_quantiles(theirs), ''])
        a12 = round(vargha_delaney_a12(ours, theirs), 3) if ours and theirs else None
        table.rows.append([name, 'generated (valid, unique)', len(ours), *_quantiles(ours), a12])
    return table


def load_prices(path: str) -> dict[str, dict[str, Any]]:
    """The `frontier:` price map of experiments/models.yaml, keyed by model id and alias."""
    import yaml

    if not path or not os.path.exists(path):
        return {}
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    prices: dict[str, dict[str, Any]] = {}
    for key, entry in (data.get('frontier') or {}).items():
        if not isinstance(entry, dict):
            continue
        prices[str(key)] = {**entry, 'id': str(key)}
        if entry.get('alias'):
            prices.setdefault(str(entry['alias']), {**entry, 'id': str(key)})
    return prices


def price_key(run: Run) -> str:
    """The model id a run's usage is priced at: what the CLI resolved, else the configured name."""
    desc = run.manifest.get('model', {}).get('adapter_describe', {}) or {}
    return str(desc.get('resolved_model') or run.config('model').get('model') or '')


def usage_totals(rows: Sequence[dict[str, Any]]) -> dict[str, float]:
    prompt = sum(int(r.get('tokens_prompt') or 0) for r in rows)
    cached = sum(int(r.get('tokens_cached') or 0) for r in rows)
    output = sum(int(r.get('tokens_completion') or 0) for r in rows)
    reported = sum(float(r.get('cost_usd') or 0.0) for r in rows)
    return {'prompt': prompt, 'cached': cached, 'output': output, 'reported_usd': reported}


def list_price_usd(totals: dict[str, float], price: dict[str, Any]) -> float | None:
    """Tokens x list price; None when the entry has no prices (never guessed)."""
    try:
        inp = float(price['input_per_mtok'])
        out = float(price['output_per_mtok'])
    except (KeyError, TypeError, ValueError):
        return None
    cached_rate = price.get('cached_input_per_mtok')
    cached_rate = inp if cached_rate is None else float(cached_rate)
    uncached = max(0.0, totals['prompt'] - totals['cached'])
    return (uncached * inp + totals['cached'] * cached_rate + totals['output'] * out) / 1e6


def cost_usd_table(run: Run, prices: dict[str, dict[str, Any]], key: str = 's_valid') -> Table:
    """What the run's tokens cost at list price, per attempt, per valid rule and per solved CVE."""
    model_id = price_key(run)
    price = prices.get(model_id, {})
    totals = usage_totals(run.rows)
    listed = list_price_usd(totals, price) if price else None
    solved = _solved(_outcomes(run, key))
    unique_valid = len(valid_unique_rows(run.rows))
    tool_rows = sum(1 for r in run.rows if int(r.get('tool_calls') or 0) > 0)
    denied_rows = sum(1 for r in run.rows if int(r.get('tool_attempts_denied') or 0) > 0)

    def per(x: float | None, n: int) -> float | None:
        return round(x / n, 4) if x is not None and n else None

    table = Table(
        f'cost at list price — {run.run_id}',
        ['metric', 'value'],
        note=(
            f'priced as {model_id!r} ({price.get("price_date", "no price entry")}); cache writes '
            'are priced at the input rate, so the list price is exact for codex (no write premium) '
            'and a lower bound for claude (1-hour cache writes cost 2x): there, the provider-reported '
            'figure the CLI prints is the one to cite; rows where a tool ran must be 0 (they are retried), '
            'rows after a refused attempt are kept and can be dropped as a sensitivity check'
        ),
    )
    table.rows = [
        ['attempts', len(run.rows)],
        ['prompt tokens', int(totals['prompt'])],
        ['of which cached', int(totals['cached'])],
        ['output tokens', int(totals['output'])],
        ['list-price USD', None if listed is None else round(listed, 2)],
        [
            'provider-reported USD',
            round(totals['reported_usd'], 2) if totals['reported_usd'] else None,
        ],
        ['USD per attempt', per(listed, len(run.rows))],
        ['unique valid rules', unique_valid],
        ['USD per valid rule', per(listed, unique_valid)],
        ['CVEs with a valid rule', solved],
        ['USD per CVE solved', per(listed, solved)],
        ['rows where a tool ran', tool_rows],
        ['rows after a refused tool attempt', denied_rows],
        ['sampling honored', all(r.get('sampling_honored', True) for r in run.rows)],
    ]
    return table


def report(
    run_dirs: Sequence[str],
    key: str = 's_valid',
    merge: str = '',
    gold_cost: str = '',
    prices: str = '',
) -> list[Table]:
    runs = [load_run(d) for d in run_dirs]
    if merge:
        runs = [merge_runs(runs, merge)]
    price_map = load_prices(prices)
    tables: list[Table] = [compare(runs, key)]
    for run in runs:
        tables.append(funnel(run.rows, f'tier funnel — {run.run_id}'))
        tables.append(verdict_table(run))
        tables.append(pass_at_k_table(run, key=key))
        tables.append(valid_at_b_table(run, key=key))
        tables.append(by_class(run, key))
        tables.append(degenerate_table(run))
        if gold_cost and os.path.exists(gold_cost):
            tables.append(cost_table(run, gold_cost))
        if price_map and price_key(run) in price_map:
            tables.append(cost_usd_table(run, price_map, key=key))
    return tables
