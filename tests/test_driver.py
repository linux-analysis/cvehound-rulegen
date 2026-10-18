"""Eval driver on a synthetic run: hand-computable pass@k, funnel stages, flags."""

import json

import pytest
import yaml
from helpers import ANCHORED_ECHO, ECHO_RULE, KFREE, WILDCARD_RULE, with_text_terms

from rulegen.eval.driver import (
    FUNNEL_STAGES,
    Run,
    attempt_costs,
    attempt_outcomes,
    by_class,
    compare,
    cost_table,
    cost_usd_table,
    degenerate_flags,
    funnel,
    furthest_stage,
    head_fire_rate,
    load_prices,
    merge_runs,
    outcomes_by_cve,
    pass_at_k_table,
    price_key,
    summary,
    valid_at_tokens,
    verdict_table,
)
from rulegen.eval.metrics import pass_at_k
from rulegen.tables import render_markdown


def legs(**verdicts: str) -> str:
    out = []
    for name, verdict in verdicts.items():
        name = name.replace('__', ':').replace('_t', '~')
        fire = name in ('fix~', 'fixes') or name.startswith(('range:', 'bp~:'))
        expect = 'fire' if fire else 'silent'
        out.append({'name': name, 'expect': expect, 'verdict': verdict, 'seconds': 0.1})
    return json.dumps(out)


def row(cve: str, index: int, valid: bool, **extra) -> dict:
    base = {
        'cve': cve,
        'cls': 'B',
        'sample_index': index,
        'round': 0,
        'parsed': True,
        'tokens_cum': 5000,
        'rule_sha': f'{cve}-{index}',  # each fixture row is its own rule
        'rule_text': KFREE,
        's_fail_class': 'none',
        's_t1_parse': True,
        's_t1_grep_query': True,
        's_t4_unrelated_files': 0,
        's_valid': valid,
        's_strong_valid': valid,
        's_legs': legs(fix_t='fire', fix='fire' if not valid else 'silent', bp__x='silent'),
    }
    return with_text_terms({**base, **extra})


def make_run() -> Run:
    rows = [row('C1', 0, True), row('C1', 1, False), row('C1', 2, True), row('C1', 3, False)]
    rows += [row('C2', i, False) for i in range(4)]
    rows += [row('C3', 0, True)] + [row('C3', i, True) for i in range(1, 4)]
    return Run('runs/x', {'run_id': 'x', 'config': {'mode': 'sample'}, 'totals': {}}, rows)


def test_pass_at_k_matches_hand_computation():
    run = make_run()
    outcomes = outcomes_by_cve(run.rows)
    assert outcomes['C1'] == [True, False, True, False]
    table = pass_at_k_table(run, ks=(1, 2), iters=200)
    expected_1 = (pass_at_k(4, 2, 1) + pass_at_k(4, 0, 1) + pass_at_k(4, 4, 1)) / 3
    expected_2 = (pass_at_k(4, 2, 2) + 0 + 1) / 3
    assert table.rows[0][:3] == [1, 3, round(expected_1, 4)]
    assert table.rows[1][:3] == [2, 3, round(expected_2, 4)]
    assert table.rows[0][3] <= table.rows[0][2] <= table.rows[0][4]


def test_funnel_and_furthest_stage():
    contract = row(
        'C9', 0, False, parsed=False, s_fail_class='contract', rule_text=None, s_legs='[]'
    )
    unparsed = row('C9', 1, False, s_fail_class='parse', s_t1_parse=False, s_legs='[]')
    fires_at_fix = row('C9', 2, False)
    valid = row('C9', 3, True)
    assert furthest_stage(contract) == 0
    assert furthest_stage(unparsed) == FUNNEL_STAGES.index('T0 structure')
    assert furthest_stage(fires_at_fix) == FUNNEL_STAGES.index('fix~ fires')
    assert furthest_stage(valid) == FUNNEL_STAGES.index('STRONG')
    table = funnel([contract, unparsed, fires_at_fix, valid])
    counts = {stage: count for stage, count, _pct in table.rows}
    assert counts['attempts'] == 4 and counts['rule emitted'] == 3
    assert counts['T1 parses'] == 2 and counts['VALID'] == 1 and counts['STRONG'] == 1


def test_backport_legs_gate_and_head_legs_do_not():
    fires_after_backport = row(
        'C9', 0, False, s_legs=legs(fix_t='fire', fix='silent', **{'bp__x@1': 'fire'})
    )
    assert furthest_stage(fires_after_backport) == FUNNEL_STAGES.index('init silent')
    misses_before_backport = row(
        'C9', 0, False, s_legs=legs(fix_t='fire', fix='silent', **{'bp~__x@1': 'silent'})
    )
    assert furthest_stage(misses_before_backport) == FUNNEL_STAGES.index('init silent')
    head_fires = row(
        'C9',
        1,
        True,
        s_head_checked=8,
        s_head_fires=2,
        s_legs=legs(fix_t='fire', fix='silent', **{'head__origin/master@1': 'fire'}),
    )
    assert furthest_stage(head_fires) == FUNNEL_STAGES.index('STRONG')
    assert head_fire_rate([head_fires, row('C9', 2, True)]) == 1.0
    assert head_fire_rate([row('C9', 2, True)]) is None


def test_furthest_stage_matches_fix_legs_exactly():
    # 'fixes' must not be swept into the 'fix' stage by prefix matching.
    silent_on_fixes = row('C9', 0, False, s_legs=legs(fix_t='fire', fix='silent', fixes='silent'))
    assert furthest_stage(silent_on_fixes) == FUNNEL_STAGES.index('fix silent')


def test_degenerate_flags():
    assert degenerate_flags(row('C1', 0, True)) == {
        'over_broad': False,
        'trivial_echo': False,
        'wildcard_star': False,
        'era_matched': False,
    }
    echo = row('C1', 0, True, rule_text=ECHO_RULE, s_t1_grep_query=False)
    assert degenerate_flags(echo)['trivial_echo'] is True
    assert degenerate_flags(echo)['over_broad'] is True
    # A token-free starred line inside a named function is anchored, not an echo.
    anchored = degenerate_flags(row('C1', 0, True, rule_text=ANCHORED_ECHO))
    assert anchored['trivial_echo'] is False and anchored['wildcard_star'] is False
    wild = degenerate_flags(row('C1', 0, True, rule_text=WILDCARD_RULE))
    assert wild['wildcard_star'] is True and wild['trivial_echo'] is False
    era = row('C1', 0, True, s_t5_points=4, s_t5_fired=3)
    assert degenerate_flags(era)['era_matched'] is True


def test_pipeline_attempts_and_token_budgets():
    rows = [
        row('C1', 0, False, round=0, tokens_cum=6000),
        row('C1', 0, True, round=1, tokens_cum=13000),  # repaired on round 1
        row('C1', 1, False, round=0, tokens_cum=6000),
        row('C2', 0, False, round=0, tokens_cum=7000),
    ]
    assert attempt_outcomes(rows) == {'C1': [True, False], 'C2': [False]}
    costs = attempt_costs(rows)
    assert costs['C1'] == [(13000, True), (6000, False)]
    assert valid_at_tokens(costs, 12000) == 0.0
    assert valid_at_tokens(costs, 16000) == 0.5
    rows[1]['s_strong_valid'] = False
    assert attempt_costs(rows, 's_strong_valid')['C1'] == [(13000, False), (6000, False)]


def test_pipeline_summary_counts_later_rounds():
    rows = [
        row('C1', 0, False, round=0),
        row('C1', 0, True, round=1),  # strong only after repair
        row('C2', 0, False, round=0),
    ]
    run = Run('runs/p', {'run_id': 'p', 'config': {'mode': 'pipeline'}, 'totals': {}}, rows)
    s = summary(run)
    assert s['valid@n'] == 0.5 and s['strong@n'] == 0.5
    assert by_class(run).rows[0] == ['B', 2, 0.5, 0.5]


def test_compare_and_markdown_render():
    table = compare([make_run()])
    assert table.columns[0] == 'run' and table.rows[0][0] == 'x'
    text = render_markdown([table])
    assert text.startswith('### runs side by side') and '| x |' in text


def test_merge_runs_concatenates_rows():
    a = make_run()
    b = Run(
        'runs/y',
        {'run_id': 'y', 'config': {'mode': 'sample'}, 'totals': {'wall_s': 5}},
        [row('C9', 0, True)],
    )
    merged = merge_runs([a, b], 'all')
    assert merged.run_id == 'all' and len(merged.rows) == len(a.rows) + 1
    assert summary(merged)['CVEs'] == 4


def test_merge_runs_joins_splits_and_rejects_other_cells():
    def split_run(split: str, model: str = 'm') -> Run:
        cfg = {
            'mode': 'sample',
            'model': {'model': model},
            'oracle': {'jobs': 1, 'work': '/w', 'run_cost': True},
            'data': {'split': split},
        }
        return Run(
            f'runs/{split}',
            {'run_id': split, 'config': cfg, 'config_sha': 'abc', 'totals': {}},
            [row(f'C-{split}', 0, True)],
        )

    train, val, test = split_run('train'), split_run('val'), split_run('test')
    merged = merge_runs([train, val, test], 'cell')
    assert summary(merged)['split'] == 'train+val+test'
    assert 'config_sha' not in merged.manifest
    assert train.manifest['config']['data']['split'] == 'train'  # runs[0] untouched
    with pytest.raises(ValueError, match='model'):
        merge_runs([train, split_run('val', model='other')], 'bad')
    # Machine knobs that config_sha ignores do not split a cell; a rescore transform does.
    val.manifest['config']['oracle'].update(jobs=8, work='/elsewhere')
    val.manifest['config']['model']['concurrency'] = 4
    assert len(merge_runs([train, val], 'ok').rows) == 2
    val.manifest['transform'] = 'canon'
    with pytest.raises(ValueError, match='transform'):
        merge_runs([train, val], 'bad')
    # A run without a recorded split does not leave a hole in the joined label.
    del val.manifest['transform'], val.manifest['config']['data']['split']
    assert summary(merge_runs([train, val, test], 'two'))['split'] == 'train+test'


def test_cost_table_compares_against_gold(tmp_path):
    gold = tmp_path / 'gold.json'
    gold.write_text(
        json.dumps([{'cost_cpu_seconds': c, 'cost_prefilter_files': 1} for c in (5, 10, 12, 20)])
    )
    run = make_run()
    for i, r in enumerate(r for r in run.rows if r['s_valid']):
        r['s_cost_cpu_seconds'] = 30 + i
        r['s_cost_prefilter_files'] = 5
    table = cost_table(run, str(gold))
    cpu_generated = table.rows[1]
    assert cpu_generated[1].startswith('generated') and cpu_generated[2] == 6
    assert cpu_generated[-1] == 1.0  # every generated rule costs more than every gold rule


def test_cost_usd_table_prices_usage_at_list_price(tmp_path):
    prices_file = tmp_path / 'models.yaml'
    prices_file.write_text(
        yaml.safe_dump(
            {
                'frontier': {
                    'claude-fable-5-1': {
                        'alias': 'fable',
                        'input_per_mtok': 10.0,
                        'cached_input_per_mtok': 0.25,
                        'output_per_mtok': 50.0,
                        'price_date': '2026-09-24',
                    },
                    'gpt-6-luna': {'alias': None, 'price_date': '2026-09-24'},
                }
            }
        )
    )
    prices = load_prices(str(prices_file))
    assert prices['fable']['id'] == 'claude-fable-5-1'
    run = make_run()
    run.manifest['config']['model'] = {'model': 'fable', 'effort': 'medium'}
    run.manifest['model'] = {'adapter_describe': {'resolved_model': 'claude-fable-5-1'}}
    for r in run.rows:
        r['tokens_prompt'] = 1000
        r['tokens_cached'] = 400
        r['tokens_completion'] = 100
        r['cost_usd'] = 0.01
        r['tool_calls'] = 0
    assert price_key(run) == 'claude-fable-5-1'
    table = cost_usd_table(run, prices)
    cells = dict(table.rows)
    n = len(run.rows)
    expected = n * (600 * 10.0 + 400 * 0.25 + 100 * 50.0) / 1e6
    assert cells['list-price USD'] == round(expected, 2)
    assert cells['provider-reported USD'] == round(0.01 * n, 2)
    assert cells['USD per attempt'] == round(expected / n, 4)
    assert cells['unique valid rules'] == 6 and cells['USD per valid rule'] == round(
        expected / 6, 4
    )
    assert cells['rows where a tool ran'] == 0 and cells['sampling honored'] is True
    assert cells['rows after a refused tool attempt'] == 0
    # A model with no prices gets no number, not a guess.
    run.manifest['model']['adapter_describe']['resolved_model'] = 'gpt-6-luna'
    assert dict(cost_usd_table(run, prices).rows)['list-price USD'] is None


def test_verdict_table_counts_how_every_leg_ended():
    run = make_run()
    run.rows.append(
        row('C4', 0, False, s_truncated_legs=1, s_legs=legs(fix_t='fire', tree__x='truncated'))
    )
    table = verdict_table(run)
    by_kind = {r[0]: dict(zip(table.columns, r, strict=True)) for r in table.rows}
    assert by_kind['tree']['truncated'] == 1 and by_kind['tree']['legs'] == 1
    # 12 fixture rows fire at fix~, the 6 invalid ones also at fix, and C4 at fix~.
    assert by_kind['core']['fire'] == 12 + 6 + 1
    assert summary(run)['truncated_legs'] == 1
