"""Expert-iteration dataset construction: who the teacher may run on, and what it keeps."""

import pytest
from helpers import with_text_terms

from rulegen import synthetic
from rulegen.promptbuild import contract_body
from rulegen.shapes import ShapeRecord


def shape(cve, split='pool', funcs=(), kind='adds', year=2022, subsystem='fs'):
    return ShapeRecord(
        cve=cve,
        split=split,
        fix='deadbeef',
        year=year,
        subsystem=subsystem,
        shape=kind,
        n_files=1,
        n_add=1,
        n_del=0,
        funcs=list(funcs),
    )


HEADER = '/// Files: fs/x.c\n/// Fix: abc\n/// Fixes: def\n\n'


def rule(name='kfree_the_widget', stars=1):
    body = '\n'.join(f'*  {name}_{i}(x);' for i in range(stars))
    return HEADER + f'@r@\nidentifier f;\n@@\nf(...) {{\n...\n{body}\n...\n}}\n'


def row(cve='CVE-2022-1', text=None, cost=10.0, round_=0, sha='sha1', **over):
    out = {
        'cve': cve,
        'rule_text': text if text is not None else rule(),
        'rule_sha': sha,
        'round': round_,
        'run_id': 'teach',
        'attempt_id': f'{cve}:0:{round_}',
        'policy': 'P-H',
        's_valid': True,
        's_strong_valid': True,
        's_cost_cpu_seconds': cost,
        's_t1_grep_query': True,
        's_t4_unrelated_files': 0,
        's_t5_points': 4,
        's_t5_fired': 4,
    }
    out.update(over)
    # What the harness and the oracle record for every parsed rule.
    if out.get('rule_text'):
        out.setdefault('rule_body', contract_body(out['rule_text']))
    return with_text_terms(out)


# -- who the teacher may run on --------------------------------------------


def test_clean_pool_drops_gold_function_overlap_and_unusable_fixes():
    shapes = [
        shape('CVE-2020-GOLD', split='train', funcs=['fs/a.c:doit']),
        shape('CVE-2020-GOLD2', funcs=['fs/e.c:fifth']),  # a gold CVE listed in the pool split
        shape('CVE-2022-OVERLAP', funcs=['fs/a.c:doit']),  # same (file, function)
        shape('CVE-2022-KEEP', funcs=['fs/b.c:other']),
        shape('CVE-2022-NOSRC', funcs=['x'], kind='none'),  # touches no C source
        shape('CVE-2022-GONE', funcs=['y'], kind='deletes'),  # only deletes it
        # No agreed anchor: no fixes legs, no T5, and a rule the suite rejects.
        shape('CVE-2022-REJECTED', funcs=['fs/c.c:third']),
        shape('CVE-2024-OTHERSPLIT', split='reserve', funcs=['fs/d.c:fourth']),
    ]
    gold = {'CVE-2020-GOLD', 'CVE-2020-GOLD2'}
    kept = synthetic.clean_pool(shapes, 'pool', gold_cves=gold, ineligible={'CVE-2022-REJECTED'})
    assert kept == ['CVE-2022-KEEP']


def test_shards_interleave_deterministically_and_lose_nothing():
    ids = [f'CVE-2022-{i}' for i in range(10)]
    parts = synthetic.shards(ids, 4)
    assert [len(p) for p in parts] == [3, 3, 2, 2]
    assert sorted(sum(parts, [])) == sorted(ids)
    assert parts == synthetic.shards(list(reversed(ids)), 4)  # sorted first
    assert parts[0][0] < parts[1][0]  # interleaved, not blocked
    with pytest.raises(ValueError):
        synthetic.shards(ids, 0)


# -- what is kept ----------------------------------------------------------


def test_is_accepted_requires_an_introducing_commit():
    """No Fixes:/Detect-To: means the suite rejects it and T5/fixes legs never run."""
    unanchored = row(text='/// Files: fs/x.c\n/// Fix: abc\n\n@r@\n@@\n*  kfree_the_widget(x);\n')
    assert not synthetic.is_anchored(unanchored['rule_text'])
    assert not synthetic.is_accepted(unanchored)
    detect_to = row(
        text='/// Files: fs/x.c\n/// Fix: abc\n/// Detect-To: def\n\n@r@\n@@\n*  kfree_the_widget(x);\n'
    )
    assert synthetic.is_accepted(detect_to)
    assert synthetic.select([unanchored]) == []


@pytest.mark.parametrize(
    ('over', 'accepted'),
    [
        ({}, True),
        ({'s_strong_valid': False}, False),
        ({'rule_text': None}, False),
        # A degenerate rule (eval.driver.degenerate_flags) never enters the set.
        ({'s_t1_grep_query': False}, False),
        # A token-free star inside a named function is anchored, and kept.
        ({'text': HEADER + '@r@\n@@\nfoo(...)\n{\n*  return;\n}\n'}, True),
        # An unmeasured cost is not a licence to skip the cap.
        ({'cost': synthetic.COST_CAP + 0.1}, False),
        ({'s_cost_cpu_seconds': None}, False),
    ],
)
def test_is_accepted_requires_proof_cleanliness_and_an_affordable_cost(over, accepted):
    assert synthetic.is_accepted(row(**over)) is accepted


def test_select_ranks_tighter_cheaper_earlier_rules_first():
    rows = [
        row(text=rule(stars=3), cost=5.0, sha='wide'),
        row(text=rule(stars=1), cost=30.0, sha='tight-slow'),
        row(text=rule(stars=1, name='other'), cost=9.0, round_=2, sha='tight-fast'),
    ]
    out = synthetic.select(rows)
    assert [r['rule_sha'] for r in out] == ['tight-fast', 'tight-slow', 'wide']
    assert [r['stars'] for r in out] == [1, 1, 3]


def test_select_dedupes_identical_rules_and_caps_per_cve():
    same = rule()
    rows = [
        row(text=same, cost=8.0, round_=2, sha='late'),
        row(text=same, cost=8.0, round_=0, sha='early'),  # same rule, cheaper chain
        *[row(text=rule(name=f'f{i}'), cost=10.0 + i, sha=f's{i}') for i in range(5)],
    ]
    out = synthetic.select(rows, per_cve=3)
    assert len(out) == 3
    assert out[0]['rule_sha'] == 'early'  # the cheapest path to the shared rule
    assert len({r['rule_text'] for r in out}) == 3


def test_select_carries_provenance_and_stratification_keys():
    shapes = {'CVE-2022-1': shape('CVE-2022-1', kind='changes', year=2021, subsystem='net')}
    out = synthetic.select([row()], shapes)
    assert len(out) == 1
    kept = out[0]
    assert kept['shape'] == 'changes' and kept['year'] == 2021 and kept['subsystem'] == 'net'
    assert kept['files'] == 'fs/x.c'
    # The training target is contract form: no Fix: header.
    assert kept['rule_body'].startswith('/// Files:')
    assert 'Fix:' not in kept['rule_body']
    # The rule ships exactly as scored; the sha names those bytes.
    assert kept['rule_text'] == rule() and kept['rule_sha'] == 'sha1'
    # A row that recorded the model's own body (before Files: completion) ships that as
    # the target; the scored rule keeps the completed line.
    completed = rule().replace('/// Files: fs/x.c', '/// Files: fs/x.c fs/old_x.c')
    own = '/// Files: fs/x.c\n\n@r@\nidentifier f;\n@@\nf(...) {\n...\n*  kfree_the_widget_0(x);\n...\n}\n'
    kept = synthetic.select([row(text=completed, rule_body=own)])[0]
    assert kept['rule_body'] == own and 'old_x.c' in kept['rule_text']


def test_summary_counts_the_funnel_from_attempted_to_kept():
    rows = [
        row(cve='CVE-2022-1'),
        row(cve='CVE-2022-2', s_strong_valid=False),
        row(cve='CVE-2022-3', s_valid=False, s_strong_valid=False),
    ]
    md = synthetic.summary_md(rows, synthetic.select(rows), classes={'CVE-2022-1': 'B'})
    assert '| attempted | 3 | 3 |' in md
    assert '| >=1 valid rule | 2 | 2 |' in md
    assert '| >=1 strong rule | 1 | 1 |' in md
    assert '| accepted (kept) | 1 | 1 |' in md
    assert '| B | 1 |' in md


def test_export_writes_one_rule_per_cve_and_ranks_below_it(tmp_path):
    """CVEhound addresses a rule by CVE id, so ranks past the first need subdirs."""
    rows = synthetic.select(
        [
            row(cve='CVE-2022-1', text=rule(stars=1), cost=5.0, sha='best'),
            row(cve='CVE-2022-1', text=rule(name='other', stars=3), cost=9.0, sha='second'),
            row(cve='CVE-2022-2', text=rule(name='third'), cost=7.0, sha='only'),
        ]
    )
    written = synthetic.export(rows, str(tmp_path), per_cve=1)
    assert sorted(p.name for p in tmp_path.iterdir()) == ['CVE-2022-1.cocci', 'CVE-2022-2.cocci']
    assert len(written) == 2
    # The best rule of a CVE is the one exported, byte for byte as the oracle scored it.
    written = (tmp_path / 'CVE-2022-1.cocci').read_text()
    assert written == rows[0]['rule_text']
    assert '/// Fix: abc' in written and '@r@' in written  # the suite reads the headers

    both = tmp_path / 'both'
    synthetic.export(rows, str(both), per_cve=2)
    assert (both / 'CVE-2022-1.cocci').exists()
    assert (both / '2' / 'CVE-2022-1.cocci').exists()  # the runner-up, own pass
    assert not (both / '2' / 'CVE-2022-2.cocci').exists()  # it had only one


def test_select_merges_siblings_that_only_rename_metavariables():
    """`e` vs `E` is the same rule; a different pattern line is not."""
    hdr = '/// Files: a.c\n/// Fix: abc\n/// Fixes: def\n\n'
    a = hdr + '@r@\nexpression e;\n@@\n*  kfree_the_widget(e);\n'
    b = hdr + '@s@\nexpression   E;\n@@\n*  kfree_the_widget(E);\n'
    c = hdr + '@r@\nexpression e;\n@@\n*  kfree_the_widget(e);\n... when any\n'
    assert synthetic.canonical_form(a) == synthetic.canonical_form(b)
    assert synthetic.canonical_form(a) != synthetic.canonical_form(c)
    out = synthetic.select(
        [row(text=a, sha='a', cost=9.0), row(text=b, sha='b', cost=5.0), row(text=c, sha='c')]
    )
    assert [r['rule_sha'] for r in out] == ['b', 'c']  # the cheaper spelling survives
    assert out[0]['report_key'] == out[1]['report_key']  # same starred line, both kept


def test_canonical_form_ignores_declaration_order():
    """`e` then `f` vs `f` then `e`: the pattern is what matters."""
    a = '/// Files: a.c\n\n@r@\nexpression e;\nidentifier f;\n@@\n*  f(e);\n'
    b = '/// Files: a.c\n\n@r@\nidentifier f;\nexpression e;\n@@\n*  f(e);\n'
    c = '/// Files: a.c\n\n@r@\nidentifier f;\nexpression e;\n@@\n*  e(f);\n'
    assert synthetic.canonical_form(a) == synthetic.canonical_form(b)
    assert synthetic.report_lines(a) == synthetic.report_lines(b)
    assert synthetic.canonical_form(a) != synthetic.canonical_form(c)
