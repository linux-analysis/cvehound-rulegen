"""Record shapes: legs, Scores and corpus rows survive their row form."""

import json

import pyarrow as pa
from helpers import make_example, make_record

from rulegen.schema import (
    FIRE,
    NO_FILES,
    SILENT,
    TRUNCATED,
    CveRecord,
    ExampleRecord,
    Leg,
    Score,
    ScoreRequest,
    branch_of_ref,
    leg_from_row,
)


def test_leg_kind_and_ref_are_derived_from_the_name():
    backport = Leg('bp:stable/linux-6.6.y@' + 'a' * 40, SILENT)
    assert (backport.kind, backport.ref) == ('bp', 'stable/linux-6.6.y@' + 'a' * 40)
    assert branch_of_ref(backport.ref) == 'stable/linux-6.6.y' and backport.gating
    assert Leg('bp~:stable/linux-6.6.y@' + 'a' * 40, FIRE).kind == 'bp~'
    head = Leg('head:next/master@' + 'b' * 40, SILENT, FIRE)
    assert head.kind == 'head' and not head.gating and not head.ok
    assert (
        Leg('range:v6.1', FIRE).kind == 'range' and Leg('tree:next/master', SILENT).kind == 'tree'
    )
    core = Leg('fix~', FIRE)
    assert (core.kind, core.ref) == ('core', 'fix~')
    # No files at a ref that must be silent is the silence test_01 accepts; it never fires.
    assert Leg('init', SILENT, NO_FILES).ok and not Leg('fix~', FIRE, NO_FILES).ok
    # Rows written before the fields existed still deserialize.
    assert Leg(**{'name': 'decoy:mm/slub.c', 'expect': SILENT, 'verdict': SILENT}).kind == 'decoy'


def test_score_to_row_round_trips_through_arrow():
    score = Score(cve='CVE-2024-1', rule_sha='ab' * 32, rule_path='x.cocci')
    score.legs = [Leg('fix~', FIRE, FIRE, 0.1), Leg('tree:origin/master', SILENT, FIRE, 2.0)]
    score.t1_stderr = 'minus_token_at_line 3'
    score.t5_points, score.t5_fired = 4, 3
    score.cost_cpu_seconds = 1.25
    row = score.to_row()
    table = pa.Table.from_pylist([row])
    back = table.to_pylist()[0]
    assert back['t5_points'] == 4 and back['t5_fired'] == 3
    assert back['cost_cpu_seconds'] == 1.25
    assert back['strong_valid'] is False
    legs = json.loads(back['legs'])
    assert [leg['name'] for leg in legs] == ['fix~', 'tree:origin/master']
    assert score.leg('tree:origin/master').ok is False


def test_unscored_is_a_zero_placeholder():
    score = Score.unscored('CVE-2024-2', 'no rule here\n', 'contract', 'x' * 5000)
    assert score.valid is False and score.strong_valid is False
    assert score.reward == 0.0
    assert score.fail_class == 'contract'
    assert len(score.rule_sha) == 64
    # The harness's reason lives in `note`; t1_stderr stays spatch's own output.
    assert len(score.note) == 2000 and score.t1_stderr == ''


def test_leg_detail_round_trips_and_answers_carry_none():
    score = Score(cve='CVE-2022-50071', rule_sha='ab' * 32)
    why = 'dropped net/mptcp/protocol.c: Failure("input_value: truncated object")'
    score.legs = [
        Leg('fix~', FIRE, FIRE, 0.1),
        Leg('tree:stable/linux-5.15.y@' + 'a' * 40, SILENT, TRUNCATED, 2.0, detail=why),
    ]
    score.truncated_legs = 1
    back = pa.Table.from_pylist([score.to_row()]).to_pylist()[0]
    raw = json.loads(back['legs'])
    # An answer leaves the key out: a log of 10^5 rows does not pay for it per leg.
    assert 'detail' not in raw[0] and raw[1]['detail'] == why
    again = Score.from_row(back)
    assert again.legs[1].detail == why and again.legs[0].detail == ''
    assert again.truncated_legs == 1


def test_rows_from_other_schema_versions_load():
    # Older: no detail, no truncated_legs. Newer: a leg key this version does not know.
    old = Score.from_row(
        {
            'cve': 'C',
            'rule_sha': 'x',
            'legs': json.dumps(
                [
                    {'name': 'fix~', 'expect': FIRE, 'verdict': FIRE, 'seconds': 0.1},
                ]
            ),
        }
    )
    assert old.legs[0].detail == '' and old.truncated_legs is None
    newer = leg_from_row({'name': 'fix', 'expect': SILENT, 'verdict': SILENT, 'from_the_future': 1})
    assert newer.name == 'fix' and newer.ok


def test_corpus_and_example_rows_round_trip():
    rec = make_record('CVE-2024-1', backports={'stable/linux-6.1.y': 'a' * 40}, meta_issues=['x'])
    assert CveRecord.from_row(rec.to_row()) == rec
    example = make_example()
    assert ExampleRecord.from_row(example.to_row()) == example
    # A null JSON column (a row from before the column existed) keeps the default.
    assert CveRecord.from_row({**rec.to_row(), 'backports': None}).backports == {}


def test_a_score_request_carries_the_corpus_commits_and_sorted_backports():
    rec = make_record(
        'CVE-2024-1', backports={'stable/linux-6.6.y': 'b', 'stable/linux-6.1.y': 'a'}
    )
    req = ScoreRequest.for_record(rec, 'rule')
    assert (req.cve, req.fix, req.fixes, req.initial_epoch) == (
        'CVE-2024-1',
        'f' * 40,
        'e' * 40,
        False,
    )
    assert req.backports == (('stable/linux-6.1.y', 'a'), ('stable/linux-6.6.y', 'b'))
    assert rec.cocci_rule is False and make_record('C', rule_path='/r/C.cocci').cocci_rule
