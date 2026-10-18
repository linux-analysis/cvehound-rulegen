"""The repair loop with a scripted adapter and a scorer keyed on the rule text: no spatch."""

from helpers import KFREE, FakeScorer, fenced, run_config, run_harness, write_data

from rulegen.gen.adapters.base import GenRequest
from rulegen.gen.adapters.fake import FakeAdapter
from rulegen.gen.feedback import CRITIQUE_PROMPT
from rulegen.schema import FIRE, SILENT, Leg, Score, ScoreRequest

GOOD = fenced(KFREE)
BAD = fenced(KFREE.replace('foo_release(...)', 'foo(...)').replace('kfree(sk)', 'return -EINVAL'))
# A semantic patch: `-`/`+` lines the canon transform rewrites into detection form.
PATCH = fenced(KFREE.replace('*\tkfree(sk);', '-\tfoo_bar(sk);\n+\tfoo_baz(sk);'))
BP = f'stable/linux-6.6.y@{"b" * 40}'


def by_text(req: ScoreRequest) -> Score:
    """Valid iff the rule stars kfree(sk); otherwise it fires at the fix (and backport) too."""
    good = 'kfree(sk)' in req.rule_text
    score = Score(cve=req.cve, rule_sha='x', valid=good, reward=1.0 if good else 0.45)
    score.legs = [
        Leg('fix~', FIRE, FIRE),
        Leg('fix', SILENT, SILENT if good else FIRE),
        Leg(f'bp:{BP}', SILENT, SILENT if good else FIRE),
    ]
    return score


def strong_by_head(req: ScoreRequest) -> Score:
    """Valid on the starred kfree; strong only once the rule is anchored in a head."""
    score = by_text(req)
    score.strong_valid = score.valid and 'foo_release' in req.rule_text
    if score.valid and not score.strong_valid:
        score.legs.append(Leg(f'tree:{BP}', SILENT, FIRE))
    return score


def script(req: GenRequest, _index: int) -> str:
    return GOOD if req.round >= 2 else BAD


def pipeline_config(tmp_path, feedback: str, **overrides):
    """Two chains of up to three repair rounds, run id `pipe-<feedback>`."""
    pipeline = {
        'run_id': f'pipe-{feedback}',
        'mode': 'pipeline',
        'model': {'adapter': 'fake', 'concurrency': 2},
        'pipeline': {'attempts': 2, 'rounds': 3, 'feedback': feedback},
    }
    return run_config(str(tmp_path / 'runs'), **{**pipeline, **overrides})


def repair_turns(adapter: FakeAdapter) -> list[list[dict]]:
    return [c.messages for c in adapter.calls if len(c.messages) == 4]


def test_oracle_feedback_repairs_by_round_two(tmp_path):
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    adapter, scorer = FakeAdapter(script), FakeScorer(by_text)
    totals, rows = run_harness(tmp_path, pipeline_config(tmp_path, 'oracle'), adapter, scorer)
    # 2 attempts x rounds 0,1,2 = 6 rows; both chains valid at round 2; no round 3.
    assert totals['n_rows'] == 6 and totals['n_cves_valid'] == 1 and totals['n_valid_chains'] == 2
    by = {(r['sample_index'], r['round']): r for r in rows}
    assert by[(0, 2)]['s_valid'] is True and by[(0, 1)]['s_valid'] is False
    assert by[(0, 1)]['parent_attempt_id'] == by[(0, 0)]['attempt_id']
    assert by[(0, 0)]['tokens_cum'] < by[(0, 1)]['tokens_cum'] < by[(0, 2)]['tokens_cum']
    # Each round is a fixed offset from the chain's base seed, and the row records what was sent.
    base = by[(0, 0)]['seed']
    assert (by[(0, 1)]['seed'], by[(0, 2)]['seed']) == (base + 7, base + 14)
    assert {c.seed for c in adapter.calls} == {r['seed'] for r in rows}
    # The oracle turn names the failed legs; the second copy of the BAD rule reused the Score.
    round1 = next(c.messages for c in adapter.calls if c.round == 1)
    assert 'ALSO fires on the fixed code' in round1[-1]['content']
    assert 'stable/linux-6.6.y' in round1[-1]['content']
    # The last reply is carried as the rule alone, in contract form.
    assert round1[-2]['role'] == 'assistant'
    assert round1[-2]['content'].startswith('```\n/// Files: net/foo.c')
    assert '/// Fix:' not in round1[-2]['content']
    # Round 2 sees system + task + one (reply, feedback) pair, not the whole history.
    round2 = next(c.messages for c in adapter.calls if c.round == 2)
    assert len(round2) == 4 and round2[:2] == round1[:2]
    assert len(scorer.requests) == 2  # BAD once (deduped across attempts and rounds), GOOD once


def test_critique_arm_carries_no_oracle_information(tmp_path):
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    adapter = FakeAdapter(script)
    run_harness(tmp_path, pipeline_config(tmp_path, 'critique'), adapter, FakeScorer(by_text))
    turns = [messages[-1]['content'] for messages in repair_turns(adapter)]
    assert turns and all(turn == CRITIQUE_PROMPT for turn in turns)


def test_transform_canonicalizes_before_scoring_and_shows_what_was_judged(tmp_path):
    """A patch-style reply is scored in detection form, and the repair turn says so."""
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    adapter = FakeAdapter(lambda req, _i: PATCH if req.round == 0 else GOOD)
    scorer = FakeScorer(by_text)
    cfg = pipeline_config(tmp_path, 'oracle', transform='canon')
    _totals, rows = run_harness(tmp_path, cfg, adapter, scorer)
    first = next(r for r in rows if r['round'] == 0)
    assert first['transform_applied'] is True
    # The model wrote `-`/`+`; the oracle saw starred lines.
    assert '-\tfoo_bar(sk);' in first['completion_text']
    assert '*\tfoo_bar(sk);' in first['rule_text']
    assert all('-\tfoo_bar(sk);' not in req.rule_text for req in scorer.requests)
    reply, repair = repair_turns(adapter)[0][-2:]
    # The assistant turn carries the judged (rewritten) rule, once, in contract form:
    # the headers the harness inserted (and the model must not emit) stay out.
    assert '*\tfoo_bar(sk);' in reply['content'] and '/// Fix:' not in reply['content']
    assert 'rewritten into detection form' in repair['content']
    assert '*\tfoo_bar(sk);' not in repair['content']
    # The plain reply that follows needs no such note.
    assert next(r for r in rows if r['round'] == 1)['transform_applied'] is False


def test_accept_strong_keeps_repairing_a_valid_but_weak_rule(tmp_path):
    """With accept: valid the chain would stop at round 0; strong repairs T6."""
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    # Round 0 is valid but not strong (no function head); round 1 fixes that.
    weak = GOOD.replace('foo_release(...)', 'f(...)')
    adapter = FakeAdapter(lambda req, _i: weak if req.round == 0 else GOOD)
    cfg = pipeline_config(
        tmp_path,
        'oracle',
        run_id='pipe-strong',
        pipeline={'attempts': 1, 'rounds': 3, 'feedback': 'oracle', 'accept': 'strong'},
        oracle={'jobs': 1, 'run_tree': True},
    )
    totals, rows = run_harness(tmp_path, cfg, adapter, FakeScorer(strong_by_head))
    rows.sort(key=lambda r: r['round'])
    assert [r['round'] for r in rows] == [0, 1]  # round 0 was valid, but not accepted
    assert rows[0]['s_valid'] is True and rows[0]['s_strong_valid'] is False
    assert rows[1]['s_strong_valid'] is True
    assert totals['n_valid_chains'] == totals['n_accepted_chains'] == 1
    assert totals['n_cves_valid'] == totals['n_cves_accepted'] == 1
    # The repair turn named the whole-tree failure.
    assert 'whole-tree scan at the backport commit fires' in repair_turns(adapter)[0][-1]['content']
