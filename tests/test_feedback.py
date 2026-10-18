"""The repair turn's oracle feedback: what failed, in words a model can act on."""

from helpers import B61, SHA1, make_example

from rulegen.gen.feedback import CRITIQUE_PROMPT, render_feedback
from rulegen.schema import FIRE, NO_FILES, SILENT, TIMEOUT, TRUNCATED, Leg, Score

EXAMPLE = make_example('CVE-2023-0002')


def feedback(**fields) -> str:
    return render_feedback(Score(cve=EXAMPLE.cve, rule_sha='x', **fields), EXAMPLE)


def test_feedback_never_leaks_gold_paths_and_covers_no_files():
    text = feedback(legs=[Leg('fix~', FIRE, NO_FILES), Leg('fix', SILENT, NO_FILES)])
    assert 'None of your `Files:` paths exist' in text and 'net/foo.c' in text
    assert 'secret/gold_path.c' not in text


def test_a_parse_failure_quotes_spatch():
    text = feedback(fail_class='parse', t1_stderr='minus: parse error:\n  line 12')
    assert 'spatch --parse-cocci' in text and 'line 12' in text


def test_the_text_terms_get_their_own_repair_hints():
    text = feedback(t0_anchored=False, t0_wildcards=['f'])
    assert 'names nothing of the vulnerable code' in text
    assert '`f` stands where a function name' in text


def test_an_unfinished_check_reads_as_unfinished():
    """A truncated or timed-out leg has no answer: it must not read as "did NOT fire"
    or "fires on N stable branches", and a truncation is not the rule's fault."""
    text = feedback(fail_class=TRUNCATED, legs=[Leg('fix~', FIRE, TRUNCATED)])
    assert 'not in the rule' in text and 'Submit the rule again' in text
    text = feedback(
        legs=[
            Leg('fix~', FIRE, FIRE),
            Leg(f'bp~:{B61}@{SHA1}', FIRE, TRUNCATED),
            Leg(f'tree:{B61}@{SHA1}', SILENT, TIMEOUT),
        ]
    )
    assert '2 check(s) did not complete (timeout 1, truncated 1)' in text
    assert 'too expensive' in text and 'fault on our side' in text
    assert 'did NOT fire on the vulnerable code of' not in text
    assert 'whole-tree scan at the backport commit fires' not in text


def test_the_critique_control_carries_no_oracle_information():
    for word in ('fires', 'branch', 'decoy', 'stable/linux'):
        assert word not in CRITIQUE_PROMPT
