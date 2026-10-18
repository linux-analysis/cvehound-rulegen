"""Byte-identical prompts per policy and budget, and the model output contract."""

import pytest
from helpers import FIX, FIXES, make_example

from rulegen.promptbuild import (
    CANDIDATES_CAP,
    HISTORY_CAP,
    MSG_CAP,
    POLICIES,
    _cap_diff,
    build_prompt,
    cap_paragraphs,
    cut_trace,
    finalize_rule,
    parse_rule_output,
)


@pytest.mark.parametrize('policy', list(POLICIES))
def test_every_policy_builds_the_same_bytes_twice(policy):
    a, b = build_prompt(make_example(), policy), build_prompt(make_example(), policy)
    assert a.text and a.text == b.text and a.sha256 == b.sha256


def test_policies_add_sections_monotonically():
    ex = make_example()
    b = build_prompt(ex, 'P-B').text
    c2 = build_prompt(ex, 'P-M').text
    h = build_prompt(ex, 'P-H').text
    assert 'Fix commit message' not in b
    assert 'Fix commit message' in c2
    assert 'Symbol presence' not in c2
    assert 'Symbol presence' in h
    assert 'old_release_fn' in h  # the class-E hint reaches the prompt


def test_hide_cve_id_removes_the_id():
    ex = make_example()
    shown = build_prompt(ex, 'P-M', hide_cve_id=False).text
    hidden = build_prompt(ex, 'P-M', hide_cve_id=True).text
    assert 'CVE-2024-00000' in shown
    assert 'CVE-2024-00000' not in hidden


def test_initial_epoch_note():
    ex = make_example(initial_epoch=True, fixes=None)
    assert 'present since the start of git history' in build_prompt(ex, 'P-B').text


def test_parse_rule_output_from_fence():
    completion = (
        'Here is the rule:\n```cocci\n/// Files: net/foo.c\n@err@\n@@\n\n* kfree(sk);\n```\n'
    )
    body = parse_rule_output(completion)
    assert body is not None
    assert body.startswith('/// Files: net/foo.c')
    assert '@err@' in body


def test_parse_rule_output_rejects_prose():
    assert parse_rule_output('I think you should match kfree(sk).') is None


def test_finalize_completes_files_with_their_earlier_names():
    body = '/// Files: net/foo.c net/bar.c\n@err@\n@@\n* kfree(sk);\n'
    history = {'net/foo.c': ['net/old_foo.c', 'net/older_foo.c'], 'net/unlisted.c': ['x.c']}
    out = finalize_rule(body, FIX, FIXES, 'fixes', history)
    assert out.splitlines()[0] == '/// Files: net/foo.c net/old_foo.c net/older_foo.c net/bar.c'
    # Idempotent, and a model that wrote the old name itself adds nothing.
    again = finalize_rule(out, FIX, FIXES, 'fixes', history)
    assert again == out
    assert finalize_rule(body, FIX, FIXES, 'fixes', None).startswith(
        '/// Files: net/foo.c net/bar.c\n'
    )


def test_finalize_inserts_headers_after_files():
    body = '/// Files: net/foo.c\n@err@\n@@\n\n* kfree(sk);\n'
    out = finalize_rule(body, FIX, FIXES, 'fixes')
    lines = out.splitlines()
    assert lines[0] == '/// Files: net/foo.c'
    assert f'/// Fix: {FIX}' in lines
    assert f'/// Fixes: {FIXES}' in lines
    assert lines.index('/// Files: net/foo.c') < lines.index('@err@')


def test_finalize_strips_model_emitted_headers():
    body = '/// Files: net/foo.c\n/// Fix: deadbeef\n/// Version: 1.1.0\n@err@\n@@\n* x();\n'
    out = finalize_rule(body, FIX, None, None)
    assert 'deadbeef' not in out
    assert '/// Version: 1.1.0' not in out
    assert f'/// Fix: {FIX}' in out


def test_finalize_detect_to_kind():
    body = '/// Files: net/foo.c\n@err@\n@@\n* x();\n'
    out = finalize_rule(body, FIX, FIXES, 'detect-to')
    assert f'/// Detect-To: {FIXES}' in out


def test_finalize_leaves_virtual_declarations_for_t0():
    """finalize_rule normalises nothing: a `virtual` line stays, so T0 rejects it as the suite would."""
    body = '/// Files: net/foo.c\n\n@r@\n@@\nfoo(...)\n{\n*\tkfree(sk);\n}\n'
    out = finalize_rule(body, FIX, FIXES, 'fixes')
    assert out.startswith(
        '/// Files: net/foo.c\n/// Fix: ' + FIX + '\n/// Fixes: ' + FIXES + '\n\n@r@\n'
    )
    with_it = finalize_rule(
        '/// Files: net/foo.c\nvirtual detect\n\n@r@\n@@\n*\tx;\n', FIX, None, None
    )
    assert 'virtual detect' in with_it and '/// Fix: ' in with_it


# -- the whole-turn budget ------------------------------------------------------


def words(n: int, word: str = 'lorem') -> str:
    return ' '.join(f'{word}{i}' for i in range(n))


def test_subject_is_not_repeated_in_the_message():
    ex = make_example()
    text = build_prompt(ex, 'P-M').text
    assert text.count('net: fix a use-after-free in foo') == 1
    assert '## Fix commit message\nThe bug is here.' in text


def test_cve_id_is_masked_in_subject_and_message_when_hidden():
    ex = make_example(
        msg_subject='net: fix CVE-2024-00000 in foo',
        msg_stripped='net: fix CVE-2024-00000 in foo\n\nSee CVE-2024-00000 and CVE-2020-1234.\n',
    )
    hidden = build_prompt(ex, 'P-M', hide_cve_id=True).text
    assert 'CVE-2024-00000' not in hidden and 'CVE-2020-1234' not in hidden
    assert hidden.count('CVE-XXXX-XXXX') == 3
    assert 'CVE-2020-1234' in build_prompt(ex, 'P-M', hide_cve_id=False).text


def test_trace_is_cut_first_when_the_message_overruns():
    body, cut = cut_trace('Prose.\n\nBUG: KASAN: use-after-free in foo\nCall Trace:\n x\n y\n')
    assert cut and body.startswith('Prose.') and '[trace omitted: 4 lines]' in body
    assert cut_trace('nothing pasted here\n') == ('nothing pasted here\n', False)
    trace = 'The bug.\n\n' + '[  12.345678] BUG: bad\n' + 'Call Trace:\n' + ' frame\n' * 3000
    ex = make_example(msg_stripped='net: fix a use-after-free in foo\n\n' + trace)
    out = build_prompt(ex, 'P-M', budget_tokens=4000)
    assert 'message-trace' in out.truncated and 'trace omitted' in out.text
    assert out.token_estimate <= 4000
    assert 'diff' not in out.truncated  # the diff kept its floor untouched


def test_long_prose_is_capped_at_paragraphs_then_candidates_then_diff():
    capped, cut = cap_paragraphs('a\n\nb\n\nc', cap=6, count=lambda t: len(t))
    assert cut and capped == 'a\n\nb\n\n[message truncated: 1 paragraphs]\n'
    prose = '\n\n'.join(words(300, f'p{i}w') for i in range(20))
    ex = make_example(
        msg_stripped='net: fix a use-after-free in foo\n\n' + prose,
        files_candidates=[f'drivers/x/f{i}.c' for i in range(200)],
        diff_c='diff --git a/net/foo.c b/net/foo.c\n' + '@@ h @@\n-\tx();\n' * 400,
    )
    out = build_prompt(ex, 'P-M', budget_tokens=3000)
    assert out.truncated[:3] == ['message', 'candidates', 'diff']
    assert '[160 more candidate paths omitted]' in out.text
    assert out.sections['message'] <= MSG_CAP + 50
    assert out.text.count('drivers/x/f') == CANDIDATES_CAP
    assert out.token_estimate <= 3000 + 1000  # the diff floor is the only allowed overrun


def test_no_trimming_when_everything_fits():
    out = build_prompt(make_example(), 'P-H', budget_tokens=8192)
    assert out.truncated == [] and set(out.sections) >= {'header', 'diff', 'candidates', 'survival'}


def test_a_fix_touching_hundreds_of_files_stays_inside_the_diff_budget():
    one = 'diff --git a/d/f{i}.c b/d/f{i}.c\n@@ -1 +1 @@\n-\told{i}();\n+\tnew{i}();\n'
    diff = ''.join(one.format(i=i) for i in range(300))
    capped, cut = _cap_diff(diff, 1000, lambda t: len(t) // 4)
    assert cut and len(capped) // 4 <= 1000 + 60
    assert 'more files, starting at d/f' in capped
    # P-H on such a fix: the historical-names section joins the ladder.
    ex = make_example(
        diff_c=diff,
        files_candidates=[f'd/f{i}.c' for i in range(300)],
        historical_names={f'd/f{i}.c': [f'old/f{i}.c'] for i in range(120)},
    )
    out = build_prompt(ex, 'P-H', budget_tokens=2000)
    assert 'historical names' in out.truncated and 'more renamed files omitted' in out.text
    assert out.text.count(': previously') == HISTORY_CAP
    assert out.token_estimate <= 2000 + 1000  # the diff floor is the only allowed overrun
