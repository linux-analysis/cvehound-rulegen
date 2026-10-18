"""The system prompt and the chat messages built around the user turn."""

import pytest
from helpers import make_example

from rulegen.gen.prompts import DEFAULT_SYSTEM_PROMPT, SYSTEM_PROMPTS, build_messages, system_sha
from rulegen.promptbuild import POLICIES


def test_the_system_prompt_states_the_rule_contract():
    assert list(SYSTEM_PROMPTS) == [DEFAULT_SYSTEM_PROMPT] == ['sys-v1']
    text = SYSTEM_PROMPTS['sys-v1']
    assert 'virtual detect' not in text
    assert 'Declare no `virtual` rules' in text and 'no `exists` in a rule header' in text


def test_the_system_prompt_bytes_are_pinned():
    """Editing the text in place would change every run under the same key: bump the key."""
    assert system_sha('sys-v1') == (
        '2f2022eab966a9d6982ca4487a392bddc447eb4a9acc97ca510a3b1911ac16fb'
    )


def test_messages_budget_spends_the_system_prompt_first():
    ex = make_example(diff_c='diff --git a/net/foo.c b/net/foo.c\n' + '@@ h @@\n-\tx();\n' * 2000)
    built = build_messages(ex, 'P-M', 6000)
    assert built.sections['system'] > 0 and 'diff' in built.truncated
    assert built.token_estimate <= 6000 + 60  # user turn built inside budget - system
    assert SYSTEM_PROMPTS['sys-v1'] == built.messages[0]['content']


@pytest.mark.parametrize('policy', list(POLICIES))
def test_gold_paths_never_reach_the_model(policy):
    text = '\n'.join(m['content'] for m in build_messages(make_example(), policy, 8192).messages)
    assert 'secret/gold_path.c' not in text and 'net/foo.c' in text
