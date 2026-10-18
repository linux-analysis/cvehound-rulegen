"""Identifier extraction and the dependency-free token estimate."""

import pytest

from rulegen import tokens


@pytest.mark.parametrize(
    ('text', 'present', 'absent'),
    [
        # C keywords and names under three characters are not identifiers.
        ('if (foo_bar) return kfree(x);', {'foo_bar', 'kfree'}, {'if', 'return', 'x'}),
        # Neither is SmPL markup.
        ('... when != memset(&var, 0, sizeof(var))', {'memset', 'var'}, {'when'}),
    ],
)
def test_identifiers_drop_keywords_and_short_names(text, present, absent):
    ids = tokens.identifiers(text)
    assert present <= set(ids) and not absent & set(ids)


def test_approx_token_count_is_positive_and_grows():
    assert tokens.approx_token_count('a') >= 1
    assert tokens.approx_token_count('a' * 700) > tokens.approx_token_count('a' * 70)
