"""Context-tier classification.

The fast tests pin the token extractor, which is the part that carries the
measurement's meaning: 'literal token' must mean 'name this rule cannot match
without', not 'identifier that appears in the file'.

The slow tests classify the gold corpus at a pinned cvehound revision against
the pinned tier table, so a refactor cannot quietly change what the
classification says, and check the kernel vocabulary against the kernel.
"""

import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from helpers import (
    ANCHORED_ECHO,
    CVEHOUND,
    ECHO_RULE,
    FIXTURES,
    KERNEL,
    WILDCARD_RULE,
    needs_kernel,
)

from rulegen import corpus, tiers
from rulegen.git import git, git_run
from rulegen.vocabulary import VOCABULARY

RULE = """\
/// Files: drivers/foo.c
/// Fix: deadbeef


@err@
identifier skb, len;
symbol GFP_KERNEL;
@@

vulnerable_fn(..., struct sk_buff *skb, ...)
{
	...
*	kmalloc(len, GFP_KERNEL);
	... when != kfree(skb)
}
"""

# The same shape over names outside the kernel vocabulary, so the tests below pin
# how declarations, starred lines and `when` clauses are read, independently of
# the vocabulary gate.
NAMED_RULE = (
    RULE.replace('symbol GFP_KERNEL;', 'symbol FOO_GFP;')
    .replace('kmalloc(len, GFP_KERNEL);', 'foo_alloc(len, FOO_GFP);')
    .replace('kfree(skb)', 'foo_release(skb)')
)


@pytest.mark.parametrize(
    ('text', 'present', 'absent'),
    [
        # A declared identifier matches anything; a spelled-out type is a token spatch requires.
        (RULE, {'vulnerable_fn', 'sk_buff'}, {'skb', 'len'}),
        # `symbol` matches literally; a `when !=` name is text the author had to know.
        (NAMED_RULE, {'FOO_GFP', 'foo_release'}, set()),
        # `identifier list;` declares a metavariable named list.
        (
            RULE.replace('identifier skb, len;', 'identifier list;\nidentifier skb, len;').replace(
                'kmalloc(len,', 'kmalloc(list,'
            ),
            set(),
            {'list'},
        ),
        # Comments and numeric literals are not tokens.
        (
            RULE.replace(
                '*\tkmalloc(len, GFP_KERNEL);',
                '*\tkmalloc(0xdeadbe, GFP_KERNEL); // trailing comment_word\n\t/* block_word */',
            ),
            set(),
            {'comment_word', 'block_word', 'deadbe'},
        ),
        # Kernel vocabulary is not context; a name the author must look up is.
        (
            RULE.replace(
                '*\tkmalloc(len, GFP_KERNEL);', '*\tkmalloc(len, GFP_KERNEL);\n\tfoo_bar();'
            ),
            {'foo_bar'},
            {'kmalloc', 'GFP_KERNEL'},
        ),
    ],
)
def test_literal_tokens(text, present, absent):
    tokens, _ = tiers.literal_tokens(text)
    assert present <= tokens and not absent & tokens


def test_star_tokens_are_the_starred_lines_only():
    _, star = tiers.literal_tokens(NAMED_RULE)
    assert star == {'foo_alloc', 'FOO_GFP'}  # not vulnerable_fn, not foo_release


def test_changed_lines_strips_diff_prefixes_and_headers():
    out = tiers._changed_lines('+++ b/foo.c\n@@ -1,0 +1,1 @@\n+added_call();\n-removed_call();\n')
    assert out == 'added_call();\nremoved_call();'


# -- what the text says about the bug (reward terms and degenerate flags) --------

# A metavariable head in a helper block, bound by a literal call in its body, is not
# a wildcard (CVE-2016-4568); only the reporting block's anchor counts.
HELPER = (
    '/// Files: a.c\n@check@\nidentifier core;\n@@\ncore(...)\n{\n\t...\n\tverify(vb)\n\t...\n}\n'
    '@err depends on check@\nsymbol ops;\n@@\n*struct buf_ops ops = {\n\t...\n};\n'
)
# `identifier c.f;` inherits f from rule c: a starred `f(sk)` is still a wildcard.
INHERITED = (
    '@c@\nidentifier f;\n@@\nf(...) { ... bar(x); ... }\n'
    '@r depends on c@\nidentifier c.f;\n@@\nfoo(...)\n{\n*\tf(sk);\n}\n'
)


@pytest.mark.parametrize(
    ('text', 'wildcards'),
    [
        (WILDCARD_RULE, ['f']),  # the report calls "some function"
        (ECHO_RULE, ['f']),  # a metavariable anchor with nothing literal in the block
        # A metavariable field or argument is a renamed name, not a wildcard.
        ('/// Files: a.c\n@r@\nidentifier fn;\n@@\nfoo(...)\n{\n*\tops->fn(sk);\n}\n', []),
        ('/// Files: a.c\n@r@\nexpression e;\n@@\nfoo(...)\n{\n*\tbar(e);\n}\n', []),
        # A position annotation is not a callee (CVE-2020-27777 stars `rtas_initialize@p(void)`).
        ('/// Files: a.c\n@r@\nposition p;\n@@\n*\trtas_initialize@p(void)\n{\n\t...\n}\n', []),
        (HELPER, []),
        (INHERITED, ['f']),
    ],
)
def test_wildcard_stars_name_metavariables_where_a_name_belongs(text, wildcards):
    assert tiers.wildcard_stars(text) == wildcards


@pytest.mark.parametrize(
    ('text', 'anchored'),
    [
        (ANCHORED_ECHO, True),  # the whole rule counts, not only its starred lines
        (ECHO_RULE, False),
        ('/// Files: a.c\n@r@\nexpression e;\n@@\n*\tkfree(e);\n', False),  # vocabulary only
        # An anonymous rule opens with `@@` too: its declarations are not pattern text.
        ('@@\nidentifier f;\nexpression e;\n@@\nf(...)\n{\n*\treturn -e;\n}\n', False),
        ('@@\nexpression e;\n@@\nfoo(...)\n{\n*\treturn -e;\n}\n', True),
    ],
)
def test_literal_anchor(text, anchored):
    assert tiers.has_literal_anchor(text) is anchored


# -- against the kernel ----------------------------------------------------------------

# The corpus the fixture was taken from (cvehound 1.6.1). The test must classify
# *those* rule bytes, not the working tree's -- otherwise it stops testing the
# classifier and starts merely detecting that the corpus moved on, which is what
# the tier column itself is for.
BASELINE_REV = 'ecafe2755c65'


@needs_kernel
def test_every_vocabulary_entry_is_a_real_kernel_name():
    """A hand-written list acquires typos; this is the guard.

    Two revisions, because entries like `strlcpy`, `kzfree` and `FIELD_SIZEOF`
    were real for most of the corpus era and have since been removed.
    """
    pattern = r'\b(' + '|'.join(sorted(VOCABULARY)) + r')\b'
    seen: set[str] = set()
    for rev in ('origin/master', 'v4.9'):
        out = git(KERNEL, 'grep', '-h', '-o', '-E', pattern, rev, '--', 'include/', ok=None)
        seen |= {line.split(':', 1)[-1] for line in out.split('\n') if line}
    assert not VOCABULARY - seen, f'not kernel names: {sorted(VOCABULARY - seen)}'


@needs_kernel
def test_corpus_reproduces_the_tier_table(tmp_path):
    """The gold rules at BASELINE_REV classify exactly as the pinned table says."""
    if git_run(CVEHOUND, 'cat-file', '-e', f'{BASELINE_REV}^{{commit}}').returncode:
        pytest.skip(f'the cvehound checkout lacks {BASELINE_REV}')
    with open(os.path.join(FIXTURES, 'tier_baseline.json')) as fh:
        expected = json.load(fh)

    def classify(name):
        path = tmp_path / os.path.basename(name)
        path.write_text(git(CVEHOUND, 'show', f'{BASELINE_REV}:{name}'))
        header = corpus.parse_rule_header(str(path))
        cve = os.path.basename(name).removesuffix('.cocci')
        return cve, tiers.classify_rule(KERNEL, cve, str(path), header['fix'], header['files']).cls

    names = git(CVEHOUND, 'ls-tree', '-r', '--name-only', BASELINE_REV, 'cvehound/cve/').split()
    with ThreadPoolExecutor(16) as pool:
        got = dict(pool.map(classify, [n for n in names if n.endswith('.cocci')]))
    assert got == expected
