"""What the test modules share: builders, fakes and sample rules.

Imported as `import helpers` (pytest puts tests/ on the path). Fixtures live in
the modules that use them.
"""

import os

import pytest

from rulegen import corpus
from rulegen.schema import CveRecord, ExampleRecord

FIX, FIXES = 'f' * 40, 'e' * 40  # the fix and introducing commits of every fixture CVE
SHA1, SHA2 = 'a' * 40, 'b' * 40
B61, B510 = 'stable/linux-6.1.y', 'stable/linux-5.10.y'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
KERNEL = os.environ.get('CVEHOUND_KERNEL', os.path.join(ROOT, '..', 'cvehound', 'tests', 'linux'))
CVEHOUND = os.environ.get('CVEHOUND_REPO', os.path.join(ROOT, '..', 'cvehound'))
needs_kernel = pytest.mark.skipif(
    not os.path.isdir(os.path.join(KERNEL, '.git')), reason='needs the cvehound kernel clone'
)


def read_diff(name: str) -> str:
    with open(os.path.join(FIXTURES, 'diffs', f'{name}.diff')) as fh:
        return fh.read()


# -W excerpts of real fixes. In ADDS the @@ trailer names the *preceding*
# function (ovl_copy_up_meta_inode_data); the change is inside ovl_copy_up_one.
ADDS = read_diff('adds')
REMOVES = read_diff('removes')
CHANGES = read_diff('changes')  # braces inside a comment and a string literal

# A rule in contract form: Files: and the pattern, no commit headers.
KFREE = '/// Files: net/foo.c\n@r@\n@@\nfoo_release(...)\n{\n*\tkfree(sk);\n}\n'
# Nothing literal anywhere: any function, any expression.
ECHO_RULE = '/// Files: a.c\n@r@\nidentifier f;\nexpression e;\n@@\nf(...)\n{\n*\treturn -e;\n}\n'
# Only vocabulary on the starred line, but `foo` anchors it: a legitimate shape.
ANCHORED_ECHO = '/// Files: a.c\n@r@\nexpression e;\n@@\nfoo(...)\n{\n*\treturn -e;\n}\n'
# The report calls "some function": the E-class wildcard.
WILDCARD_RULE = '/// Files: a.c\n@r@\nidentifier f;\n@@\nfoo(...)\n{\n*\tf(sk);\n}\n'


def make_example(cve: str = 'CVE-2024-00000', **overrides) -> ExampleRecord:
    """A model input for net/foo.c; the gold path is one no prompt may show."""
    fields = {
        'cve': cve,
        'fix': FIX,
        'fixes': FIXES,
        'initial_epoch': False,
        'msg_subject': 'net: fix a use-after-free in foo',
        'msg_stripped': 'net: fix a use-after-free in foo\n\nThe bug is here.\n',
        'syzbot': False,
        'diff_a': '--- a/net/foo.c\n+++ b/net/foo.c\n-\tkfree(sk);\n',
        'diff_b': 'diff --git a/net/foo.c b/net/foo.c\n@@ -1,3 +1,2 @@\n-\tkfree(sk);\n',
        'diff_c': 'diff --git a/net/foo.c b/net/foo.c\n@@ foo_release @@\n-\tkfree(sk);\n',
        'diff_fallback_unrestricted': False,
        'files_candidates': ['net/foo.c'],
        'files_gold': ['secret/gold_path.c'],
        'historical_names': {'net/foo.c': ['net/old_foo.c']},
        'intermediate': ['abcd123 net: refactor foo'],
        'historical_symbols': ['old_release_fn'],
        'survival_map': ['old_release_fn: present v4.4; absent v6.6'],
        'size_stats': {},
    }
    return ExampleRecord(**{**fields, **overrides})


def make_record(cve: str, split: str = 'val', **overrides) -> CveRecord:
    """A corpus row with an agreed fix and introducing commit."""
    return CveRecord(
        **{
            'cve': cve,
            'fix': FIX,
            'fixes': FIXES,
            'fixes_kind': 'fixes',
            'split': split,
            **overrides,
        }
    )


def write_corpus(data_dir: str, records: list[CveRecord]) -> None:
    corpus.save_corpus(records, os.path.join(data_dir, corpus.CORPUS))
