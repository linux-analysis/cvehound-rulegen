"""What the test modules share: builders, fakes and sample rules.

Imported as `import helpers` (pytest puts tests/ on the path). Fixtures live in
the modules that use them.
"""

import json
import os
from collections.abc import Callable

import pytest

from rulegen import corpus, extract, tiers
from rulegen.gen import harness
from rulegen.gen.config import RunConfig, from_dict
from rulegen.gen.log import SampleRow, read_samples
from rulegen.schema import CveRecord, ExampleRecord, Score, ScoreRequest

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


# -- generation runs -------------------------------------------------------------------


def fenced(rule: str, prose: str = '') -> str:
    """A model reply carrying `rule` in a code block."""
    return f'{prose}```\n{rule}```\n'


def jsonl(events: list[dict]) -> str:
    return '\n'.join(json.dumps(e) for e in events) + '\n'


def write_data(data_dir: str, cves: list[str], split: str = 'val') -> None:
    """A corpus of gold CVEs and their model inputs, all in one split."""
    write_corpus(data_dir, [make_record(cve, split, has_rule=True) for cve in cves])
    extract.save_examples(
        [make_example(cve) for cve in cves], extract.examples_path(data_dir, split)
    )


def make_row(index: int = 0, **overrides) -> SampleRow:
    """A sample-log row of one attempt, its required fields filled in."""
    fields = {
        'run_id': 'r',
        'config_sha': 'c',
        'cve': 'CVE-2024-0001',
        'split': 'val',
        'cls': 'B',
        'mode': 'sample',
        'policy': 'P-M',
        'prompt_sha': 'p',
        'messages_sha': 'm',
        'system_prompt_id': 'sys-v1',
        'system_sha': 's',
        'adapter': 'fake',
        'model_id': 'fake',
        'temperature': 0.7,
        'top_p': 0.95,
        'max_tokens': 2048,
        'thinking': None,
        'seed': index,
        'sample_index': index,
    }
    return SampleRow(**{**fields, **overrides})


def with_text_terms(row: dict) -> dict:
    """A sample-log row with the text terms the oracle records at T0 for every rule it reads."""
    if row.get('rule_text'):
        anchored, wildcards = tiers.text_terms(row['rule_text'])
        row.setdefault('s_t0_anchored', anchored)
        row.setdefault('s_t0_wildcards', json.dumps(wildcards))
    return row


def valid(req: ScoreRequest) -> Score:
    return Score(cve=req.cve, rule_sha='x', valid=True, reward=1.0, strong_valid=True)


class FakeScorer:
    """The oracle's interface, judging by `verdict(request)`; every rule valid by default."""

    def __init__(self, verdict: Callable[[ScoreRequest], Score] = valid) -> None:
        self.verdict = verdict
        self.requests: list[ScoreRequest] = []

    def score_batch(self, reqs: list[ScoreRequest]) -> list[Score]:
        self.requests.extend(reqs)
        return [self.verdict(req) for req in reqs]

    def score(self, req: ScoreRequest) -> Score:
        return self.score_batch([req])[0]

    def close(self) -> None:
        pass


def run_config(out: str, **overrides) -> RunConfig:
    """A sample-mode cell on the fake adapter, n=3, over the val split."""
    base = {
        'run_id': 'unit',
        'mode': 'sample',
        'model': {'adapter': 'fake', 'concurrency': 3},
        'sampling': {'n': 3},
        'data': {'split': 'val'},
        'oracle': {'jobs': 1},
        'out': out,
    }
    return from_dict({**base, **overrides})


def run_harness(tmp_path, cfg: RunConfig, adapter, scorer=None, **kwargs) -> tuple[dict, list]:
    """Run `cfg` over tmp_path/data: the totals, and the rows the run logged."""
    totals = harness.run(
        cfg,
        str(tmp_path / 'kernel'),
        data_dir=str(tmp_path / 'data'),
        adapter=adapter,
        scorer_factory=(lambda: scorer) if scorer is not None else FakeScorer,
        **kwargs,
    )
    return totals, read_samples(os.path.join(cfg.out, cfg.run_id))
