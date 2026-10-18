"""Membership probe mechanics: prompt split, similarity, verdicts (no server)."""

import pytest
from helpers import FIX, FIXES

from rulegen.gen import probe
from rulegen.gen.adapters.base import Completion, GenRequest
from rulegen.gen.probe import (
    PROBE_SYSTEM,
    ChatCompleter,
    complete_prefix,
    edit_similarity,
    membership_prompt,
    run_membership,
    strip_fence,
)
from rulegen.schema import CveRecord

OLD_STYLE = f"""\
/// Files: net/foo.c
/// Fix: {FIX}
/// Fixes: {FIXES}

virtual detect

@r@
position p;
@@

foo_release(...) {{
	kfree@p(sk);
}}

@script:python depends on detect@
p << r.p;
@@
coccilib.report.print_report(p[0], 'ERROR: CVE-2023-0001')
"""


def test_prompt_splits_after_the_first_rule_header():
    prefix, remainder = membership_prompt(OLD_STYLE)
    assert prefix.endswith('virtual detect\n\n@r@\n')
    assert remainder.startswith('position p;')
    assert membership_prompt('/// Files: a.c\nvirtual detect\n') is None


def test_similarity_is_whitespace_insensitive():
    assert edit_similarity('a  b\n\tc', 'a b c') == 1.0
    assert edit_similarity('kfree(sk);', 'completely different') < 0.5


class Verbatim:
    """A 'model' that has memorized every rule: returns the true remainder."""

    def __init__(self, rules: dict[str, str]) -> None:
        self.texts = dict(membership_prompt(t) for t in rules.values())

    def raw_complete(self, prompt, n_predict, temperature=0.0, cache_prompt=True):
        return Completion(text=self.texts[prompt])


@pytest.fixture
def memorized(monkeypatch):
    """Rules served as the public text at the probe's ref, and a model that knows them all."""

    def serve(rules: dict[str, str]) -> tuple[Verbatim, list[CveRecord]]:
        monkeypatch.setattr(probe, 'snapshot_rule', lambda _repo, _ref, cve: rules[cve])
        records = [
            CveRecord(cve=c, fix=FIX, has_rule=True, rule_path=f'/x/{c}.cocci', split='train')
            for c in rules
        ]
        return Verbatim(rules), records

    return serve


def test_run_membership_flags_verbatim_and_not_control(memorized):
    body1 = OLD_STYLE.split('@r@\n', 1)[1].split('@script', 1)[0]
    body2 = (
        'identifier dev;\nexpression E;\n@@\n\nprobe(...) {\n\tdev = alloc(E);\n'
        '\tif (!dev) return -ENOMEM;\n\tregister@p(dev);\n}\n\n'
    )
    body3 = 'type T;\nidentifier len;\n@@\n\nparse(T *buf, int len) {\n\tmemcpy@p(buf, src, len);\n}\n\n'
    model, records = memorized(
        {  # distinct headers: the prompt is the header block, so it must differ per rule
            'CVE-2023-0001': OLD_STYLE,
            'CVE-2023-0002': OLD_STYLE.replace(body1, body2).replace('net/foo.c', 'drivers/bar.c'),
            'CVE-2023-0003': OLD_STYLE.replace(body1, body3).replace('net/foo.c', 'fs/baz.c'),
        }
    )
    rows = run_membership(model, '/nonexistent', records, threshold=0.9)
    assert len(rows) == 3 and all(r['memorized'] for r in rows)
    assert not any(r['control_memorized'] for r in rows)
    assert all(r['control_cve'] != r['cve'] for r in rows)


def test_run_membership_samples_under_a_seed(memorized):
    rules = {f'CVE-2023-000{i}': OLD_STYLE.replace('net/foo.c', f'net/f{i}.c') for i in range(1, 6)}
    model, records = memorized(rules)
    a = run_membership(model, '/nonexistent', records, sample=3, seed=4)
    b = run_membership(model, '/nonexistent', records, sample=3, seed=4)
    assert len(a) == 3 and [r['cve'] for r in a] == [r['cve'] for r in b]
    assert all(r['refused'] is False and r['tokens_completion'] is None for r in a)


class Chat:
    """A chat adapter with one canned reply."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.requests: list[GenRequest] = []

    def complete(self, req: GenRequest) -> Completion:
        self.requests.append(req)
        return Completion(text=self.reply, tokens_completion=9, cost_usd=0.01)


def test_chat_completer_strips_fences_and_flags_refusals():
    verbatim = Chat('```cocci\nposition p;\n@@\n```\n')
    comp = complete_prefix(ChatCompleter(verbatim), 'PREFIX', 'CVE-2023-0001', 256)
    assert comp.text == 'position p;\n@@\n' and comp.raw['refused'] is False
    req = verbatim.requests[0]
    assert req.messages[0] == {'role': 'system', 'content': PROBE_SYSTEM}
    assert 'cvehound/cve/CVE-2023-0001.cocci' in req.messages[1]['content']
    assert req.messages[1]['content'].endswith('PREFIX') and req.params.max_tokens == 256
    refusing = Chat("I can't reproduce that file verbatim from memory.")
    assert complete_prefix(ChatCompleter(refusing), 'PREFIX', 'CVE-2023-0001', 256).raw['refused']


def test_strip_fence_unwraps_one_fenced_reply_only():
    assert strip_fence('```cocci\n@r@\n@@\n```\n') == '@r@\n@@\n'
    assert strip_fence('plain') == 'plain'
