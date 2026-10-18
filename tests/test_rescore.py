"""Offline re-scoring with canonicalization on a tiny synthetic run."""

import json
import os

import pytest
from helpers import KFREE, FakeScorer, fenced, make_row, write_data

from rulegen.gen.log import SampleLog, read_samples
from rulegen.gen.manifest import write_manifest
from rulegen.gen.rescore import inherited_transform, rescore

PATCH = fenced(
    KFREE.replace('*\tkfree(sk);', '\t...\n-\tkfree(sk);\n+\tkfree_rcu(sk, rcu);\n\t...')
)
STARRED = fenced(KFREE)


def write_run(tmp_path, name, texts, cve='CVE-2023-0001', transform=None, rule_texts=()):
    """A parent run directory: one sample row per completion text, and its manifest.

    `rule_texts` are the rules the parent scored for those rows (what a real
    run logs), for the tests that need the parent's Files: line.
    """
    run = str(tmp_path / 'runs' / name)
    rows = [
        make_row(
            i,
            run_id=name,
            cve=cve,
            attempt_id=f'{cve}:{i}:0',
            completion_text=text,
            parsed=True,
            rule_text=rule_texts[i] if i < len(rule_texts) else None,
        )
        for i, text in enumerate(texts)
    ]
    SampleLog(run).append(rows)
    write_manifest(run, {'run_id': name, 'config': {'mode': 'sample', 'transform': transform}})
    return run


def test_rescore_canonicalizes_patches_and_keeps_detection_rules(tmp_path):
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    run = write_run(tmp_path, 'orig', [PATCH, STARRED, 'no rule here'], transform='canon')
    scorer = FakeScorer()
    out_dir = str(tmp_path / 'runs' / 'orig-canon')
    totals = rescore(run, out_dir, str(tmp_path / 'data'), scorer)
    out = {r['sample_index']: r for r in read_samples(out_dir)}
    assert totals['n_rows'] == 3 and totals['n_canonicalized'] == 1
    assert out[0]['s_canonicalized'] is True and '*\tkfree(sk);' in out[0]['rule_text']
    assert 'kfree_rcu' not in out[0]['rule_text'] and out[0]['s_valid'] is True
    assert out[1]['s_canonicalized'] is False and out[1]['s_valid'] is True
    assert out[2]['s_fail_class'] == 'contract' and out[2]['rule_text'] is None
    assert len(scorer.requests) == 2
    with open(os.path.join(out_dir, 'manifest.json')) as fh:
        manifest = json.load(fh)
    assert manifest['transform'] == 'canon' and manifest['derived_from'][0].endswith('orig')


def test_auto_transform_reproduces_what_the_parent_run_scored():
    """A rescore must re-derive the parent's rules, not silently score different text."""
    assert inherited_transform({'config': {'transform': 'canon'}}) == 'canon'
    assert inherited_transform({'config': {'transform': None}}) is None
    # A manifest written before the key existed is not re-scorable by inheritance.
    for manifest in ({'config': {}}, {}):
        with pytest.raises(ValueError, match='--canonicalize'):
            inherited_transform(manifest)


def test_rescore_can_take_several_parents_and_a_cve_subset(tmp_path):
    """Re-reading a handful of CVEs must not cost a whole shard."""
    data = str(tmp_path / 'data')
    write_data(data, ['CVE-2023-0001', 'CVE-2023-0002'])
    runs = [
        write_run(tmp_path, name, [STARRED], cve=cve)
        for name, cve in (('a', 'CVE-2023-0001'), ('b', 'CVE-2023-0002'))
    ]
    both = rescore(runs, str(tmp_path / 'runs' / 'both'), data, FakeScorer(), transform=None)
    assert both['n_rows'] == 2
    one_dir = str(tmp_path / 'runs' / 'one')
    one = rescore(runs, one_dir, data, FakeScorer(), transform=None, subset={'CVE-2023-0002'})
    assert one['n_rows'] == 1 and [r['cve'] for r in read_samples(one_dir)] == ['CVE-2023-0002']


def test_rescore_keeps_the_files_line_the_parent_scored(tmp_path):
    """The parent may have completed Files: with a file's earlier name (or not);
    a rescore re-derives that line from the parent's own rule, so the rescored
    rule is the bytes the parent judged, and the target stays the model's own."""
    data = str(tmp_path / 'data')
    write_data(data, ['CVE-2023-0001', 'CVE-2023-0002'])
    completed = KFREE.replace('/// Files: net/foo.c', '/// Files: net/foo.c net/old_foo.c')
    plain = write_run(tmp_path, 'plain', [STARRED], cve='CVE-2023-0001', rule_texts=[KFREE])
    done = write_run(tmp_path, 'done', [STARRED], cve='CVE-2023-0002', rule_texts=[completed])
    rescore([plain, done], str(tmp_path / 'runs' / 'full'), data, FakeScorer())
    rows = {r['cve']: r for r in read_samples(str(tmp_path / 'runs' / 'full'))}
    assert rows['CVE-2023-0001']['rule_text'].startswith('/// Files: net/foo.c\n')
    assert rows['CVE-2023-0002']['rule_text'].startswith('/// Files: net/foo.c net/old_foo.c\n')
    for row in rows.values():
        assert row['rule_body'] == KFREE
