"""The harness loop with a scripted adapter and a fake scorer: no network, no spatch."""

import json
import os

import pytest
from helpers import (
    FIX,
    FIXES,
    KFREE,
    FakeScorer,
    fenced,
    make_example,
    make_record,
    make_row,
    run_config,
    run_harness,
    write_corpus,
    write_data,
)

from rulegen import extract
from rulegen.gen import harness
from rulegen.gen.adapters.base import AbortRun, GenRequest, SamplingParams
from rulegen.gen.adapters.fake import FakeAdapter
from rulegen.gen.harness import Harness, load_split
from rulegen.gen.log import read_samples

GOOD = fenced(KFREE, 'Here you go:\n')
PROSE = "I'm sorry, I can't write that rule without more context."


def script(req: GenRequest, _index: int) -> str:
    """Sample 1 of every CVE answers in prose; 0 and 2 write the same rule."""
    return PROSE if req.seed % 1000 == 1 else GOOD


def test_sample_run_logs_every_attempt_dedups_and_resumes(tmp_path):
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001', 'CVE-2023-0002'])
    cfg = run_config(str(tmp_path / 'runs'))
    adapter, scorer = FakeAdapter(script), FakeScorer()
    totals, rows = run_harness(tmp_path, cfg, adapter, scorer)

    assert totals['n_rows'] == 6 and totals['n_valid'] == 4 and totals['n_contract'] == 2
    assert len(adapter.calls) == 6 and len(rows) == 6
    assert len(scorer.requests) == 2  # one unique rule per CVE; the duplicate reused the Score
    by_key = {(r['cve'], r['sample_index']): r for r in rows}
    prose = by_key[('CVE-2023-0001', 1)]
    assert not prose['parsed'] and prose['s_fail_class'] == 'contract' and not prose['s_valid']
    first, dup = by_key[('CVE-2023-0001', 0)], by_key[('CVE-2023-0001', 2)]
    assert first['s_valid'] and dup['s_valid']
    assert dup['dedup_of'] == first['attempt_id'] and first['dedup_of'] == ''
    # Files: is completed with the file's earlier name from the example.
    assert first['rule_text'].startswith(f'/// Files: net/foo.c net/old_foo.c\n/// Fix: {FIX}')
    assert f'/// Fixes: {FIXES}' in first['rule_text']
    # The training target is the model's own rule: no completed name, no commit headers.
    assert first['rule_body'] == KFREE
    assert first['tokens_cum'] > 0 and first['prompt_sha'] and first['messages_sha']

    with open(tmp_path / 'runs' / 'unit' / 'manifest.json') as fh:
        manifest = json.load(fh)
    assert {'config_sha', 'git', 'kernel', 'oracle', 'versions', 'prompt', 'model', 'data'} <= set(
        manifest
    )
    assert manifest['totals']['n_rows'] == 6 and manifest['prompt']['system_sha']

    # Resume: everything is already logged, so nothing is generated or appended.
    again = FakeAdapter(script)
    totals, rows = run_harness(tmp_path, cfg, again, scorer, resume=True)
    assert again.calls == [] and totals['n_rows'] == 0 and len(rows) == 6


def test_dry_run_writes_prompts_only(tmp_path):
    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    adapter = FakeAdapter(script)
    totals, rows = run_harness(tmp_path, run_config(str(tmp_path / 'runs')), adapter, dry_run=True)
    assert totals['n_prompts'] == 1 and adapter.calls == [] and rows == []
    assert os.path.exists(tmp_path / 'runs' / 'unit' / 'prompts.parquet')


def test_load_split_refuses_examples_with_no_introducing_commit(tmp_path):
    """A prompt with every range section blank is not a smaller prompt; it is not an example."""
    data = str(tmp_path / 'data')
    write_data(data, ['CVE-2023-0001', 'CVE-2023-0002'])
    examples = extract.load_examples(extract.examples_path(data, 'val'))
    examples[1].fixes = None
    extract.save_examples(examples, extract.examples_path(data, 'val'))
    with pytest.raises(ValueError, match='no introducing commit'):
        load_split(data, 'val', None, 0)


def test_abort_run_leaves_the_chunk_unlogged(tmp_path):
    """A usage-limit abort must not write error rows: --resume would treat them as done."""

    class Aborting(FakeAdapter):
        def complete(self, req: GenRequest):
            raise AbortRun('usage limit resets in 9 h')

    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    with pytest.raises(AbortRun, match='usage limit'):
        run_harness(tmp_path, run_config(str(tmp_path / 'runs')), Aborting(script))
    assert read_samples(str(tmp_path / 'runs' / 'unit')) == []
    assert os.path.exists(tmp_path / 'runs' / 'unit' / 'manifest.json')


def test_gold_split_merges_the_three_files_and_rows_keep_their_true_split(tmp_path):
    data = str(tmp_path / 'data')
    splits = {'CVE-2019-0001': 'train', 'CVE-2023-0001': 'val', 'CVE-2024-0001': 'test'}
    write_corpus(data, [make_record(cve, split, has_rule=True) for cve, split in splits.items()])
    for cve, split in splits.items():
        extract.save_examples([make_example(cve)], extract.examples_path(data, split))
    examples, _records, _classes = load_split(data, 'gold', {'CVE-2019-0001', 'CVE-2024-0001'}, 0)
    assert [ex.cve for ex in examples] == ['CVE-2019-0001', 'CVE-2024-0001']

    cfg = run_config(
        str(tmp_path / 'runs'), run_id='gold', sampling={'n': 1}, data={'split': 'gold'}
    )
    _totals, rows = run_harness(tmp_path, cfg, FakeAdapter(script))
    assert {r['cve']: r['split'] for r in rows} == splits
    assert all(r['sampling_honored'] is True and r['tool_calls'] == 0 for r in rows)
    with open(tmp_path / 'runs' / 'gold' / 'manifest.json') as fh:
        recorded = json.load(fh)['data']
    assert {'examples_train_sha256', 'examples_val_sha256', 'examples_test_sha256'} <= set(recorded)


def test_cli_completion_fields_reach_the_row(tmp_path):
    class Priced(FakeAdapter):
        honors_sampling = False

        def complete(self, req: GenRequest):
            comp = super().complete(req)
            comp.request_id, comp.tokens_cached, comp.cost_usd = 'sess-9', 5, 0.5
            comp.raw = {'tool_calls': 0, 'tool_attempts_denied': 2}
            return comp

    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    _totals, rows = run_harness(tmp_path, run_config(str(tmp_path / 'runs')), Priced(script))
    row = rows[0]
    assert row['request_id'] == 'sess-9' and row['tokens_cached'] == 5 and row['cost_usd'] == 0.5
    assert row['sampling_honored'] is False and row['tool_attempts_denied'] == 2


def test_a_run_refuses_a_server_that_serves_another_model(tmp_path):
    class Served(FakeAdapter):
        def describe(self):
            return {'props': {'model_path': '/models/gemma-4-31B-it-Q4_K_M.gguf'}}

    write_data(str(tmp_path / 'data'), ['CVE-2023-0001'])
    model = {'adapter': 'fake', 'model_file': '/models/Qwen3.8-27B-UD-Q4_K_M.gguf'}
    cfg = run_config(str(tmp_path / 'runs'), run_id='guard', model=model)
    adapter = Served(script)
    with pytest.raises(ValueError, match='serving /models/gemma-4-31B'):
        run_harness(tmp_path, cfg, adapter)
    assert adapter.calls == []  # not one request went out
    # The same file elsewhere is the same weights; a server that says nothing is let through.
    assert (
        harness.served_model_error('/m/a.gguf', {'props': {'model_path': '/other/a.gguf'}}) is None
    )
    assert harness.served_model_error('/m/a.gguf', {}) is None


def test_over_context_requests_are_refused_before_the_server_sees_them(tmp_path):
    adapter = FakeAdapter(script)
    h = Harness(run_config(str(tmp_path / 'runs')), str(tmp_path / 'kernel'), adapter=adapter)
    small = GenRequest([{'role': 'user', 'content': 'x'}], SamplingParams(max_tokens=10), 0)
    huge = GenRequest(
        [{'role': 'user', 'content': 'word ' * 40000}], SamplingParams(max_tokens=2048), 0
    )
    huge_tokens = h.count(huge.messages[0]['content'])
    assert h.context_error(1, 10) is None
    why = h.context_error(huge_tokens, 2048)
    assert why and why.startswith('context:') and '> 16384' in why
    rows = [make_row(0, prompt_tokens_est=huge_tokens), make_row(1, prompt_tokens_est=1)]
    comps = h.generate(list(zip(rows, (huge, small), strict=True)))
    assert comps[0].error == why and comps[0].text == ''
    assert comps[1].error is None and len(adapter.calls) == 1  # only the small one was sent
