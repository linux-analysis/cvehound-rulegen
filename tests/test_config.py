"""Run configs: typed sections, strict keys, stable identity."""

import dataclasses

import pytest
import yaml

from rulegen.gen.config import (
    cell_identity,
    config_sha,
    context_needed,
    from_dict,
    load_config,
    to_oracle_config,
)

FAKE = {'adapter': 'fake'}
CODEX = {'adapter': 'codex-cli', 'model': 'gpt-6-sol', 'effort': 'low'}
CLAUDE = {'adapter': 'claude-cli', 'model': 'fable', 'effort': 'low'}


def test_defaults_fill_in_and_run_id_derives_from_file(tmp_path):
    path = tmp_path / 'sample-anchor-pm.yaml'
    path.write_text(yaml.safe_dump({'mode': 'sample', 'model': FAKE}))
    cfg = load_config(str(path))
    assert cfg.run_id.startswith('sample-anchor-pm-')
    assert cfg.sampling.n == 20 and cfg.prompt.hide_cve_id is True
    assert cfg.oracle.run_selectivity is True


@pytest.mark.parametrize(
    ('raw', 'error'),
    [
        ({'sampling': {'temprature': 0.5}}, 'unknown keys'),
        ({'mode': 'interactive', 'model': FAKE}, 'mode must be one of'),
        ({'mode': 'mechanical'}, 'mechanical'),
        ({'prompt': {'policy': 'P-Z'}}, 'policy'),
        ({'model': {**FAKE, 'context_tokens': 8192}}, 'exceeds model.context_tokens'),
        # Without a post-acceptance tier strong_valid == valid: the gate would promise nothing.
        (
            {
                'mode': 'pipeline',
                'model': FAKE,
                'pipeline': {'accept': 'strong'},
                'oracle': {'run_selectivity': False},
            },
            'run_selectivity',
        ),
        # The vendor CLIs take an effort, not sampling knobs or local weights.
        ({'model': {**CODEX, 'effort': None}}, 'effort'),
        ({'model': {**CODEX, 'model': ''}}, 'model.model'),
        ({'model': {**CLAUDE, 'effort': 'ultra'}}, 'ultra'),
        ({'model': {**CODEX, 'thinking': False}}, 'thinking'),
        ({'model': {**CLAUDE, 'model_file': '/w'}}, 'does not apply'),
        ({'model': {**FAKE, 'effort': 'low'}}, 'claude-cli / codex-cli only'),
    ],
)
def test_invalid_configs_are_refused(raw, error):
    with pytest.raises(ValueError, match=error):
        from_dict({'run_id': 'x', **raw})


def test_overrides_are_typed_and_hash_ignores_labels(tmp_path):
    path = tmp_path / 'c.yaml'
    path.write_text(yaml.safe_dump({'run_id': 'a', 'model': FAKE}))
    a = load_config(str(path))
    b = load_config(str(path), ['sampling.n=5', 'model.thinking=true', 'run_id=b'])
    assert b.sampling.n == 5 and b.model.thinking is True and b.run_id == 'b'
    c = load_config(str(path), ['run_id=c', 'notes=hello', 'oracle.jobs=3'])
    assert config_sha(a) == config_sha(c) != config_sha(b)


def test_cell_identity_strips_labels_and_machine_knobs_from_any_config_dict():
    cfg = {
        'run_id': 'a',
        'notes': 'n',
        'mode': 'sample',
        'oracle': {'jobs': 4, 'work': '/w', 'run_cost': True},
        'model': {'model': 'm', 'concurrency': 2},
    }
    assert cell_identity(cfg) == {
        'mode': 'sample',
        'oracle': {'run_cost': True},
        'model': {'model': 'm'},
    }
    assert cfg['oracle']['jobs'] == 4  # the input is not mutated
    assert cell_identity({'mode': 'sample'}) == {'mode': 'sample'}  # sections may be missing


def test_machine_knobs_are_outside_the_cell_identity():
    """Two halves of one cell may run on different hosts, with different batching."""
    base = {'run_id': 'a', 'model': FAKE}
    other_host = {
        **base,
        'chunk_cves': 32,
        'model': {**FAKE, 'endpoint': 'http://10.0.0.1:9000/v1', 'model_file': '/w'},
        'oracle': {'jobs': 3, 'use_cache': False, 'zygote': 'off', 'heavy_slots': 6},
    }
    assert config_sha(from_dict(base)) == config_sha(from_dict(other_host))
    assert config_sha(from_dict(base)) != config_sha(from_dict({**base, 'sampling': {'n': 5}}))


def test_oracle_run_config_forwards_every_field():
    cfg = from_dict(
        {'run_id': 'a', 'oracle': {'range_max_points': 4, 'worktrees': '/tmp/wt', 'run_tree': True}}
    )
    oracle = to_oracle_config(cfg.oracle, '/kernel')
    assert (oracle.range_max_points, oracle.worktrees, oracle.run_tree) == (4, '/tmp/wt', True)
    # Nothing the service knows about is left behind by the YAML layer.
    service_fields = {f.name for f in dataclasses.fields(oracle)} - {'kernel', 'work_root'}
    assert service_fields <= {f.name for f in dataclasses.fields(cfg.oracle)}


def test_budget_must_fit_the_slot_with_the_counter_safety_factor():
    cfg = from_dict({'run_id': 'x', 'model': FAKE})
    assert context_needed(cfg) == int(8192 * 1.5) + 2048 <= cfg.model.context_tokens
    # An exact tokenizer needs no margin: 12000 + 2048 fits where 12000 x 1.5 would not.
    exact = from_dict(
        {
            'run_id': 'x',
            'model': {**FAKE, 'tokenizer_json': 'tok.json'},
            'prompt': {'budget_tokens': 12000},
        }
    )
    assert context_needed(exact) == 14048


def test_cli_adapters_get_a_frontier_context():
    cfg = from_dict({'run_id': 'x', 'model': {**CLAUDE, 'effort': 'medium'}})
    assert cfg.model.context_tokens == 200_000 and cfg.model.effort == 'medium'


def test_cli_cell_identity_tracks_effort_and_args_but_not_the_machine_knobs():
    a = from_dict({'run_id': 'x', 'model': CODEX})
    b = from_dict({'run_id': 'x', 'model': {**CODEX, 'effort': 'xhigh'}})
    c = from_dict({'run_id': 'x', 'model': {**CODEX, 'cli_args': ['--x']}})
    machine = {'config_dir': '/h', 'cli_bin': '/usr/bin/codex', 'usage_wait_cap_s': 5}
    d = from_dict({'run_id': 'x', 'model': {**CODEX, **machine}})
    assert config_sha(a) != config_sha(b) != config_sha(c)
    assert config_sha(a) == config_sha(d)
    assert c.model.cli_args == ('--x',)
