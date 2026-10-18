"""Agent mechanics without a model: the workspace export, the stream parsers, scripted sessions."""

import json
import os
import pathlib
import subprocess
import time
import types

import pytest
from helpers import FIX, FIXES, FakeScorer, jsonl, make_record, write_corpus

from rulegen.gen import agentic
from rulegen.gen.adapters.cli_subprocess import CliResult
from rulegen.gen.log import export_rules, read_samples
from rulegen.git import git
from rulegen.oracle.service import OracleConfig
from rulegen.promptbuild import finalize_completion

GOLD = f'/// Files: net/foo.c\n/// Fix: {FIX}\n\n@r@\n@@\n\nfoo(...)\n{{\n*\tkfree(sk);\n}}\n'
OTHER = f'/// Files: fs/bar.c\n/// Fix: {"a" * 40}\n\n@r@\n@@\n\nbar(...)\n{{\n*\tkfree(p);\n}}\n'
AGENT_RULE = f'/// Files: net/foo.c\n/// Fix: {FIX}\n/// Fixes: {FIXES}\n\n@err@\n@@\n\nfoo(...)\n{{\n*\tkfree(sk);\n}}\n'
COMMIT = ('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q')


def make_cvehound(root: str) -> str:
    """A tiny cvehound-shaped repo: two rules, a doc citing one, the skill, a pyproject."""
    repo = os.path.join(root, 'cvehound')
    for rel, text in (
        ('cvehound/cve/CVE-2023-0001.cocci', GOLD),
        ('cvehound/cve/disputed/CVE-2023-0002.cocci', OTHER),
        ('docs/WRITING_RULES.md', 'The worked example CVE-2023-0001 shows ...\n'),
        ('tests/conftest.py', 'missing_backports = [("CVE-2023-0001", "stable/linux-5.10.y")]\n'),
        ('tests/.gitignore', 'linux/\n'),
        ('.agents/skills/write-cve-rule/SKILL.md', '# skill\n'),
        ('pyproject.toml', '[project]\nname = "cvehound"\nversion = "0"\n'),
        ('.gitignore', '.venv\n'),
    ):
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pathlib.Path(path).write_text(text)
    os.makedirs(os.path.join(repo, '.claude'))
    os.symlink('../.agents/skills', os.path.join(repo, '.claude', 'skills'))
    git(repo, 'init', '-q', '-b', 'main')
    git(repo, 'add', '-A')
    git(repo, *COMMIT, '-m', 'one')
    with open(os.path.join(repo, 'cvehound/cve/CVE-2023-0001.cocci'), 'a') as fh:
        fh.write('// touched\n')
    git(repo, *COMMIT, '-am', 'two')
    return repo


def make_kernel(root: str) -> str:
    kernel = os.path.join(root, 'linux')
    os.makedirs(os.path.join(kernel, 'net'))
    pathlib.Path(kernel, 'net', 'foo.c').write_text('int foo(void) { kfree(sk); return 0; }\n')
    git(kernel, 'init', '-q', '-b', 'master')
    git(kernel, 'add', '-A')
    git(kernel, *COMMIT, '-m', 'k')
    return kernel


@pytest.fixture
def checkout(tmp_path) -> types.SimpleNamespace:
    """A cvehound checkout, a kernel clone, and an empty data directory beside them."""
    return types.SimpleNamespace(
        repo=make_cvehound(str(tmp_path)),
        kernel=make_kernel(str(tmp_path)),
        data=str(tmp_path / 'data'),
    )


@pytest.fixture
def oracle(monkeypatch) -> FakeScorer:
    """The oracle every agent run scores with: valid, whatever the rule."""
    scorer = FakeScorer()
    monkeypatch.setattr(agentic, 'OracleService', lambda cfg, jobs: scorer)
    return scorer


def run_agent(tmp_path, checkout, runner=None, **settings) -> dict:
    """agentic.run_agent over the checkout, with a session config of `settings`."""
    options = {k: settings.pop(k) for k in ('resume', 'dry_run') if k in settings}
    cfg = agentic.AgentConfig(
        **{
            'run_id': 'agent-unit',
            'cli': 'claude',
            'model': 'fable',
            'split': 'val',
            'jobs': 1,
            'out': str(tmp_path / 'runs'),
            'workspaces': str(tmp_path / 'ws'),
            **settings,
        }
    )
    oracle_cfg = OracleConfig(
        kernel=checkout.kernel, work_root=str(tmp_path / 'oracle'), branches=('stable/linux-6.1.y',)
    )
    return agentic.run_agent(
        cfg,
        checkout.kernel,
        oracle_cfg,
        data_dir=checkout.data,
        cvehound_repo=checkout.repo,
        runner=runner,
        **options,
    )


# -- the workspace -----------------------------------------------------------------


def test_export_workspace_removes_the_rule_and_its_history(tmp_path, checkout):
    dest = str(tmp_path / 'ws')
    ws = agentic.export_workspace(
        checkout.repo, checkout.kernel, 'CVE-2023-0001', dest, sync_venv=False
    )
    assert ws.removed == ['cvehound/cve/CVE-2023-0001.cocci']
    assert not os.path.exists(os.path.join(dest, 'cvehound/cve/CVE-2023-0001.cocci'))
    assert os.path.exists(os.path.join(dest, 'cvehound/cve/disputed/CVE-2023-0002.cocci'))
    # One commit, and no object anywhere in the store carries the gold rule's blob.
    assert git(dest, 'rev-list', '--count', 'HEAD').strip() == '1'
    blob = git(dest, 'hash-object', '--stdin', input=GOLD).strip()
    assert blob not in git(dest, 'rev-list', '--objects', '--all')
    # The kernel is reachable at tests/linux, the skills survive, the guard is in place.
    assert os.path.islink(os.path.join(dest, 'tests', 'linux'))
    assert os.path.exists(os.path.join(dest, 'tests', 'linux', 'net', 'foo.c'))
    assert os.path.exists(os.path.join(dest, '.claude', 'skills', 'write-cve-rule', 'SKILL.md'))
    settings = json.loads(pathlib.Path(dest, '.claude', 'settings.json').read_text())
    assert {'WebFetch', 'Bash(git fetch*)'} <= set(settings['permissions']['deny'])
    assert settings['hooks']['PreToolUse'][0]['hooks'][0]['command'].endswith('agent-guard.sh')
    guard = pathlib.Path(dest, '.claude', 'hooks', 'agent-guard.sh')
    assert os.access(guard, os.X_OK) and 'AGENT_MAX_TOOL_CALLS:-200' in guard.read_text()
    # The remaining mentions are the suite's own inputs, reported not hidden.
    assert ws.mentions == ['docs/WRITING_RULES.md', 'tests/conftest.py']


def test_guard_hook_blocks_network_and_caps_calls(tmp_path, checkout):
    dest = str(tmp_path / 'ws')
    agentic.export_workspace(
        checkout.repo, checkout.kernel, 'CVE-2023-0001', dest, max_tool_calls=2, sync_venv=False
    )
    guard = os.path.join(dest, '.claude', 'hooks', 'agent-guard.sh')
    env = {**os.environ, 'CLAUDE_PROJECT_DIR': dest}

    def call(command: str) -> subprocess.CompletedProcess:
        payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}})
        return subprocess.run(
            [guard], input=payload, env=env, capture_output=True, text=True, check=False
        )

    assert call('git -C tests/linux show HEAD').returncode == 0
    blocked = call('git -C tests/linux fetch origin')
    assert blocked.returncode == 2 and 'blocked' in blocked.stderr
    capped = call('ls')
    assert capped.returncode == 2 and 'budget' in capped.stderr


def test_scratch_clones_are_only_new_clones_of_the_kernel(tmp_path):
    kernel = make_kernel(str(tmp_path))
    tmp = tmp_path / 'tmp'
    tmp.mkdir()

    def clone(dest) -> None:
        subprocess.run(
            ['git', 'clone', '-q', '--shared', '--no-checkout', kernel, str(dest / 'linux')],
            check=True,
        )

    old_clone = tmp / 'old-clone'
    clone(old_clone)
    since = time.time() + 0.01
    time.sleep(0.05)
    new_clone = tmp / 'cvehound-1234.abc'
    clone(new_clone)
    other_repo = tmp / 'someone-elses'
    (other_repo / 'proj').mkdir(parents=True)
    git(str(other_repo / 'proj'), 'init', '-q')
    plain = tmp / 'pytest-of-work'
    plain.mkdir()
    suite_root = tmp / 'cvehound-CVE-2025-0001-tests'
    (suite_root / 'cvehound-worktrees-1000' / 'origin-master').mkdir(parents=True)
    found = agentic.scratch_clones([str(tmp)], since, kernel)
    assert found == sorted([str(new_clone), str(suite_root)])
    assert agentic.remove_scratch_clones([str(tmp)], since, kernel) == found
    assert not new_clone.exists() and not suite_root.exists()
    assert old_clone.exists() and other_repo.exists() and plain.exists()


# -- reading what the agent did ----------------------------------------------------------

CLAUDE_EVENTS = [
    {'type': 'system', 'subtype': 'init', 'session_id': 's1', 'model': 'claude-fable-5-1'},
    {
        'type': 'assistant',
        'message': {
            'content': [
                {
                    'type': 'tool_use',
                    'id': 't1',
                    'name': 'Bash',
                    'input': {'command': 'git -C tests/linux show abc'},
                },
            ]
        },
    },
    {
        'type': 'user',
        'message': {'content': [{'type': 'tool_result', 'tool_use_id': 't1', 'content': 'diff'}]},
    },
    {
        'type': 'assistant',
        'message': {
            'content': [
                {
                    'type': 'tool_use',
                    'id': 't2',
                    'name': 'Write',
                    'input': {'file_path': 'cvehound/cve/CVE-2023-0001.cocci'},
                },
                {
                    'type': 'tool_use',
                    'id': 't3',
                    'name': 'Bash',
                    'input': {
                        'command': '.agents/skills/write-cve-rule/scripts/validate-rule.sh cvehound/cve/CVE-2023-0001.cocci'
                    },
                },
                {
                    'type': 'tool_use',
                    'id': 't4',
                    'name': 'Bash',
                    'input': {'command': 'uv run pytest --runslow --cve=CVE-2023-0001'},
                },
            ]
        },
    },
    {
        'type': 'user',
        'message': {
            'content': [
                {'type': 'tool_result', 'tool_use_id': 't3', 'content': 'ok'},
                {
                    'type': 'tool_result',
                    'tool_use_id': 't4',
                    'content': [{'type': 'text', 'text': '== 12 passed in 30s =='}],
                },
            ]
        },
    },
    {
        'type': 'result',
        'subtype': 'success',
        'is_error': False,
        'result': 'Wrote cvehound/cve/CVE-2023-0001.cocci; the suite passed.',
        'num_turns': 5,
        'total_cost_usd': 0.42,
        'usage': {
            'input_tokens': 10,
            'cache_read_input_tokens': 500,
            'cache_creation_input_tokens': 90,
            'output_tokens': 70,
        },
        'duration_ms': 90000,
        'session_id': 's1',
        'modelUsage': {'claude-fable-5-1': {}},
    },
]


def test_parse_claude_stream_reads_tools_pytest_and_result():
    trace = agentic.parse_claude_stream(jsonl(CLAUDE_EVENTS))
    assert trace.tool_calls == 4 and trace.tool_names == {'Bash': 3, 'Write': 1}
    assert trace.validator_ran and trace.pytest_ran and trace.pytest_passed is True
    assert trace.num_turns == 5 and trace.cost_usd == 0.42 and trace.request_id == 's1'
    assert trace.resolved_model == 'claude-fable-5-1' and trace.error is None
    assert trace.message.startswith('Wrote') and trace.blocked_commands == 0
    failing = json.loads(json.dumps(CLAUDE_EVENTS))
    failing[4]['message']['content'][1]['content'] = [
        {'type': 'text', 'text': '1 failed, 11 passed'}
    ]
    failing[1]['message']['content'][0]['input']['command'] = 'git -C tests/linux fetch origin'
    trace = agentic.parse_claude_stream(jsonl(failing))
    assert trace.pytest_passed is False and trace.blocked_commands == 1


def command(text: str, exit_code: int, output: str) -> dict:
    item = {
        'type': 'command_execution',
        'command': text,
        'exit_code': exit_code,
        'aggregated_output': output,
    }
    return {'type': 'item.completed', 'item': item}


def test_parse_codex_stream_reads_commands_exit_codes_and_every_tool_kind(tmp_path):
    events = [
        {'type': 'thread.started', 'thread_id': 'thr', 'model': 'gpt-6-astra-2026'},
        command('git -C tests/linux show abc', 0, 'diff'),
        {'type': 'item.completed', 'item': {'type': 'file_change', 'changes': []}},
        {'type': 'item.completed', 'item': {'type': 'computer_use'}},
        command('uv run pytest --runslow --cve=CVE-2023-0001', 1, '1 failed'),
        command('uv run pytest --runslow --cve=CVE-2023-0001', 0, '12 passed'),
        {
            'type': 'turn.completed',
            'usage': {'input_tokens': 900, 'cached_input_tokens': 300, 'output_tokens': 50},
        },
    ]
    out = tmp_path / 'final.md'
    out.write_text('done: cvehound/cve/CVE-2023-0001.cocci, suite passed')
    trace = agentic.parse_codex_stream(jsonl(events), str(out))
    # Every tool item the direct cells would retry counts, not only shell and patch.
    assert trace.tool_calls == 5 and trace.tool_names['computer_use'] == 1
    assert trace.pytest_ran and trace.pytest_passed is True and trace.validator_ran is False
    assert trace.message.startswith('done') and trace.usage['input_tokens'] == 900
    assert trace.request_id == 'thr' and trace.resolved_model == 'gpt-6-astra-2026'
    failed = agentic.parse_codex_stream(jsonl([{'type': 'error', 'message': 'quota exceeded'}]))
    assert failed.error == 'quota exceeded'


def test_codex_agent_hides_personal_skills_but_keeps_its_shell(tmp_path):
    home = tmp_path / 'codex-home'
    (home / 'skills' / 'personal-skill').mkdir(parents=True)
    (home / 'skills' / 'personal-skill' / 'SKILL.md').write_text('# lazy\n')
    cfg = agentic.AgentConfig(
        run_id='x',
        cli='codex',
        model='gpt-6-astra',
        config_dir=str(home),
        suite_tmpdir=str(tmp_path / 'tmp'),
    )
    ws = agentic.Workspace(path=str(tmp_path / 'ws'), cve='CVE-2023-0001', removed=[], mentions=[])
    argv = agentic.agent_argv(cfg, ws, str(tmp_path / 'linux'), str(tmp_path / 'out.md'))
    skills = next(a for a in argv if a.startswith('skills.config='))
    assert 'personal-skill' in skills and 'enabled=false' in skills
    disabled = {argv[i + 1] for i, a in enumerate(argv) if a == '--disable'}
    assert {'plugins', 'hooks', 'memories', 'browser_use'} <= disabled
    assert 'shell_tool' not in disabled and 'unified_exec' not in disabled
    assert argv[argv.index('-s') + 1] == 'workspace-write' and argv[-1] == '-'
    assert str(tmp_path / 'linux') in argv and str(tmp_path / 'tmp') in argv


# -- sessions ----------------------------------------------------------------------------


@pytest.fixture
def claude_session(tmp_path, checkout, oracle) -> types.SimpleNamespace:
    """One scripted Claude Code session that writes AGENT_RULE and passes the suite."""
    write_corpus(
        checkout.data,
        [
            make_record('CVE-2023-0001', cmt_subject='net: fix foo', has_rule=True),
            make_record('CVE-2023-0002', fix='a' * 40, fixes='b' * 40),
        ],
    )
    seen: dict = {}

    def runner(argv, stdin_text, env, cwd, timeout_s) -> CliResult:
        seen.update(argv=argv, stdin=stdin_text, env=env, cwd=cwd, timeout=timeout_s)
        pathlib.Path(cwd, 'cvehound', 'cve', 'CVE-2023-0001.cocci').write_text(AGENT_RULE)
        return CliResult(stdout=jsonl(CLAUDE_EVENTS), stderr='', returncode=0, latency_s=12.5)

    totals = run_agent(tmp_path, checkout, runner, limit=1, max_wall_s=100, max_tool_calls=50)
    run_dir = tmp_path / 'runs' / 'agent-unit'
    manifest = json.loads((run_dir / 'manifest.json').read_text())
    return types.SimpleNamespace(
        seen=seen,
        runner=runner,
        totals=totals,
        run_dir=run_dir,
        rows=read_samples(str(run_dir)),
        manifest=manifest,
    )


def test_a_session_runs_the_cli_in_its_workspace_with_the_task(claude_session):
    seen = claude_session.seen
    argv, env = seen['argv'], seen['env']
    assert argv[:2] == ['claude', '-p'] and '--dangerously-skip-permissions' in argv
    assert argv[argv.index('--setting-sources') + 1] == 'project' and seen['timeout'] == 100
    assert os.path.isabs(seen['cwd'])
    assert 'Add a CVEhound detection rule for CVE-2023-0001' in seen['stdin']
    assert FIX in seen['stdin'] and FIXES in seen['stdin']
    assert env['CVEHOUND_TEST_OFFLINE'] == '1' and env['PYTEST_ADDOPTS'] == '-n 4'
    assert env['AGENT_MAX_TOOL_CALLS'] == '50' and 'OPENAI_API_KEY' not in env
    assert env['PATH'].startswith(os.path.join(seen['cwd'], '.venv', 'bin'))


def test_a_session_logs_a_scored_row_and_its_manifest(tmp_path, claude_session, oracle):
    totals, (row,) = claude_session.totals, claude_session.rows
    assert totals['n_rows'] == 1 and totals['n_valid'] == 1 and totals['n_pytest_passed'] == 1
    assert row['mode'] == 'agentic' and row['policy'] == 'agent' and row['split'] == 'val'
    assert row['agent_rule_text'] == AGENT_RULE and row['pytest_passed'] is True
    assert row['tool_calls'] == 4 and row['validator_ran'] is True and row['kernel_clean'] is True
    assert (
        row['cost_usd'] == 0.42 and row['tokens_prompt'] == 600 and row['tokens_completion'] == 70
    )
    assert row['s_valid'] is True and row['parsed'] is True
    # The scored rule carries the corpus headers, not the agent's own Fix:/Fixes: lines twice.
    assert row['rule_text'].count('/// Fix:') == 1 and f'/// Fixes: {FIXES}' in row['rule_text']
    assert [req.rule_text for req in oracle.requests] == [row['rule_text']]
    record = make_record('CVE-2023-0001', cmt_subject='net: fix foo', has_rule=True)
    assert finalize_completion(row['completion_text'], record).rule == row['rule_text']
    manifest = claude_session.manifest
    assert (
        manifest['config']['mode'] == 'agentic'
        and manifest['config']['agent']['max_tool_calls'] == 50
    )
    # The model the CLI resolved prices the run (eval.driver.price_key).
    assert manifest['model']['adapter_describe']['resolved_model'] == 'claude-fable-5-1'
    assert (claude_session.run_dir / 'transcripts' / 'CVE-2023-0001-0.jsonl').exists()
    # The workspace kept its tree for auditing; venv and kernel link are gone.
    ws = tmp_path / 'ws' / 'agent-unit' / 'CVE-2023-0001-0'
    assert (ws / 'cvehound' / 'cve' / 'CVE-2023-0001.cocci').exists()
    assert not (ws / 'tests' / 'linux').exists()


def test_a_session_exports_for_the_suite_and_resumes(tmp_path, checkout, claude_session):
    written = export_rules(str(claude_session.run_dir), str(tmp_path / 'audit'))
    assert [os.path.basename(p) for p in written] == ['CVE-2023-0001.cocci']
    assert pathlib.Path(written[0]).read_text() == claude_session.rows[0]['rule_text']
    again = run_agent(tmp_path, checkout, claude_session.runner, limit=1, resume=True)
    assert again['n_rows'] == 0


def test_session_without_a_rule_is_a_contract_row(tmp_path, checkout, oracle):
    write_corpus(checkout.data, [make_record('CVE-2023-0001')])

    def runner(argv, stdin_text, env, cwd, timeout_s) -> CliResult:
        return CliResult(stdout='', stderr='killed', returncode=-9, latency_s=100.0, timed_out=True)

    totals = run_agent(
        tmp_path, checkout, runner, run_id='agent-none', cli='codex', model='gpt-6-astra'
    )
    row = read_samples(str(tmp_path / 'runs' / 'agent-none'))[0]
    assert totals['n_timed_out'] == 1 and row['timed_out'] is True
    assert row['s_fail_class'] == 'contract' and row['error'].startswith('timed out')
    assert row['agent_rule_text'] is None and row['finish_reason'] == 'timeout'


def test_gold_split_selects_train_val_and_test(tmp_path, checkout):
    write_corpus(
        checkout.data,
        [
            make_record('CVE-2019-0001', 'train'),
            make_record('CVE-2023-0001'),
            make_record('CVE-2025-0001', 'newrule'),
        ],
    )
    totals = run_agent(tmp_path, checkout, split='gold', dry_run=True)
    assert totals['n_cves'] == 2 and totals['sessions'] == ['CVE-2019-0001-0', 'CVE-2023-0001-0']


def test_codex_session_gets_absolute_paths_from_relative_settings(
    tmp_path, checkout, oracle, monkeypatch
):
    write_corpus(checkout.data, [make_record('CVE-2023-0001')])
    seen = {}

    def runner(argv, stdin_text, env, cwd, timeout_s) -> CliResult:
        seen.update(argv=argv, cwd=cwd)
        return CliResult(stdout='', stderr='', returncode=0, latency_s=1.0)

    monkeypatch.chdir(tmp_path)
    run_agent(
        tmp_path, checkout, runner, cli='codex', model='gpt-6-astra', out='runs', workspaces='ws'
    )
    argv = seen['argv']
    assert os.path.isabs(argv[argv.index('-C') + 1]) and os.path.isabs(argv[argv.index('-o') + 1])
    assert argv[argv.index('-C') + 1] == seen['cwd']
