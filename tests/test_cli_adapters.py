"""The vendor-CLI adapters against a fake runner: rendering, argv, parsing, errors, the gate."""

import datetime as dt
import json
import pathlib

import pytest
from helpers import jsonl

from rulegen.gen.adapters.base import AbortRun, GenRequest, SamplingParams
from rulegen.gen.adapters.claude_cli import ClaudeCliAdapter
from rulegen.gen.adapters.cli_subprocess import (
    SEP_FEEDBACK,
    SEP_PREVIOUS,
    CliResult,
    UsageGate,
    child_env,
    classify,
    parse_reset_time,
    render_turns,
)
from rulegen.gen.adapters.codex_cli import CodexCliAdapter

TASK = [{'role': 'system', 'content': 'SYS'}, {'role': 'user', 'content': 'TASK'}]
REPAIR = [
    *TASK,
    {'role': 'assistant', 'content': '```\n/// Files: a.c\n```\n'},
    {'role': 'user', 'content': 'FEEDBACK'},
]

CLAUDE_OK = {
    'type': 'result',
    'subtype': 'success',
    'is_error': False,
    'duration_ms': 4200,
    'duration_api_ms': 4000,
    'num_turns': 1,
    'result': 'Here:\n```\n/// Files: net/foo.c\n@r@\n@@\n*\tkfree(sk);\n```\n',
    'session_id': 'sess-1',
    'total_cost_usd': 0.0123,
    'usage': {
        'input_tokens': 100,
        'cache_creation_input_tokens': 2000,
        'cache_read_input_tokens': 300,
        'output_tokens': 50,
        'output_tokens_details': {'thinking_tokens': 20},
    },
    'modelUsage': {'claude-fable-5-1': {'inputTokens': 100, 'outputTokens': 50}},
    'permission_denials': [],
}
CODEX_OK = [
    {'type': 'thread.started', 'thread_id': 'thr-1'},
    {'type': 'turn.started'},
    {'type': 'item.completed', 'item': {'id': 'i0', 'type': 'reasoning', 'text': 'thinking'}},
    {
        'type': 'item.completed',
        'item': {'id': 'i1', 'type': 'agent_message', 'text': '```\n/// Files: a.c\n```'},
    },
    {
        'type': 'turn.completed',
        'usage': {'input_tokens': 900, 'cached_input_tokens': 600, 'output_tokens': 40},
    },
]


class Runner:
    """A scripted CLI: each call pops the next (stdout, stderr, returncode) triple."""

    def __init__(self, *outputs) -> None:
        self.outputs = list(outputs)
        self.calls: list[dict] = []

    def __call__(self, argv, stdin_text, env, cwd, timeout_s) -> CliResult:
        self.calls.append({'argv': argv, 'stdin': stdin_text, 'env': env, 'cwd': cwd})
        out, err, rc = self.outputs.pop(0)
        return CliResult(stdout=out, stderr=err, returncode=rc, latency_s=0.01)


def claude(runner, tmp_path, **kw) -> ClaudeCliAdapter:
    return ClaudeCliAdapter(
        'fable',
        'medium',
        scratch_dir=str(tmp_path / 'scratch'),
        runner=runner,
        **{'sleep': lambda _s: None, **kw},
    )


def codex(runner, tmp_path, **kw) -> CodexCliAdapter:
    return CodexCliAdapter(
        'gpt-6-astra',
        'medium',
        scratch_dir=str(tmp_path / 'scratch'),
        runner=runner,
        **{'sleep': lambda _s: None, **kw},
    )


def error_result(message: str, subtype: str = 'error') -> str:
    """Claude Code's JSON for a request that failed with `message`."""
    return json.dumps({**CLAUDE_OK, 'subtype': subtype, 'is_error': True, 'result': message})


class FakeClock:
    """A clock the adapter's sleeps advance."""

    def __init__(self, start: float = 0.0) -> None:
        self.t = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


def request(messages=TASK) -> GenRequest:
    return GenRequest(messages, SamplingParams(), seed=0)


# -- rendering and environment ---------------------------------------------


def test_round_zero_renders_to_the_user_turn_verbatim():
    assert render_turns(TASK) == ('SYS', 'TASK')


def test_repair_turn_renders_reply_and_feedback_under_the_separators():
    system, prompt = render_turns(REPAIR)
    assert system == 'SYS'
    assert (
        prompt == 'TASK' + SEP_PREVIOUS + '```\n/// Files: a.c\n```\n' + SEP_FEEDBACK + 'FEEDBACK'
    )


def test_child_env_strips_session_and_api_key_variables():
    base = {
        'PATH': '/bin',
        'HOME': '/h',
        'CLAUDECODE': '1',
        'CLAUDE_CODE_SESSION_ID': 'x',
        'CLAUDE_PID': '1',
        'CLAUDE_EFFORT': 'max',
        'OPENAI_API_KEY': 'sk',
        'ANTHROPIC_API_KEY': 'sk',
        'MAX_THINKING_TOKENS': '5',
        'CODEX_HOME': '/c',
    }
    env = child_env({'EXTRA': '1'}, base=base)
    assert env == {'PATH': '/bin', 'HOME': '/h', 'CODEX_HOME': '/c', 'EXTRA': '1'}


# -- claude ----------------------------------------------------------------


def test_claude_argv_env_and_parsing(tmp_path):
    runner = Runner((json.dumps(CLAUDE_OK), '', 0))
    adapter = claude(runner, tmp_path, thinking=False, config_dir='/cfg', cli_args=('--x',))
    comp = adapter.complete(request(REPAIR))
    call = runner.calls[0]
    argv = call['argv']
    assert argv[:4] == ['claude', '-p', '--output-format', 'json']
    assert argv[argv.index('--model') + 1] == 'fable'
    assert argv[argv.index('--effort') + 1] == 'medium'
    assert argv[argv.index('--tools') + 1] == ''
    assert argv[argv.index('--setting-sources') + 1] == ''
    assert '--restricted' in argv and '--no-session-persistence' in argv and '--x' in argv
    system_path = argv[argv.index('--system-prompt-file') + 1]
    assert pathlib.Path(system_path).read_text() == 'SYS'
    assert call['stdin'].startswith('TASK' + SEP_PREVIOUS)
    assert call['env']['CLAUDE_CONFIG_DIR'] == '/cfg' and call['env']['MAX_THINKING_TOKENS'] == '0'
    assert 'OPENAI_API_KEY' not in call['env']
    assert comp.error is None and comp.text.startswith('Here:')
    assert (comp.tokens_prompt, comp.tokens_completion, comp.tokens_cached) == (2400, 50, 300)
    assert comp.tokens_reasoning == 20
    assert comp.cost_usd == 0.0123 and comp.request_id == 'sess-1' and comp.attempts == 1
    assert comp.raw['tool_calls'] == 0
    assert adapter.resolved_model == 'claude-fable-5-1'
    desc = adapter.describe()
    assert desc['sampling'] == 'provider-default' and desc['effort'] == 'medium'
    assert desc['system_channel'] == 'system-prompt-file' and desc['thinking'] is False


def test_claude_keeps_a_reply_after_a_refused_tool_call(tmp_path):
    denied = {**CLAUDE_OK, 'num_turns': 2, 'permission_denials': [{'tool_name': 'Bash'}]}
    runner = Runner((json.dumps(denied), '', 0))
    adapter = claude(runner, tmp_path)
    comp = adapter.complete(request())
    assert comp.error is None and comp.text.startswith('Here:') and comp.attempts == 1
    assert comp.raw['tool_attempts_denied'] == 1 and comp.raw['tool_calls'] == 0
    assert len(runner.calls) == 1 and adapter.tool_retries == 0
    assert adapter.describe()['tool_attempts_denied'] == 1


def test_claude_retries_a_reply_after_a_tool_that_ran(tmp_path):
    ran = {**CLAUDE_OK, 'num_turns': 3}  # two extra turns, nothing denied: a tool ran
    runner = Runner((json.dumps(ran), '', 0), (json.dumps(CLAUDE_OK), '', 0))
    adapter = claude(runner, tmp_path)
    comp = adapter.complete(request())
    assert comp.error is None and comp.attempts == 2 and adapter.tool_retries == 1
    assert comp.raw['tool_calls'] == 0


def test_claude_reply_whose_tools_keep_running_is_logged_flagged(tmp_path):
    ran = {**CLAUDE_OK, 'num_turns': 2}
    runner = Runner(*[(json.dumps(ran), '', 0)] * 3)
    comp = claude(runner, tmp_path, max_retries=2).complete(request())
    assert comp.text.startswith('Here:')
    assert comp.error.startswith('tool ran in a direct-response cell')
    assert comp.attempts == 3 and comp.raw['tool_calls'] == 1


def test_claude_error_result_is_an_error_row(tmp_path):
    failed = error_result('Something broke', 'error_during_execution')
    comp = claude(Runner((failed, '', 1)), tmp_path).complete(request())
    assert comp.text == '' and comp.error.startswith('error_during_execution: Something broke')
    assert comp.raw['error_kind'] == 'fatal'


def test_claude_no_json_uses_stderr(tmp_path):
    comp = claude(Runner(('', 'boom: unexpected failure', 2)), tmp_path).complete(request())
    assert comp.error.startswith('no JSON result (exit 2): boom')


# -- codex -----------------------------------------------------------------


def test_codex_argv_env_and_parsing(tmp_path):
    home = tmp_path / 'codex-home'
    for skill in ('skills/mine', 'skills/.system/sys'):
        (home / skill).mkdir(parents=True)
        (home / skill / 'SKILL.md').write_text('# s\n')
    runner = Runner((jsonl(CODEX_OK), 'warning: x', 0))
    adapter = codex(runner, tmp_path, config_dir=str(home))
    comp = adapter.complete(request())
    call = runner.calls[0]
    argv = call['argv']
    assert argv[:3] == ['codex', 'exec', '--json']
    assert argv[argv.index('-m') + 1] == 'gpt-6-astra'
    assert 'model_reasoning_effort="medium"' in argv and 'tools.web_search=false' in argv
    instructions = next(a for a in argv if a.startswith('model_instructions_file='))
    assert pathlib.Path(instructions.split('=', 1)[1].strip('"')).read_text() == 'SYS'
    assert argv[argv.index('-s') + 1] == 'read-only' and '--ignore-user-config' in argv
    assert '--ephemeral' in argv and '--skip-git-repo-check' in argv and argv[-1] == '-'
    assert argv[argv.index('-C') + 1] == call['cwd'] == adapter.scratch
    skills = next(a for a in argv if a.startswith('skills.config='))
    assert str(home / 'skills' / 'mine' / 'SKILL.md') in skills and 'enabled=false' in skills
    assert str(home / 'skills' / '.system' / 'sys' / 'SKILL.md') in skills
    disabled = [argv[i + 1] for i, a in enumerate(argv) if a == '--disable']
    assert {'shell_tool', 'unified_exec', 'plugins', 'hooks', 'browser_use', 'computer_use'} <= set(
        disabled
    )
    assert call['stdin'] == 'TASK' and call['env']['CODEX_HOME'] == str(home)
    assert call['env']['PATH'].endswith('/usr/bin:/bin') and '.local/bin' not in call['env']['PATH']
    assert comp.error is None and comp.text == '```\n/// Files: a.c\n```'
    assert comp.reasoning == 'thinking' and comp.request_id == 'thr-1'
    assert (comp.tokens_prompt, comp.tokens_completion, comp.tokens_cached) == (900, 40, 600)
    assert adapter.describe()['system_channel'] == 'model_instructions_file'


def test_codex_retries_tool_items_and_reads_the_output_file_when_the_stream_lacks_the_reply(
    tmp_path,
):
    with_tool = [
        CODEX_OK[0],
        {'type': 'item.completed', 'item': {'type': 'command_execution', 'command': 'ls'}},
        CODEX_OK[-1],
    ]
    calls = {'n': 0}

    def runner(argv, stdin_text, env, cwd, timeout_s):
        calls['n'] += 1
        out_path = argv[argv.index('-o') + 1]
        with open(out_path, 'w') as fh:
            fh.write('from file')
        events = with_tool if calls['n'] == 1 else [CODEX_OK[0], CODEX_OK[-1]]
        return CliResult(stdout=jsonl(events), stderr='', returncode=0, latency_s=0.0)

    adapter = codex(runner, tmp_path)
    comp = adapter.complete(request())
    assert comp.error is None and comp.text == 'from file' and comp.attempts == 2
    assert adapter.tool_retries == 1


def test_codex_turn_failed_is_an_error_row(tmp_path):
    events = [CODEX_OK[0], {'type': 'turn.failed', 'error': {'message': 'model refused'}}]
    comp = codex(Runner((jsonl(events), '', 1)), tmp_path).complete(request())
    assert comp.text == '' and 'model refused' in comp.error and comp.raw['error_kind'] == 'fatal'


def test_codex_warning_beside_a_reply_is_kept_not_fatal(tmp_path):
    warning = 'Codex is ignoring 1 unrecognized configuration setting.'
    events = [{'type': 'error', 'message': warning}, *CODEX_OK]
    comp = codex(Runner((jsonl(events), '', 0)), tmp_path).complete(request())
    assert comp.error is None and comp.text.startswith('```') and comp.raw['warnings'] == [warning]


def test_codex_stream_error_without_a_reply_names_the_error(tmp_path):
    events = [CODEX_OK[0], {'type': 'error', 'message': 'unexpected item in the event stream'}]
    comp = codex(Runner((jsonl(events), '', 1)), tmp_path).complete(request())
    assert 'unexpected item in the event stream' in comp.error and 'None' not in comp.error


# -- errors and the gate ---------------------------------------------------


@pytest.mark.parametrize(
    'text, kind',
    [
        ('You have hit your usage limit. Resets at 3pm.', 'usage_limit'),
        ("You've hit your session limit · resets 7am (Europe/Berlin)", 'usage_limit'),
        (
            "success: You've reached your Fable limit. Switch to another model, or manage usage credits",
            'usage_limit',
        ),
        ('429 Too Many Requests', 'usage_limit'),
        ('Not logged in. Please run /login', 'auth'),
        ('401 Unauthorized', 'auth'),
        ('fetch failed: ECONNRESET', 'transient'),
        ('API Error: 529 overloaded', 'transient'),
        ('the model produced no rule', 'fatal'),
    ],
)
def test_classify(text, kind):
    assert classify(text) == kind


NOW = 1_700_000_000.0


@pytest.mark.parametrize(
    ('text', 'reset'),
    [
        ('reset in 2h 13m', NOW + 2 * 3600 + 13 * 60),
        ('try again in 45 minutes', NOW + 45 * 60),
        ('Retry-After: 120', NOW + 120),
        (
            'limit reached, resets at 2026-09-24 18:00 UTC',
            dt.datetime(2026, 9, 24, 18, 0, tzinfo=dt.UTC).timestamp(),
        ),
        ('reached your Fable limit. Switch to another model', None),
        ('no time here', None),
    ],
)
def test_parse_reset_time(text, reset):
    assert parse_reset_time(text, NOW) == reset


@pytest.mark.parametrize(
    'text', ['resets at 3pm (UTC)', "You've hit your session limit · resets 7am (Europe/Berlin)"]
)
def test_a_reset_clock_time_is_the_next_one(text):
    assert 0 < parse_reset_time(text, NOW) - NOW <= 24 * 3600


def test_usage_gate_pauses_until_reset_then_backs_off_and_aborts_past_the_cap():
    clock = FakeClock(1000.0)
    gate = UsageGate(cap_s=3600, clock=clock, sleep=clock.sleep, margin_s=10)
    assert gate.pause(1300.0, 'resets in 5 min') == 310.0
    gate.wait_if_paused()
    assert clock.t == 1310.0 and sum(clock.slept) == 310.0
    # No reset time: 15 min, then 30 min.
    assert gate.pause(None, 'limit') == 900.0
    gate.wait_if_paused()
    assert gate.pause(None, 'limit') == 1800.0
    gate.wait_if_paused()
    with pytest.raises(AbortRun, match='past the 1.0 h cap'):
        gate.pause(clock.t + 5 * 3600, 'weekly limit')
    assert gate.pauses == 3


def test_complete_waits_out_a_usage_limit_without_spending_an_attempt(tmp_path):
    limit = error_result('usage limit reached, resets in 1m')
    clock = FakeClock()
    runner = Runner((limit, '', 1), (json.dumps(CLAUDE_OK), '', 0))
    adapter = claude(runner, tmp_path, clock=clock, sleep=clock.sleep, max_retries=0)
    comp = adapter.complete(request())
    assert comp.error is None and comp.attempts == 1 and comp.raw['usage_waits'] == 1
    assert clock.t >= 60 and adapter.gate.pauses == 1


def test_complete_retries_transient_then_gives_up_with_the_last_error(tmp_path):
    runner = Runner(('', 'fetch failed', 1), ('', 'fetch failed', 1), ('', 'fetch failed', 1))
    comp = claude(runner, tmp_path, max_retries=2).complete(request())
    assert comp.error.startswith('no JSON result') and comp.attempts == 3
    assert len(runner.calls) == 3


def test_auth_failure_aborts_the_run_after_the_waits(tmp_path):
    runner = Runner(*[('', 'Not logged in. Please run /login', 1)] * 4)
    slept = []
    adapter = claude(runner, tmp_path, sleep=slept.append)
    with pytest.raises(AbortRun, match='not authenticated'):
        adapter.complete(request())
    assert len(runner.calls) == 4 and slept == [60.0, 120.0, 240.0]


def test_an_auth_blip_is_ridden_out(tmp_path):
    runner = Runner(
        ('', 'stream disconnected: 401 Unauthorized', 1), (json.dumps(CLAUDE_OK), '', 0)
    )
    slept = []
    adapter = claude(runner, tmp_path, sleep=slept.append)
    comp = adapter.complete(request())
    assert comp.error is None and comp.attempts == 1 and slept == [60.0]


def test_codex_keeps_a_reply_after_a_tool_call_the_router_refused(tmp_path):
    runner = Runner(
        (jsonl(CODEX_OK), 'ERROR codex_core::tools::router: error=code-mode host is disabled', 0),
    )
    adapter = codex(runner, tmp_path)
    comp = adapter.complete(request())
    assert comp.error is None and comp.attempts == 1 and adapter.tool_retries == 0
    assert comp.raw['tool_attempts_denied'] == 1 and comp.raw['tool_calls'] == 0


ODD = error_result('Mysterious backend failure 42')


def test_a_run_of_identical_unknown_errors_aborts_the_run(tmp_path):
    runner = Runner(*[(ODD, '', 1)] * 8)
    adapter = claude(runner, tmp_path, max_retries=0)
    for _ in range(7):
        assert adapter.complete(request()).error.startswith('error: Mysterious backend')
    with pytest.raises(AbortRun, match='8 requests in a row failed'):
        adapter.complete(request())


def test_a_success_resets_the_error_streak(tmp_path):
    runner = Runner(*[(ODD, '', 1)] * 7, (json.dumps(CLAUDE_OK), '', 0), *[(ODD, '', 1)] * 7)
    adapter = claude(runner, tmp_path, max_retries=0)
    for _ in range(15):
        adapter.complete(request())  # never 8 in a row: no abort
