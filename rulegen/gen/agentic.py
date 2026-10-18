"""Agentic rule writing: an agent with the maintainer's own tools writes the rule.

The direct-response cells hand a model our prompt and take its one reply. This
arm hands an agent (Claude Code or Codex) what a CVEhound maintainer has: the
cvehound checkout with its `write-cve-rule` skill, the validator, the kernel
clone and the unmodified test suite, and asks it to add the rule for one CVE.
One session per CVE, capped in wall clock and tool calls, no network.

Each session runs in a fresh export of the checkout with the target's rule
removed and the git history discarded (a single commit), so neither the file
nor `git log -p` can hand the agent the gold rule; the workspace gets its own
editable venv because cvehound resolves rules from the *installed* package's
`cvehound/cve/`, and a shared venv would import the original checkout where
the rule still exists. The rule the agent leaves behind is scored by the same
oracle as every other arm, and the suite audits it afterwards.
"""

import collections
import concurrent.futures as cf
import dataclasses
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

from rulegen import corpus, extract, tables, tiers
from rulegen.gen import manifest as manifest_mod
from rulegen.gen.adapters import codex_cli
from rulegen.gen.adapters.claude_cli import prompt_tokens
from rulegen.gen.adapters.cli_subprocess import (
    CliResult,
    Runner,
    child_env,
    cli_version,
    jsonl_events,
    run_cli,
)
from rulegen.gen.log import SampleLog, SampleRow, attempt_id, score_counts
from rulegen.git import GitError, git, git_run
from rulegen.oracle.service import OracleConfig, OracleService
from rulegen.promptbuild import Finalized, finalize_completion
from rulegen.schema import CveRecord, Score, ScoreRequest

log = logging.getLogger(__name__)

TASK_VERSION = 'agent-task-v1'
# Codex add-ons the agent does not need, as in the direct cells; the shell, exec
# and patch tools stay on.
AGENT_CODEX_DISABLED = tuple(
    f for f in codex_cli.DISABLED_FEATURES if f not in codex_cli.SHELL_FEATURES
)
RULE_DIRS = ('cvehound/cve', 'cvehound/cve/disputed')
SKIP_DIRS = frozenset({'.git', '.venv', 'linux', '__pycache__', '.result_cache', 'node_modules'})
PYTEST_RE = re.compile(r'\bpytest\b[^\n]*--runslow')
VALIDATOR_RE = re.compile(r'validate-rule\.sh')
PASSED_RE = re.compile(r'\b(\d+) passed\b')
FAILED_RE = re.compile(r'\b(\d+) (failed|errors?)\b')
# Commands the agent must not run: anything that reaches the network or
# rewrites the shared kernel clone. The hook below blocks them for Claude Code;
# codex's sandbox denies the network and the parse flags them either way.
BLOCKED_COMMAND_RE = (
    r'\bgit\b[^|;&]*\b(fetch|pull|push|clone|remote\s+add|worktree\s+add|worktree\s+remove)\b'
    r'|\bgit\s+-C\s+\S*linux\S*\s+(checkout|reset|clean|switch|restore|stash|gc|prune)\b'
    r'|\bcurl\b|\bwget\b|\bpip3?\s+install\b|\buv\s+(add|pip|sync|tool)\b|\bnpm\b|\bssh\b|\bnc\b|\bapt(-get)?\b'
)

GUARD_HOOK = r"""#!/usr/bin/env bash
# PreToolUse guard for an agent session: caps tool calls and blocks network and
# kernel-rewriting commands. Exit 2 = block the call and tell the model why.
set -u
dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"
input=$(cat)
count_file="$dir/.agent-toolcalls"
n=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$count_file"
max=${AGENT_MAX_TOOL_CALLS:-__MAX__}
if [ "$n" -gt "$max" ]; then
    echo "tool-call budget of $max exhausted: write the best rule you have and stop" >&2
    exit 2
fi
cmd=$(printf '%s' "$input" | python3 -c 'import json,sys
d=json.load(sys.stdin); print(d.get("tool_input",{}).get("command",""))' 2>/dev/null || echo)
if printf '%s' "$cmd" | grep -qE '__BLOCKED__'; then
    echo "blocked: no network access and no changes to the kernel clone in this session" >&2
    exit 2
fi
exit 0
"""

TASK_PROMPT = """Add a CVEhound detection rule for {cve}.

- CVE: {cve}
- Fix commit (mainline): {fix}
- {anchor_kind}: {fixes}
- Fix subject: {subject}

Use the write-cve-rule skill. The kernel clone is at tests/linux: read it with git
(`git -C tests/linux show <commit>`, `git -C tests/linux log ...`); never fetch, check
out, reset or modify it. Write the rule to cvehound/cve/{cve}.cocci, run
.agents/skills/write-cve-rule/scripts/validate-rule.sh on it, then run
`uv run pytest --runslow --cve={cve}` and iterate until the suite passes or your
budget is spent. No network access. Edit nothing but that one rule file; do not
commit. End with the rule path and whether the suite passed.
"""


@dataclass(frozen=True)
class AgentConfig:
    run_id: str
    cli: str  # claude | codex
    model: str
    effort: str = 'medium'
    split: str = 'newrule'  # corpus split of the CVEs (examples file: `examples_split`)
    examples_split: str = ''  # examples parquet name when it differs (newrule200)
    subset: str = ''  # id-list file
    limit: int = 0
    repetitions: int = 1
    max_wall_s: float = 2700.0
    max_tool_calls: int = 200
    jobs: int = 2
    suite_workers: int = 4
    suite_tmpdir: str = ''
    config_dir: str = ''
    cli_bin: str = ''
    keep_venv: bool = False
    out: str = 'runs'
    workspaces: str = 'runs/agent-workspaces'
    notes: str = ''

    def identity(self) -> dict[str, Any]:
        """What defines the cell: not paths, caps on the machine, or labels."""
        data = dataclasses.asdict(self)
        for key in (
            'run_id',
            'notes',
            'out',
            'workspaces',
            'jobs',
            'suite_workers',
            'suite_tmpdir',
            'config_dir',
            'cli_bin',
            'keep_venv',
        ):
            data.pop(key, None)
        return data

    def sha(self) -> str:
        canonical = json.dumps(self.identity(), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Workspace:
    path: str
    cve: str
    removed: list[str]
    mentions: list[str]
    venv_ok: bool | None = None
    venv_note: str = ''


@dataclass
class AgentTrace:
    """What one session did, read off the CLI's event stream."""

    message: str = ''
    request_id: str | None = None
    resolved_model: str | None = None
    num_turns: int | None = None
    tool_calls: int = 0
    tool_names: collections.Counter = field(default_factory=collections.Counter)
    blocked_commands: int = 0
    pytest_ran: bool = False
    pytest_passed: bool | None = None
    pytest_tail: str = ''
    validator_ran: bool = False
    cost_usd: float | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    duration_ms: int | None = None
    error: str | None = None
    events: int = 0


# -- the workspace ------------------------------------------------------------


def task_prompt(rec: CveRecord) -> str:
    kind = (
        'Detect-To boundary (the oldest commit the rule must still fire at)'
        if rec.fixes_kind == 'detect-to'
        else 'Introducing commit (Fixes:)'
    )
    return TASK_PROMPT.format(
        cve=rec.cve,
        fix=rec.fix,
        anchor_kind=kind,
        fixes=rec.fixes or 'unknown',
        subject=rec.cmt_subject or '(no subject recorded)',
    )


def rule_files(root: str, cve: str) -> list[str]:
    """The CVE's rule files in a checkout, relative to it, in the order cvehound looks."""
    return [
        rel
        for rule_dir in RULE_DIRS
        for suffix in ('.cocci', '.grep')
        if os.path.exists(os.path.join(root, rel := os.path.join(rule_dir, f'{cve}{suffix}')))
    ]


def find_mentions(root: str, cve: str) -> list[str]:
    """Files under `root` (skipping the kernel, venv and git) that name the CVE."""
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > 8 << 20 or os.path.islink(path):
                    continue
                with open(path, errors='replace') as fh:
                    if cve in fh.read():
                        hits.append(os.path.relpath(path, root))
            except OSError:
                continue
    return sorted(hits)


def write_claude_guard(dest: str, max_tool_calls: int) -> None:
    """Project settings + a PreToolUse hook for the session (Claude Code reads both from cwd)."""
    hooks_dir = os.path.join(dest, '.claude', 'hooks')
    os.makedirs(hooks_dir, exist_ok=True)
    guard = os.path.join(hooks_dir, 'agent-guard.sh')
    with open(guard, 'w') as fh:
        fh.write(
            GUARD_HOOK.replace('__MAX__', str(max_tool_calls)).replace(
                '__BLOCKED__', BLOCKED_COMMAND_RE
            )
        )
    os.chmod(guard, 0o755)
    settings_path = os.path.join(dest, '.claude', 'settings.json')
    settings: dict[str, Any] = {}
    if os.path.exists(settings_path):
        with open(settings_path) as fh:
            try:
                settings = json.load(fh)
            except ValueError:
                settings = {}
    permissions = settings.setdefault('permissions', {})
    deny = list(permissions.get('deny') or [])
    for rule in (
        'WebFetch',
        'WebSearch',
        'Bash(git fetch*)',
        'Bash(git pull*)',
        'Bash(git push*)',
        'Bash(git clone*)',
        'Bash(curl*)',
        'Bash(wget*)',
    ):
        if rule not in deny:
            deny.append(rule)
    permissions['deny'] = deny
    hooks = settings.setdefault('hooks', {})
    hooks['PreToolUse'] = [
        {
            'matcher': '',
            'hooks': [
                {'type': 'command', 'command': '"$CLAUDE_PROJECT_DIR"/.claude/hooks/agent-guard.sh'}
            ],
        }
    ]
    with open(settings_path, 'w') as fh:
        json.dump(settings, fh, indent=1)


def export_workspace(
    cvehound_repo: str,
    kernel: str,
    cve: str,
    dest: str,
    guard: str | None = 'claude',
    max_tool_calls: int = 200,
    sync_venv: bool = True,
) -> Workspace:
    """A single-commit copy of the checkout without the CVE's rule, wired to the kernel."""
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    archive = subprocess.Popen(
        ['git', '-C', cvehound_repo, 'archive', '--format=tar', 'HEAD'], stdout=subprocess.PIPE
    )
    subprocess.run(['tar', '-x', '-C', dest], stdin=archive.stdout, check=True)
    archive.wait()
    if archive.returncode != 0:
        raise RuntimeError(f'git archive of {cvehound_repo} failed')
    removed = rule_files(dest, cve)
    for rel in removed:
        os.remove(os.path.join(dest, rel))
    mentions = find_mentions(dest, cve)
    if guard == 'claude':
        write_claude_guard(dest, max_tool_calls)
    git(dest, 'init', '-q', '-b', 'main')
    git(dest, 'add', '-A')
    git(
        dest,
        '-c',
        'user.name=agent',
        '-c',
        'user.email=agent@localhost',
        'commit',
        '-q',
        '-m',
        f'workspace for {cve}',
    )
    linux = os.path.join(dest, 'tests', 'linux')
    os.makedirs(os.path.dirname(linux), exist_ok=True)
    if os.path.lexists(linux):
        os.remove(linux)
    os.symlink(os.path.abspath(kernel), linux)
    ws = Workspace(path=dest, cve=cve, removed=removed, mentions=mentions)
    if sync_venv:
        ws.venv_ok, ws.venv_note = sync_workspace_venv(dest)
    return ws


def sync_workspace_venv(dest: str, uv: str = 'uv') -> tuple[bool, str]:
    """An editable install of the workspace's own cvehound, hardlinked from the uv cache."""
    env = child_env({'UV_LINK_MODE': 'hardlink'})
    env.pop('VIRTUAL_ENV', None)
    env.pop('UV_PROJECT_ENVIRONMENT', None)
    proc = subprocess.run(
        [uv, 'sync', '--extra', 'spatch', '--group', 'test'],
        cwd=dest,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False, f'uv sync failed: {proc.stderr.strip()[-500:]}'
    check = subprocess.run(
        [
            os.path.join(dest, '.venv', 'bin', 'python'),
            '-c',
            'import os, cvehound; print(os.path.dirname(os.path.abspath(cvehound.__file__)))',
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    where = check.stdout.strip()
    if not where.startswith(os.path.abspath(dest)):
        return False, f'cvehound imports from {where!r}, not the workspace'
    return True, where


def _is_kernel_clone(repo: str, kernel_markers: tuple[str, ...]) -> bool:
    """A git repo (worktree or bare) whose alternates or remotes point at the kernel clone."""
    for git_dir in (os.path.join(repo, '.git'), repo):
        for rel in (os.path.join('objects', 'info', 'alternates'), 'config'):
            path = os.path.join(git_dir, rel)
            try:
                with open(path, errors='replace') as fh:
                    text = fh.read(65536)
            except OSError:
                continue
            if any(marker in text for marker in kernel_markers):
                return True
    return False


def scratch_clones(roots: list[str], since: float, kernel: str) -> list[str]:
    """Top-level directories under `roots`, created at or after `since`, holding a kernel clone.

    Codex's sandbox keeps `.git` read-only, so a codex agent that wants to run the
    suite clones the kernel into a scratch dir (over a gigabyte each) and never
    removes it. Only clones of the kernel itself count -- recognised by
    an alternates file or a remote naming the kernel clone -- so nothing else in a
    shared temp dir is ever touched.
    """
    real = os.path.realpath(kernel)
    markers = tuple(dict.fromkeys((real, os.path.abspath(kernel), 'tests/linux')))
    found = []
    for root in dict.fromkeys(r for r in roots if r and os.path.isdir(r)):
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.stat(follow_symlinks=False).st_ctime < since:
                    continue
            except OSError:
                continue
            subdirs = _subdirs(entry.path)
            candidates = [entry.path, *(os.path.join(entry.path, sub) for sub in subdirs)]
            # A session's own suite temp root (TMPDIR=/tmp/cvehound-CVE-...-tests)
            # holds branch worktrees of such a clone, several GB each.
            suite_root = any(sub.startswith('cvehound-worktrees-') for sub in subdirs)
            if suite_root or any(_is_kernel_clone(c, markers) for c in candidates):
                found.append(entry.path)
    return sorted(found)


def _subdirs(path: str) -> list[str]:
    try:
        return [e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []


def remove_scratch_clones(roots: list[str], since: float, kernel: str) -> list[str]:
    removed = scratch_clones(roots, since, kernel)
    for path in removed:
        shutil.rmtree(path, ignore_errors=True)
    if removed:
        # Worktrees the session added to the real clone now point nowhere.
        git_run(kernel, 'worktree', 'prune')
    return removed


def kernel_state(kernel: str) -> str:
    """A digest of the clone's working tree, HEAD and worktree list."""
    parts = []
    for args in (
        ['status', '--porcelain'],
        ['rev-parse', 'HEAD'],
        ['worktree', 'list', '--porcelain'],
    ):
        try:
            parts.append(git(kernel, *args))
        except (GitError, OSError) as err:
            parts.append(f'error: {err!r}')
    return hashlib.sha256('\n'.join(parts).encode()).hexdigest()


# -- invocations -----------------------------------------------------------


def agent_argv(cfg: AgentConfig, ws: Workspace, kernel: str, out_path: str) -> list[str]:
    binary = cfg.cli_bin or cfg.cli
    if cfg.cli == 'claude':
        return [
            binary,
            '-p',
            '--output-format',
            'stream-json',
            '--verbose',
            '--model',
            cfg.model,
            '--effort',
            cfg.effort,
            '--dangerously-skip-permissions',
            '--disallowedTools',
            'WebFetch,WebSearch',
            '--setting-sources',
            'project',
            '--no-session-persistence',
        ]
    if cfg.cli == 'codex':
        argv = [
            binary,
            'exec',
            '--json',
            '--ignore-user-config',
            '-m',
            cfg.model,
            '-c',
            f'model_reasoning_effort="{cfg.effort}"',
            '-c',
            'tools.web_search=false',
            '-c',
            'sandbox_workspace_write.network_access=false',
            '-s',
            'workspace-write',
            '--add-dir',
            os.path.abspath(kernel),
            '-C',
            ws.path,
            '--skip-git-repo-check',
            '--ephemeral',
            '-o',
            out_path,
        ]
        if cfg.suite_tmpdir:
            argv += ['--add-dir', os.path.abspath(cfg.suite_tmpdir)]
        # The user's own Codex skills and add-ons are not part of a maintainer's
        # cvehound setup: hide them as the direct cells do.
        # The repo's .agents/skills (write-cve-rule) stay visible, and the agent
        # keeps its shell and patch tools.
        personal = codex_cli.discovered_skills(codex_cli.codex_home(cfg.config_dir))
        if personal:
            argv += ['-c', f'skills.config={codex_cli.skills_config(personal)}']
        for feature in AGENT_CODEX_DISABLED:
            argv += ['--disable', feature]
        return [*argv, '-']
    raise ValueError(f'unknown cli {cfg.cli!r}')


def agent_env(cfg: AgentConfig, ws: Workspace, cvehound_repo: str) -> dict[str, str]:
    venv = os.path.join(ws.path, '.venv')
    extra = {
        'PATH': os.path.join(venv, 'bin') + os.pathsep + os.environ.get('PATH', ''),
        'VIRTUAL_ENV': venv,
        'UV_NO_SYNC': '1',
        'UV_OFFLINE': '1',
        'UV_LINK_MODE': 'hardlink',
        'CVEHOUND_TEST_OFFLINE': '1',
        'PYTEST_ADDOPTS': f'-n {cfg.suite_workers}',
        'AGENT_MAX_TOOL_CALLS': str(cfg.max_tool_calls),
    }
    blob = os.path.join(cvehound_repo, 'cvehound', 'data', 'kernel_cves.json.gz')
    if os.path.exists(blob):
        extra['CVEHOUND_METADATA'] = os.path.abspath(blob)
    if cfg.suite_tmpdir:
        extra['TMPDIR'] = os.path.abspath(cfg.suite_tmpdir)
    if cfg.cli == 'claude' and cfg.config_dir:
        extra['CLAUDE_CONFIG_DIR'] = cfg.config_dir
    if cfg.cli == 'codex' and cfg.config_dir:
        extra['CODEX_HOME'] = cfg.config_dir
    env = child_env(extra)
    env.pop('CVEHOUND_CONTENT', None)  # the workspace's own rules must win
    return env


# -- reading what the agent did ------------------------------------------------


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return '\n'.join(
            _text_of(c.get('text') or c.get('content') or '') if isinstance(c, dict) else str(c)
            for c in content
        )
    return str(content or '')


def _pytest_verdict(output: str, exit_code: int | None) -> bool | None:
    passed = PASSED_RE.search(output)
    failed = FAILED_RE.search(output)
    if exit_code is not None:
        if exit_code == 0 and passed:
            return True
        if exit_code != 0:
            return False
    if passed and not failed:
        return True
    if failed:
        return False
    return None


def _note_command(trace: AgentTrace, command: str) -> None:
    """What a shell command says about the session: the validator ran, or a blocked command."""
    if VALIDATOR_RE.search(command):
        trace.validator_ran = True
    if re.search(BLOCKED_COMMAND_RE, command):
        trace.blocked_commands += 1


def _note_pytest(trace: AgentTrace, output: str, passed: bool | None) -> None:
    trace.pytest_ran = True
    trace.pytest_passed = passed
    trace.pytest_tail = output[-1500:]


def parse_claude_stream(text: str) -> AgentTrace:
    """Claude Code's stream-json: tool_use blocks, their results, and the final result."""
    trace = AgentTrace()
    events = jsonl_events(text)
    trace.events = len(events)
    pending: dict[str, str] = {}  # tool_use id -> command
    for event in events:
        kind = event.get('type')
        if kind == 'system' and event.get('subtype') == 'init':
            trace.request_id = event.get('session_id') or trace.request_id
            trace.resolved_model = event.get('model') or trace.resolved_model
        elif kind == 'assistant':
            for block in (event.get('message') or {}).get('content') or []:
                if not isinstance(block, dict) or block.get('type') != 'tool_use':
                    continue
                trace.tool_calls += 1
                trace.tool_names[str(block.get('name') or '')] += 1
                command = str((block.get('input') or {}).get('command') or '')
                if command:
                    pending[str(block.get('id'))] = command
                    _note_command(trace, command)
        elif kind == 'user':
            for block in (event.get('message') or {}).get('content') or []:
                if not isinstance(block, dict) or block.get('type') != 'tool_result':
                    continue
                command = pending.pop(str(block.get('tool_use_id')), '')
                if command and PYTEST_RE.search(command):
                    output = _text_of(block.get('content'))
                    verdict = _pytest_verdict(output, None)
                    if block.get('is_error'):
                        verdict = False if verdict is None else verdict
                    _note_pytest(trace, output, verdict)
        elif kind == 'result':
            trace.message = str(event.get('result') or '')
            trace.num_turns = event.get('num_turns')
            trace.cost_usd = event.get('total_cost_usd')
            trace.usage = event.get('usage') or {}
            trace.duration_ms = event.get('duration_ms')
            trace.request_id = event.get('session_id') or trace.request_id
            model_usage = event.get('modelUsage') or {}
            if model_usage:
                trace.resolved_model = next(iter(model_usage))
            if event.get('is_error') or event.get('subtype') not in (None, 'success'):
                trace.error = f'{event.get("subtype")}: {trace.message[:500]}'
    return trace


def parse_codex_stream(text: str, out_path: str | None = None) -> AgentTrace:
    """codex exec --json: command items with their output, the final message, usage."""
    stream = codex_cli.read_events(jsonl_events(text))
    trace = AgentTrace(
        events=stream.events,
        request_id=stream.thread_id,
        resolved_model=stream.model,
        message=stream.message or '',
        num_turns=stream.messages or None,
        tool_calls=len(stream.tools),
        usage=stream.usage,
    )
    for item in stream.tools:
        trace.tool_names[str(item.get('type'))] += 1
        if item.get('type') != 'command_execution':
            continue
        command = str(item.get('command') or '')
        _note_command(trace, command)
        if PYTEST_RE.search(command):
            output = str(item.get('aggregated_output') or '')
            _note_pytest(trace, output, _pytest_verdict(output, item.get('exit_code')))
    if not trace.message and out_path and os.path.exists(out_path):
        with open(out_path) as fh:
            trace.message = fh.read()
    if stream.errors:
        trace.error = '; '.join(stream.errors)[:800]
    return trace


def collect_rule(ws: Workspace) -> tuple[str | None, str | None]:
    """The rule file the agent left, and its path relative to the workspace."""
    for rel in rule_files(ws.path, ws.cve):
        with open(os.path.join(ws.path, rel), errors='replace') as fh:
            return fh.read(), rel
    return None, None


# -- one session, then the run -------------------------------------------------


def session_row(cfg: AgentConfig, rec: CveRecord, cls: str, rep: int, prompt: str) -> SampleRow:
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    return SampleRow(
        run_id=cfg.run_id,
        config_sha=cfg.sha(),
        cve=rec.cve,
        split=rec.split,
        cls=cls,
        mode='agentic',
        policy='agent',
        prompt_sha=prompt_sha,
        messages_sha=prompt_sha,
        system_prompt_id=TASK_VERSION,
        system_sha=hashlib.sha256(TASK_PROMPT.encode()).hexdigest(),
        adapter=f'{cfg.cli}-agent',
        model_id=cfg.model,
        temperature=0.0,
        top_p=0.0,
        max_tokens=0,
        thinking=None,
        seed=rep,
        sample_index=rep,
        attempt_id=attempt_id(rec.cve, rep, 0),
        sampling_honored=False,
    )


def run_session(
    cfg: AgentConfig,
    rec: CveRecord,
    cls: str,
    rep: int,
    kernel: str,
    cvehound_repo: str,
    workspace_root: str,
    transcripts: str,
    runner: Runner | None = None,
) -> tuple[SampleRow, Workspace | None]:
    prompt = task_prompt(rec)
    row = session_row(cfg, rec, cls, rep, prompt)
    dest = os.path.abspath(os.path.join(workspace_root, f'{rec.cve}-{rep}'))
    started = time.monotonic()
    try:
        ws = export_workspace(
            cvehound_repo,
            kernel,
            rec.cve,
            dest,
            guard=cfg.cli,
            max_tool_calls=cfg.max_tool_calls,
            sync_venv=runner is None,
        )
    except (subprocess.CalledProcessError, RuntimeError, OSError) as err:
        row.error = f'workspace: {err!r}'
        row.latency_s = round(time.monotonic() - started, 3)
        return row, None
    if ws.venv_ok is False:
        row.error = f'workspace venv: {ws.venv_note}'
        row.latency_s = round(time.monotonic() - started, 3)
        return row, ws
    out_path = os.path.join(dest, '.agent-final.md')
    argv = agent_argv(cfg, ws, kernel, out_path)
    env = agent_env(cfg, ws, cvehound_repo)
    before = kernel_state(kernel)
    session_started = time.time()
    res: CliResult = run_cli(argv, prompt, env, ws.path, cfg.max_wall_s, runner)
    row.kernel_clean = before == kernel_state(kernel)
    cleaned: list[str] = []
    if cfg.cli == 'codex':
        # Sessions run one at a time for codex (run_agent), so a clone created in
        # this window is this session's.
        roots = ['/tmp', tempfile.gettempdir(), cfg.suite_tmpdir]
        cleaned = remove_scratch_clones(roots, session_started, kernel)
    os.makedirs(transcripts, exist_ok=True)
    with open(os.path.join(transcripts, f'{rec.cve}-{rep}.jsonl'), 'w') as fh:
        fh.write(res.stdout)
        if res.stderr:
            fh.write('\n# stderr\n' + res.stderr)
    trace = (
        parse_claude_stream(res.stdout)
        if cfg.cli == 'claude'
        else parse_codex_stream(res.stdout, out_path)
    )
    rule_text, rule_rel = collect_rule(ws)
    _record_session(row, cfg, res, trace, rule_text)
    row.server_timings = json.dumps(
        {
            'tool_names': dict(trace.tool_names),
            'blocked_commands': trace.blocked_commands,
            'pytest_tail': trace.pytest_tail,
            'removed': ws.removed,
            'mentions': ws.mentions,
            'rule_path': rule_rel,
            'resolved_model': trace.resolved_model,
            'events': trace.events,
            'returncode': res.returncode,
            'scratch_clones_removed': cleaned,
        }
    )
    if rule_rel and rule_rel.endswith('.grep'):
        row.error = (row.error or '') + ' grep rule (out of the model scope)'
    return row, ws


def _record_session(
    row: SampleRow, cfg: AgentConfig, res: CliResult, trace: AgentTrace, rule_text: str | None
) -> None:
    """What the session did and left behind, onto its row."""
    row.latency_s = res.latency_s
    row.timed_out = res.timed_out
    row.request_id = trace.request_id
    row.agent_message = trace.message[:20000] if trace.message else None
    row.agent_rule_text = rule_text
    row.num_turns = trace.num_turns
    row.duration_ms = trace.duration_ms
    row.tool_calls = trace.tool_calls
    row.pytest_ran = trace.pytest_ran
    row.pytest_passed = trace.pytest_passed
    row.validator_ran = trace.validator_ran
    row.cost_usd = trace.cost_usd
    usage = trace.usage or {}
    row.tokens_prompt = prompt_tokens(usage) or None
    row.tokens_cached = usage.get('cache_read_input_tokens', usage.get('cached_input_tokens'))
    row.tokens_completion = usage.get('output_tokens')
    row.tokens_cum = int(row.tokens_prompt or 0) + int(row.tokens_completion or 0)
    row.finish_reason = 'timeout' if res.timed_out else ('error' if trace.error else 'stop')
    if trace.error and not rule_text:
        row.error = trace.error
    elif res.timed_out and not rule_text:
        row.error = f'timed out after {cfg.max_wall_s:.0f} s with no rule'
    # The rule file, fenced, is the completion: finalize_completion and every
    # downstream reader (rescore, report, the training-target column) then
    # treat it exactly like a direct reply.
    row.completion_text = f'```\n{rule_text}```\n' if rule_text else (trace.message or '')


def score_row(
    row: SampleRow,
    rec: CveRecord,
    historical_names: dict[str, list[str]] | None,
    svc: OracleService,
) -> None:
    done = (
        finalize_completion(row.completion_text, rec, None, historical_names)
        if row.agent_rule_text
        else Finalized(None, '', False)
    )
    row.record_rule(done)
    if done.rule is None:
        row.attach(
            Score.unscored(rec.cve, row.completion_text, 'contract', row.error or 'no rule file')
        )
        return
    row.attach(svc.score(ScoreRequest.for_record(rec, done.rule)))


def trim_workspace(ws: Workspace, keep_venv: bool) -> None:
    if keep_venv:
        return
    venv = os.path.join(ws.path, '.venv')
    if os.path.isdir(venv):
        shutil.rmtree(venv, ignore_errors=True)
    linux = os.path.join(ws.path, 'tests', 'linux')
    if os.path.islink(linux):
        os.remove(linux)


def config_dict(cfg: AgentConfig) -> dict[str, Any]:
    """The run manifest's `config`: what build_manifest and the report driver read."""
    return {
        'run_id': cfg.run_id,
        'mode': 'agentic',
        'model': {
            'adapter': f'{cfg.cli}-agent',
            'model': cfg.model,
            'effort': cfg.effort,
            'model_file': None,
        },
        'prompt': {'policy': 'agent', 'system_prompt': TASK_VERSION, 'hide_cve_id': False},
        'sampling': {
            'n': cfg.repetitions,
            'temperature': None,
            'top_p': None,
            'max_tokens': None,
            'seed': 0,
        },
        'data': {'split': cfg.split, 'subset': cfg.subset or None, 'limit': cfg.limit},
        'agent': cfg.identity(),
        'transform': None,
        'out': cfg.out,
        'notes': cfg.notes,
    }


def _targets(cfg: AgentConfig, records: dict[str, CveRecord]) -> list[CveRecord]:
    """The eligible CVEs of the configured split (`gold` = train+val+test) and subset."""
    wanted = tables.read_ids(cfg.subset) if cfg.subset else None
    splits = set(extract.MERGED_SPLITS.get(cfg.split, (cfg.split,)))
    todo = [
        rec
        for rec in sorted(records.values(), key=lambda r: r.cve)
        if rec.split in splits
        and rec.fix
        and rec.eligible
        and (wanted is None or rec.cve in wanted)
    ]
    return todo[: cfg.limit] if cfg.limit else todo


def _renames(cfg: AgentConfig, data_dir: str) -> dict[str, dict[str, list[str]]]:
    """cve -> the earlier names of its files, to complete a rule's Files: line."""
    split = cfg.examples_split or cfg.split
    try:
        return {ex.cve: ex.historical_names for ex in extract.load_split_examples(data_dir, split)}
    except (FileNotFoundError, OSError):
        log.warning('no examples for %s: Files: lines are scored uncompleted', split)
        return {}


def _describe(cfg: AgentConfig, repo: str, runner: Runner | None) -> dict[str, Any]:
    """The manifest's adapter description of an agent run."""
    binary = cfg.cli_bin or cfg.cli
    return {
        'adapter': f'{cfg.cli}-agent',
        'cli_bin': binary,
        'cli_version': cli_version(binary) if runner is None else 'fake',
        'model': cfg.model,
        'effort': cfg.effort,
        'task_version': TASK_VERSION,
        'sampling': 'provider-default',
        'max_wall_s': cfg.max_wall_s,
        'max_tool_calls': cfg.max_tool_calls,
        'cvehound': manifest_mod.git_state(repo),
    }


def run_agent(
    cfg: AgentConfig,
    kernel: str,
    oracle_cfg: OracleConfig,
    data_dir: str = 'data',
    cvehound_repo: str | None = None,
    oracle_jobs: int = 4,
    resume: bool = False,
    dry_run: bool = False,
    runner: Runner | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    repo = cvehound_repo or manifest_mod.cvehound_path(kernel)
    todo = _targets(cfg, corpus.load_records(data_dir))
    classes = tiers.load_classes(data_dir)
    renames = _renames(cfg, data_dir)
    run_dir = os.path.join(cfg.out, cfg.run_id)
    sample_log = SampleLog(run_dir)
    done = {(cve, index) for cve, index, _round in sample_log.done_keys()} if resume else set()
    jobs = [
        (rec, rep) for rec in todo for rep in range(cfg.repetitions) if (rec.cve, rep) not in done
    ]
    describe = _describe(cfg, repo, runner)
    man = manifest_mod.build_manifest(
        config_dict(cfg),
        cfg.sha(),
        oracle_cfg,
        describe,
        data_dir,
        prompt_extra={'policy': 'agent', 'task_version': TASK_VERSION, 'hide_cve_id': False},
        cvehound_repo=repo,
    )
    manifest_mod.write_manifest(run_dir, man)
    log.info(
        'agent %s: %d sessions (%d CVEs x %d) with %s %s@%s, %d in parallel -> %s',
        cfg.run_id,
        len(jobs),
        len(todo),
        cfg.repetitions,
        cfg.cli,
        cfg.model,
        cfg.effort,
        cfg.jobs,
        run_dir,
    )
    totals: dict[str, Any] = {
        'n_rows': 0,
        'n_cves': len(todo),
        'n_valid': 0,
        'n_strong_valid': 0,
        'n_truncated_legs': 0,
        'n_rules': 0,
        'n_pytest_passed': 0,
        'n_timed_out': 0,
    }
    if dry_run:
        totals['dry_run'] = True
        totals['sessions'] = [f'{rec.cve}-{rep}' for rec, rep in jobs]
        man['totals'] = totals
        manifest_mod.write_manifest(run_dir, man)
        return totals
    # Absolute: the agent runs with its cwd inside the workspace, and codex
    # resolves `-C`/`-o` against that cwd (a relative path doubles up).
    workspace_root = os.path.abspath(os.path.join(cfg.workspaces, cfg.run_id))
    transcripts = os.path.abspath(os.path.join(run_dir, 'transcripts'))
    svc = OracleService(oracle_cfg, jobs=oracle_jobs)
    # codex: one session at a time, so the scratch clones a session leaves behind
    # can be attributed to it and removed (see scratch_clones).
    workers = 1 if cfg.cli == 'codex' else max(1, cfg.jobs)
    if workers != cfg.jobs:
        log.info('codex sessions run one at a time (asked for %d)', cfg.jobs)
    # The model the vendor actually ran, which list prices are keyed by
    # (eval.driver.price_key): the first session that names one decides.
    resolved = None
    try:
        with cf.ThreadPoolExecutor(workers) as pool:
            futures = {
                pool.submit(
                    run_session,
                    cfg,
                    rec,
                    classes.get(rec.cve, ''),
                    rep,
                    kernel,
                    repo,
                    workspace_root,
                    transcripts,
                    runner,
                ): rec
                for rec, rep in jobs
            }
            for future in cf.as_completed(futures):
                rec = futures[future]
                row, ws = future.result()
                score_row(row, rec, renames.get(rec.cve), svc)
                sample_log.append([row])
                if ws is not None:
                    trim_workspace(ws, cfg.keep_venv)
                _count_session(totals, row)
                resolved = resolved or json.loads(row.server_timings or '{}').get('resolved_model')
                log.info(
                    '  %s: %s in %.0f s, %d tool calls, pytest %s, oracle %s (%d/%d done, %d valid)',
                    row.cve,
                    'rule' if row.agent_rule_text else 'no rule',
                    row.latency_s,
                    row.tool_calls,
                    'passed' if row.pytest_passed else ('failed' if row.pytest_ran else 'not run'),
                    'valid'
                    if row.score.get('valid')
                    else (row.score.get('fail_class') or 'invalid'),
                    totals['n_rows'],
                    len(jobs),
                    totals['n_valid'],
                )
    finally:
        svc.close()
        sample_log.finalize()
        totals['wall_s'] = round(time.monotonic() - started, 1)
        if resolved:
            man['model']['adapter_describe']['resolved_model'] = resolved
        man['totals'] = totals
        manifest_mod.write_manifest(run_dir, man)
    log.info('done: %s', totals)
    return totals


def _count_session(totals: dict[str, Any], row: SampleRow) -> None:
    totals['n_rows'] += 1
    for key, count in score_counts([row]).items():
        totals[key] += count
    totals['n_rules'] += int(bool(row.agent_rule_text))
    totals['n_pytest_passed'] += int(bool(row.pytest_passed))
    totals['n_timed_out'] += int(row.timed_out)
