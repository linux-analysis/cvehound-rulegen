"""OpenAI models through the Codex CLI, under the invoking user's login.

`codex exec --json` in an empty scratch directory under the read-only sandbox,
web search disabled, and our system prompt as the model instructions. The
event stream (JSONL) carries the thread id, the reply, any tool items (which
must not occur) and the turn's token usage; the last message is also written
to a file, the fallback when the stream is incomplete.
"""

import glob
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from rulegen.gen.adapters.base import Completion, GenRequest
from rulegen.gen.adapters.cli_subprocess import (
    CliAdapter,
    CliResult,
    child_env,
    jsonl_events,
)

# Item types that mean the model did something other than answer.
TOOL_ITEMS = frozenset(
    {
        'command_execution',
        'file_change',
        'mcp_tool_call',
        'web_search',
        'computer_use',
        'browser_use',
        'collab_tool_call',
        'todo_list',
    }
)
# `--ignore-user-config` drops the user's config.toml (model, effort, hooks,
# MCP servers) but keeps the auth under CODEX_HOME. Everything else Codex
# would hand the model besides our prompt is switched off feature by feature
# (checked on codex 0.156.1 by asking the model to list its tools: exec,
# browser, computer use, apps, plugins, goals and memories all gone; with
# `shell_tool` off a command item cannot occur).
DIRECT_FLAGS = (
    '--ignore-user-config',
    '-s',
    'read-only',
    '--skip-git-repo-check',
    '--ephemeral',
)
# The features that run commands: off in a direct cell, on for an agent.
SHELL_FEATURES = (
    'shell_tool',
    'unified_exec',
    'unified_exec_tty',
    'code_mode_host',
    'sleep_tool',
    'shell_snapshot',
)
DISABLED_FEATURES = (
    'plugins',
    'hooks',
    'goals',
    'memories',
    'tool_suggest',
    *SHELL_FEATURES,
    'browser_use',
    'browser_use_external',
    'browser_use_full_cdp_access',
    'computer_use',
    'apps',
    'skill_search',
    'skill_mcp_dependency_install',
)
# A tool call Codex refuses (its tool is disabled) never reaches the event
# stream: the router logs it on stderr and hands the model an error, and the
# model answers again in a second call -- the input is billed twice and the
# reply is not a single-turn answer any more.
ROUTER_ERROR_RE = re.compile(r'tools::router: error=')

# Codex discovers skills in these roots whatever the config says, so the
# user's own skills would reach the model; each SKILL.md found is disabled by
# path through `skills.config`.
SKILL_ROOTS = (
    '{codex_home}/skills/*/SKILL.md',
    '{codex_home}/skills/.system/*/SKILL.md',
    '~/.agents/skills/*/SKILL.md',
    '~/.claude/skills/*/SKILL.md',
    '~/.codex/skills/*/SKILL.md',
)


def codex_home(config_dir: str | None = None) -> str:
    """The CODEX_HOME a child runs under: the configured one, else the user's."""
    return config_dir or os.environ.get('CODEX_HOME') or os.path.expanduser('~/.codex')


def discovered_skills(codex_home: str) -> list[str]:
    found: set[str] = set()
    for pattern in SKILL_ROOTS:
        expanded = os.path.expanduser(pattern.format(codex_home=codex_home))
        found.update(os.path.abspath(p) for p in glob.glob(expanded))
    return sorted(found)


def skills_config(paths: list[str]) -> str:
    """The TOML value that hides every listed skill from the model."""
    entries = ','.join('{path="' + p.replace('"', '\\"') + '",enabled=false}' for p in paths)
    return f'[{entries}]'


def minimal_path(cli_bin: str) -> str:
    """A PATH with the system dirs, node and the CLI itself: no spatch, no cvehound.

    The shell tool is disabled, but a PATH without the user's tool dirs is
    the second wall should a future CLI version re-enable something.
    """
    dirs = ['/usr/bin', '/bin']
    for name in (cli_bin, 'node'):
        resolved = shutil.which(name)
        if resolved:
            real_dir = os.path.dirname(resolved)
            if real_dir not in dirs:
                dirs.insert(0, real_dir)
    return os.pathsep.join(dirs)


@dataclass
class CodexEvents:
    """What one `codex exec --json` event stream says."""

    events: int = 0
    thread_id: str | None = None
    model: str | None = None
    message: str | None = None  # the last agent message
    messages: int = 0
    reasoning: list[str] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)  # completed TOOL_ITEMS, in order
    usage: dict[str, Any] = field(default_factory=dict)  # the last turn's
    errors: list[str] = field(default_factory=list)


def read_events(events: list[dict[str, Any]]) -> CodexEvents:
    """The parts of a codex event stream both the direct cells and the agents read."""
    out = CodexEvents(events=len(events))
    for event in events:
        kind = event.get('type')
        if kind == 'thread.started':
            out.thread_id = event.get('thread_id')
            out.model = str(event['model']) if event.get('model') else out.model
        elif kind == 'item.completed':
            item = event.get('item') or {}
            item_type = str(item.get('type') or '')
            if item_type == 'agent_message':
                out.message = item.get('text') or ''
                out.messages += 1
            elif item_type == 'reasoning':
                out.reasoning.append(item.get('text') or '')
            elif item_type in TOOL_ITEMS:
                out.tools.append(item)
            elif item_type == 'error':
                out.errors.append(str(item.get('message') or item))
        elif kind == 'turn.completed':
            out.usage = event.get('usage') or {}
        elif kind in ('turn.failed', 'error'):
            err = event.get('error')
            text = err.get('message') if isinstance(err, dict) else err
            out.errors.append(str(text or event.get('message') or event))
    return out


class CodexCliAdapter(CliAdapter):
    kind = 'codex'
    default_bin = 'codex'
    system_channel = 'model_instructions_file'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.codex_home = codex_home(self.config_dir)
        self.disabled_skills = discovered_skills(self.codex_home)
        self.path = minimal_path(self.cli_bin)

    def argv(self, system_path: str, req: GenRequest, out_path: str) -> list[str]:
        argv = [
            self.cli_bin,
            'exec',
            '--json',
            '-m',
            self.model,
            '-c',
            f'model_reasoning_effort="{self.effort}"',
            '-c',
            'tools.web_search=false',
            '-c',
            f'model_instructions_file="{system_path}"',
            '-C',
            self.scratch,
            '-o',
            out_path,
            *DIRECT_FLAGS,
        ]
        if self.disabled_skills:
            argv += ['-c', f'skills.config={skills_config(self.disabled_skills)}']
        for feature in DISABLED_FEATURES:
            argv += ['--disable', feature]
        return [*argv, *self.cli_args, '-']  # the prompt on stdin

    def env(self, req: GenRequest) -> dict[str, str]:
        extra: dict[str, str] = {'CODEX_HOME': self.codex_home, 'PATH': self.path}
        return child_env(extra)

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info['codex_home'] = self.codex_home
        info['disabled_skills'] = self.disabled_skills
        info['disabled_features'] = list(DISABLED_FEATURES)
        info['path'] = self.path
        return info

    def parse(self, res: CliResult, out_path: str) -> Completion:
        stream = read_events(jsonl_events(res.stdout))
        self.resolved_model = stream.model or self.resolved_model or self.model
        text, usage, errors = stream.message, stream.usage, stream.errors
        if text is None and os.path.exists(out_path):
            with open(out_path) as fh:
                text = fh.read()
        tool_kinds = [str(item.get('type')) for item in stream.tools]
        tool_calls = len(tool_kinds)
        raw: dict[str, Any] = {
            'usage': usage,
            'thread_id': stream.thread_id,
            'tool_calls': tool_calls,
            'tool_kinds': tool_kinds,
            'events': stream.events,
        }
        comp = Completion(
            text=text or '',
            reasoning='\n\n'.join(r for r in stream.reasoning if r) or None,
            finish_reason='stop' if text else '',
            tokens_prompt=usage.get('input_tokens'),
            tokens_completion=usage.get('output_tokens'),
            tokens_reasoning=usage.get('reasoning_output_tokens'),
            tokens_cached=usage.get('cached_input_tokens'),
            request_id=stream.thread_id,
            raw=raw,
        )
        if not text:
            detail = '; '.join(errors) or res.stderr.strip()[-800:] or res.stdout.strip()[-800:]
            comp.error = f'codex exec (exit {res.returncode}): {detail[:800]}'
            comp.text = ''
            return comp
        if errors:
            # A reply arrived anyway: a configuration warning or a recovered
            # stream error, kept for the record rather than failing the row.
            raw['warnings'] = errors[:5]
        # Same rule as the claude adapter: a call the router refused returned
        # nothing but an error, so the reply is kept and the attempt recorded; a
        # tool item in the stream means something ran, and that reply is retried.
        raw['tool_attempts_denied'] = len(ROUTER_ERROR_RE.findall(res.stderr))
        if tool_calls:
            raw['retry'] = True
            comp.error = (
                f'tool ran in a direct-response cell ({tool_calls}: {", ".join(tool_kinds[:5])}); '
                'reply discarded'
            )
        return comp
