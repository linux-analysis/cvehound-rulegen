"""Anthropic models through Claude Code's print mode, under the invoking user's login.

`claude -p --output-format json` with every tool switched off and our system
prompt in place of Claude Code's own: the model sees exactly the messages the
local models see. One JSON object comes back with the reply, the session id,
token usage (cache reads and writes separately) and the cost Claude Code
computes at list price.
"""

from typing import Any

from rulegen.gen.adapters.base import Completion, GenRequest
from rulegen.gen.adapters.cli_subprocess import (
    CliAdapter,
    CliResult,
    child_env,
    last_json_object,
)

# `--tools ""` removes every built-in tool and `--restricted` the code-running
# ones plus the settings files; both, so neither flag's future default matters.
# `--setting-sources ""` keeps the user's settings.json (model, effort, hooks,
# MCP servers) out; `--no-session-persistence` leaves no transcript behind.
DIRECT_FLAGS = (
    '--tools',
    '',
    '--restricted',
    '--setting-sources',
    '',
    '--disallowedTools',
    'WebFetch,WebSearch',
    '--no-session-persistence',
)


def prompt_tokens(usage: dict[str, Any]) -> int | None:
    """Every prompt token of a Claude usage block: uncached input, cache reads and
    cache writes, which the API counts apart; None without a usage block."""
    if not usage:
        return None
    return (
        int(usage.get('input_tokens') or 0)
        + int(usage.get('cache_read_input_tokens') or 0)
        + int(usage.get('cache_creation_input_tokens') or 0)
    )


class ClaudeCliAdapter(CliAdapter):
    kind = 'claude'
    default_bin = 'claude'
    system_channel = 'system-prompt-file'

    def argv(self, system_path: str, req: GenRequest, out_path: str) -> list[str]:
        return [
            self.cli_bin,
            '-p',
            '--output-format',
            'json',
            '--model',
            self.model,
            '--effort',
            self.effort,
            '--system-prompt-file',
            system_path,
            *DIRECT_FLAGS,
            *self.cli_args,
        ]

    def env(self, req: GenRequest) -> dict[str, str]:
        extra: dict[str, str] = {}
        if self.config_dir:
            extra['CLAUDE_CONFIG_DIR'] = self.config_dir
        if self.thinking is False:
            extra['MAX_THINKING_TOKENS'] = '0'
        return child_env(extra)

    def parse(self, res: CliResult, out_path: str) -> Completion:
        data = last_json_object(res.stdout)
        if data is None:
            tail = (res.stderr.strip() or res.stdout.strip())[-800:]
            return Completion(
                error=f'no JSON result (exit {res.returncode}): {tail}',
                raw={'stderr': res.stderr[-2000:], 'returncode': res.returncode},
            )
        usage = data.get('usage') or {}
        model_usage = data.get('modelUsage') or {}
        if model_usage:
            self.resolved_model = next(iter(model_usage))
        subtype = str(data.get('subtype') or '')
        text = data.get('result') or ''
        num_turns = data.get('num_turns')
        denials = data.get('permission_denials') or []
        raw: dict[str, Any] = {
            'usage': usage,
            'model_usage': model_usage,
            'num_turns': num_turns,
            'duration_ms': data.get('duration_ms'),
            'duration_api_ms': data.get('duration_api_ms'),
            'subtype': subtype,
            'session_id': data.get('session_id'),
            'permission_denials': len(denials),
            'tool_calls': 0,
        }
        details = usage.get('output_tokens_details') or {}
        comp = Completion(
            text=text,
            finish_reason=subtype,
            tokens_prompt=prompt_tokens(usage),
            tokens_completion=usage.get('output_tokens'),
            tokens_reasoning=details.get('thinking_tokens'),
            tokens_cached=usage.get('cache_read_input_tokens'),
            cost_usd=data.get('total_cost_usd'),
            request_id=data.get('session_id'),
            raw=raw,
        )
        if data.get('is_error') or subtype not in ('', 'success'):
            detail = text.strip() or res.stderr.strip()[-800:]
            comp.error = f'{subtype or "error"}: {detail[:800]}'
            comp.text = ''
            return comp
        # A direct-response cell is one answer to one prompt. A tool call Claude
        # Code refused (a permission denial) returned nothing to the model: the
        # reply is kept and the attempt recorded on the row. A tool that ran --
        # an extra turn with no denial behind it -- may have handed the model
        # information the prompt did not: that reply is discarded and the request
        # retried (cli_subprocess.CliAdapter.complete; counted in the manifest).
        extra_turns = max(0, int(num_turns or 1) - 1)
        executed = max(0, extra_turns - len(denials))
        raw['tool_attempts_denied'] = len(denials)
        raw['tool_calls'] = executed
        if executed:
            raw['retry'] = True
            comp.error = (
                f'tool ran in a direct-response cell (num_turns={num_turns}, '
                f'denials={len(denials)}); reply discarded'
            )
        return comp
