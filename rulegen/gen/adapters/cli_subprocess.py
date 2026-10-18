"""What the two vendor-CLI adapters share: one subprocess per request.

Frontier models are reached through the vendors' own clients (`codex exec`,
`claude -p`) under the invoking user's login, so a request is a child
process: the system turn goes into a file the CLI reads, the user turn
on stdin, and the reply comes back as JSON on stdout. Everything the two
adapters have in common lives here -- the rendering of a message list into
that shape, the environment the child must NOT inherit, error classification,
and the gate that turns a usage-limit reply into a pause instead of a row.
"""

import contextlib
import datetime as dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from rulegen.gen.adapters.base import AbortRun, Completion, GenRequest

log = logging.getLogger(__name__)

# The repair turn is rendered statelessly: the task, then the model's previous
# reply and the feedback on it, in one user prompt. The local arm keeps only
# the last (reply, feedback) pair too, so the information content is the same.
SEP_PREVIOUS = '\n\n===== YOUR PREVIOUS REPLY =====\n'
SEP_FEEDBACK = '\n\n===== FEEDBACK ON THAT REPLY =====\n'
RENDER_VERSION = 1

# The parent process is often itself a Claude Code session; its variables would
# steer the child (model, effort, session wiring) and an API key would change
# the account the CLI uses. Strip them all.
STRIP_ENV_PREFIXES = ('CLAUDE_CODE_',)
STRIP_ENV_KEYS = frozenset(
    {
        'CLAUDECODE',
        'CLAUDE_PID',
        'CLAUDE_EFFORT',
        'ANTHROPIC_API_KEY',
        'ANTHROPIC_AUTH_TOKEN',
        'ANTHROPIC_BASE_URL',
        'ANTHROPIC_MODEL',
        'ANTHROPIC_SMALL_FAST_MODEL',
        'MAX_THINKING_TOKENS',
        'OPENAI_API_KEY',
        'OPENAI_BASE_URL',
        'OPENAI_ORG_ID',
    }
)

ErrorKind = Literal['usage_limit', 'transient', 'auth', 'fatal']
AUTH_WAITS_S = (60.0, 120.0, 240.0)  # waits before an auth-looking error aborts the run

# Wordings the CLIs print: "You've hit your session limit · resets 7am
# (Europe/Berlin)" (a rolling usage window) and "You've reached your <model>
# limit. Switch to another model, or manage usage credits" (a per-model cap,
# no time).
USAGE_RE = re.compile(
    r'usage limit|rate[ -]?limit|\b429\b|hit your (\w+ )?limit|limit reached|reached your'
    r'|too many requests|quota|usage cap|out of (extra )?usage|resets? (at |in )?\d'
    r'|manage usage|switch to another model|limit\s*[·.-]\s*resets',
    re.IGNORECASE,
)
AUTH_RE = re.compile(
    r'not logged in|please (run )?/?login|run codex login|\b401\b|unauthori[sz]ed'
    r'|authentication (failed|error|required)|invalid api key|login required'
    r'|refresh token|credentials? (expired|missing|not found)|not authenticated',
    re.IGNORECASE,
)
TRANSIENT_RE = re.compile(
    r'\b5\d\d\b|overloaded|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|EPIPE'
    r'|fetch failed|timed? ?out|connection (reset|refused|closed|error)|temporarily'
    r'|network error|internal server error|service unavailable|bad gateway'
    r'|stream (disconnected|error)|socket hang up|try again later',
    re.IGNORECASE,
)


@dataclass
class CliResult:
    stdout: str
    stderr: str
    returncode: int
    latency_s: float
    timed_out: bool = False


Runner = Callable[[list[str], str, dict[str, str], str, float], CliResult]


def render_turns(messages: list[dict[str, str]]) -> tuple[str, str]:
    """(system, prompt): the system turns joined, every later turn folded into one prompt.

    Round 0 is `[system, user]` and renders to the user turn verbatim. A repair
    turn `[system, user(task), assistant(reply), user(feedback)]` renders to the
    task, the reply under SEP_PREVIOUS and the feedback under SEP_FEEDBACK --
    the same bytes for every vendor, whatever its notion of a conversation.
    """
    system: list[str] = []
    prompt: list[str] = []
    for message in messages:
        role, content = message['role'], message['content']
        if role == 'system':
            system.append(content)
        elif role == 'user':
            prompt.append(content if not prompt else SEP_FEEDBACK + content)
        elif role == 'assistant':
            prompt.append(SEP_PREVIOUS + content)
        else:
            raise ValueError(f'unknown role {role!r}')
    return '\n\n'.join(system), ''.join(prompt)


def child_env(
    extra: dict[str, str] | None = None, base: dict[str, str] | None = None
) -> dict[str, str]:
    """The parent environment minus everything that would steer or re-authenticate the CLI."""
    env = {
        k: v
        for k, v in (os.environ if base is None else base).items()
        if k not in STRIP_ENV_KEYS and not k.startswith(STRIP_ENV_PREFIXES)
    }
    env.update(extra or {})
    return env


def run_cli(
    argv: list[str],
    stdin_text: str,
    env: dict[str, str],
    cwd: str,
    timeout_s: float,
    runner: Runner | None = None,
) -> CliResult:
    """Run one CLI invocation; on timeout kill its whole process group and say so."""
    if runner is not None:
        return runner(argv, stdin_text, env, cwd, timeout_s)
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 -- argv is built by the adapter, not the model
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(stdin_text, timeout=timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, 9)
        out, err = proc.communicate()
        timed_out = True
    return CliResult(
        stdout=out or '',
        stderr=err or '',
        returncode=proc.returncode if proc.returncode is not None else -9,
        latency_s=round(time.monotonic() - started, 3),
        timed_out=timed_out,
    )


def cli_version(binary: str) -> str:
    try:
        proc = subprocess.run(
            [binary, '--version'], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return f'unknown ({err!r})'
    return (
        (proc.stdout or proc.stderr).strip().splitlines()[0] if (proc.stdout or proc.stderr) else ''
    )


# -- errors ------------------------------------------------------------------

_DURATION_RE = re.compile(
    r'(?:reset|retry|try again|available)[^.\n]{0,40}?\bin\s+'
    r'(?:(\d+)\s*(?:h|hours?|hr))?\s*(?:(\d+)\s*(?:m|min|minutes?))?\s*(?:(\d+)\s*(?:s|sec|seconds?))?\b',
    re.IGNORECASE,
)
_RETRY_AFTER_RE = re.compile(r'retry[- ]after[:\s]+(\d+)', re.IGNORECASE)
_CLOCK_RE = re.compile(
    r'resets?\s+(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?(?:\s*\(?([A-Z]{2,4}|UTC[+-]\d+)\)?)?',
    re.IGNORECASE,
)
_ISO_RE = re.compile(r'resets?\s+(?:at\s+)?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)(Z| ?UTC)?')


def parse_reset_time(text: str, now: float | None = None) -> float | None:
    """The epoch second a usage-limit message says the window resets at, or None.

    Understands "resets at 3pm", "resets at 15:30", "resets 2026-09-24 18:00 UTC",
    "reset in 2h 13m", "try again in 45 minutes" and "Retry-After: 120". A clock
    time without a date is the next such time from `now`, read in local time
    unless the message says UTC.
    """
    now = time.time() if now is None else now
    match = _ISO_RE.search(text)
    if match:
        stamp = match.group(1).replace(' ', 'T')
        try:
            when = dt.datetime.fromisoformat(stamp)
        except ValueError:
            when = None
        if when is not None:
            when = when.replace(tzinfo=dt.UTC) if match.group(2) else when.astimezone()
            return when.timestamp()
    match = _RETRY_AFTER_RE.search(text)
    if match:
        return now + int(match.group(1))
    match = _DURATION_RE.search(text)
    if match and any(match.groups()):
        hours, minutes, seconds = (int(g) if g else 0 for g in match.groups())
        return now + hours * 3600 + minutes * 60 + seconds
    match = _CLOCK_RE.search(text)
    if match:
        hour = int(match.group(1))
        minute = int(match.group(2) or 0)
        meridiem = (match.group(3) or '').lower()
        zone = (match.group(4) or '').upper()
        if meridiem == 'pm' and hour < 12:
            hour += 12
        if meridiem == 'am' and hour == 12:
            hour = 0
        if hour > 23 or minute > 59:
            return None
        tz = dt.UTC if zone.startswith('UTC') or zone == 'GMT' else None
        base = dt.datetime.fromtimestamp(now, tz=tz) if tz else dt.datetime.fromtimestamp(now)
        when = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if when.timestamp() <= now:
            when += dt.timedelta(days=1)
        return when.timestamp()
    return None


def classify(text: str, timed_out: bool = False) -> ErrorKind:
    """Which of the four things an error text means for the run."""
    if timed_out:
        return 'transient'
    if AUTH_RE.search(text) and not USAGE_RE.search(text):
        return 'auth'
    if USAGE_RE.search(text):
        return 'usage_limit'
    if AUTH_RE.search(text):
        return 'auth'
    if TRANSIENT_RE.search(text):
        return 'transient'
    return 'fatal'


class UsageGate:
    """One pause shared by every worker thread of an adapter.

    A usage-limit reply parks the whole adapter until the window resets (plus a
    margin), or for a doubling backoff when the message gives no time. A pause
    longer than the cap means a weekly limit, which no wait inside a run should
    absorb: that aborts the run for `--resume` later.
    """

    def __init__(
        self,
        cap_s: float = 6 * 3600,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        margin_s: float = 30.0,
        backoff_s: float = 900.0,
        backoff_max_s: float = 7200.0,
    ) -> None:
        self.cap_s = cap_s
        self.clock = clock
        self.sleep = sleep
        self.margin_s = margin_s
        self._backoff = backoff_s
        self._backoff_initial = backoff_s
        self._backoff_max = backoff_max_s
        self._until = 0.0
        self._lock = threading.Lock()
        self.pauses = 0
        self.waited_s = 0.0

    def wait_if_paused(self) -> None:
        while True:
            with self._lock:
                remaining = self._until - self.clock()
            if remaining <= 0:
                return
            self.sleep(min(remaining, 60.0))

    def pause(self, reset_ts: float | None, reason: str) -> float:
        """Park the adapter; returns the seconds until it resumes. Raises past the cap."""
        with self._lock:
            now = self.clock()
            if reset_ts is not None and reset_ts > now:
                until = reset_ts + self.margin_s
                self._backoff = self._backoff_initial
            else:
                until = now + self._backoff
                self._backoff = min(self._backoff * 2, self._backoff_max)
            wait = until - now
            if wait > self.cap_s:
                raise AbortRun(
                    f'usage limit resets in {wait / 3600:.1f} h, past the {self.cap_s / 3600:.1f} h '
                    f'cap; resume the run later ({reason.strip()[:200]})'
                )
            self._until = max(self._until, until)
            self.pauses += 1
            self.waited_s += wait
            log.warning('usage limit: pausing %.0f s (%s)', wait, reason.strip()[:160])
            return wait

    def reset_backoff(self) -> None:
        with self._lock:
            self._backoff = self._backoff_initial


# -- the shared adapter body -------------------------------------------------


def last_json_object(text: str) -> dict[str, Any] | None:
    """The whole stdout as JSON, else the last line that parses as an object."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except ValueError:
        pass
    events = jsonl_events(text)
    return events[-1] if events else None


def jsonl_events(text: str) -> list[dict[str, Any]]:
    """Every line of `text` that parses as a JSON object, in order; anything else skipped."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            events.append(data)
    return events


class CliAdapter:
    """Everything but the argv and the parser; subclasses supply those."""

    kind = ''  # 'claude' | 'codex'
    default_bin = ''
    system_channel = ''  # how the CLI is handed the system turn
    honors_sampling = False

    def __init__(
        self,
        model: str,
        effort: str,
        thinking: bool | None = None,
        cli_args: tuple[str, ...] = (),
        config_dir: str | None = None,
        cli_bin: str | None = None,
        timeout_s: float = 1800.0,
        max_retries: int = 3,
        usage_wait_cap_s: float = 6 * 3600,
        scratch_dir: str | None = None,
        runner: Runner | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.model = model
        self.effort = effort
        self.thinking = thinking
        self.cli_args = tuple(cli_args)
        self.config_dir = config_dir
        self.cli_bin = cli_bin or self.default_bin
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.runner = runner
        self.sleep = sleep
        self.gate = UsageGate(usage_wait_cap_s, clock=clock, sleep=sleep)
        if scratch_dir:
            self.scratch = scratch_dir
            os.makedirs(self.scratch, exist_ok=True)
        else:
            # A temp dir of our own (system prompt files, reply files, the empty
            # cwd the CLI runs in) goes away with the adapter.
            self.scratch = tempfile.mkdtemp(prefix=f'rulegen-{self.kind}-')
            weakref.finalize(self, shutil.rmtree, self.scratch, ignore_errors=True)
        self._system_files: dict[str, str] = {}
        self._lock = threading.Lock()
        self.resolved_model: str | None = None
        # Circuit breaker: the same unrecognised error over and over is a limit or
        # an outage worded in a way `classify` does not know. Past this many in a
        # row, stop the run unlogged instead of filling it with error rows.
        self.same_error_limit = 8
        self._error_streak: tuple[str, int] = ('', 0)
        self.tool_retries = 0  # replies discarded because a tool actually ran
        self.tool_attempts_denied = 0  # refused tool calls in kept replies
        self.id = f'{self.kind}-cli:{model}:{effort}'
        self._version: str | None = None

    @classmethod
    def from_config(cls, cfg: Any) -> 'CliAdapter':
        return cls(
            cfg.model,
            cfg.effort or 'medium',
            thinking=cfg.thinking,
            cli_args=tuple(cfg.cli_args or ()),
            config_dir=cfg.config_dir,
            cli_bin=cfg.cli_bin,
            timeout_s=cfg.timeout_s,
            max_retries=cfg.max_retries,
            usage_wait_cap_s=cfg.usage_wait_cap_s,
        )

    # -- what subclasses provide ---------------------------------------------

    def argv(self, system_path: str, req: GenRequest, out_path: str) -> list[str]:
        raise NotImplementedError

    def env(self, req: GenRequest) -> dict[str, str]:
        raise NotImplementedError

    def parse(self, res: CliResult, out_path: str) -> Completion:
        """A Completion from the CLI's output; `error` set when there is no usable reply."""
        raise NotImplementedError

    # -- shared -------------------------------------------------------------

    def version(self) -> str:
        if self._version is None:
            self._version = cli_version(self.cli_bin)
        return self._version

    def system_file(self, system: str) -> str:
        """The path holding this system text, written once per distinct text."""
        digest = hashlib.sha256(system.encode()).hexdigest()[:12]
        with self._lock:
            path = self._system_files.get(digest)
            if path is None:
                path = os.path.join(self.scratch, f'system-{digest}.txt')
                with open(path, 'w') as fh:
                    fh.write(system)
                self._system_files[digest] = path
        return path

    def complete(self, req: GenRequest) -> Completion:
        system, prompt = render_turns(req.messages)
        system_path = self.system_file(system)
        env = self.env(req)
        started = time.monotonic()
        attempts = 0
        usage_waits = 0
        auth_waits = 0
        last: Completion | None = None
        while attempts <= self.max_retries:
            self.gate.wait_if_paused()
            out_path = os.path.join(
                self.scratch, f'reply-{os.getpid()}-{threading.get_ident()}.txt'
            )
            argv = self.argv(system_path, req, out_path)
            res = run_cli(argv, prompt, env, self.scratch, self.timeout_s, self.runner)
            attempts += 1
            if res.timed_out:
                comp = Completion(error=f'timeout after {self.timeout_s:.0f} s', raw={})
            else:
                comp = self.parse(res, out_path)
            with contextlib.suppress(OSError):
                os.unlink(out_path)
            if comp.raw.get('retry'):
                # A tool ran: the reply may carry information the prompt did not.
                # Drop it and ask again. Counted, and bounded by max_retries like a
                # transport failure; past that the last reply is logged flagged.
                # (A refused attempt is not retried: the reply is kept and the
                # attempt recorded on the row as tool_attempts_denied.)
                self.tool_retries += 1
                last = comp
                if attempts <= self.max_retries:
                    continue
                break
            if comp.error is None:
                with self._lock:
                    self._error_streak = ('', 0)
                self.tool_attempts_denied += int(comp.raw.get('tool_attempts_denied') or 0)
                comp.attempts = attempts
                comp.latency_s = round(time.monotonic() - started, 3)
                comp.raw.setdefault('usage_waits', usage_waits)
                self.gate.reset_backoff()
                return comp
            last = comp
            kind = classify(comp.error, timed_out=res.timed_out)
            comp.raw['error_kind'] = kind
            if kind == 'auth':
                # A token that expired mid-request looks like a logout for a moment:
                # the CLI refreshes it and the next request goes through. Wait and
                # retry; only an error that survives the waits is a real logout.
                if auth_waits < len(AUTH_WAITS_S):
                    wait = AUTH_WAITS_S[auth_waits]
                    auth_waits += 1
                    attempts -= 1  # not the model's failure
                    log.warning(
                        '%s: auth-looking error, retrying in %.0f s (%d/%d): %s',
                        self.kind,
                        wait,
                        auth_waits,
                        len(AUTH_WAITS_S),
                        comp.error[:160],
                    )
                    self.sleep(wait)
                    continue
                raise AbortRun(f'{self.kind} CLI is not authenticated: {comp.error[:300]}')
            if kind == 'usage_limit':
                reset = parse_reset_time(comp.error, now=self.gate.clock())
                self.gate.pause(reset, comp.error)
                usage_waits += 1
                attempts -= 1  # a paused request is not a failed one
                continue
            if kind == 'transient' and attempts <= self.max_retries:
                self.sleep(min(60.0, 2.0**attempts))
                continue
            break
        assert last is not None
        self._note_error(last.error or '')
        last.attempts = attempts
        last.latency_s = round(time.monotonic() - started, 3)
        last.raw.setdefault('usage_waits', usage_waits)
        return last

    def _note_error(self, error: str) -> None:
        """Count identical failures in a row across worker threads; abort past the limit."""
        key = re.sub(r'\d+', '#', error)[:200]  # ids and counts vary, the wording does not
        with self._lock:
            text, count = self._error_streak
            count = count + 1 if key == text else 1
            self._error_streak = (key, count)
        if count >= self.same_error_limit:
            raise AbortRun(
                f'{count} requests in a row failed with the same error; stopping so they are not '
                f'logged as rows (resume once it is understood): {error[:300]}'
            )

    def describe(self) -> dict[str, Any]:
        return {
            'adapter': f'{self.kind}-cli',
            'cli_bin': self.cli_bin,
            'cli_version': self.version(),
            'model': self.model,
            'resolved_model': self.resolved_model,
            'effort': self.effort,
            'thinking': self.thinking,
            'cli_args': list(self.cli_args),
            'config_dir': self.config_dir,
            'multi_turn': 'stateless',
            'render_version': RENDER_VERSION,
            'sampling': 'provider-default',
            'system_channel': self.system_channel,
            'usage_pauses': self.gate.pauses,
            'usage_waited_s': round(self.gate.waited_s, 1),
            'tool_retries': self.tool_retries,
            'tool_attempts_denied': self.tool_attempts_denied,
        }
