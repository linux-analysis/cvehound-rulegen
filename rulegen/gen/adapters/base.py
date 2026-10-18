"""The adapter protocol shared by every generation backend."""

from dataclasses import dataclass, field
from typing import Any, Protocol

from rulegen.schema import ExampleRecord


@dataclass(frozen=True)
class SamplingParams:
    temperature: float = 0.7
    top_p: float = 0.95
    max_tokens: int = 2048
    thinking: bool | None = None
    stop: tuple[str, ...] = ()


class AbortRun(RuntimeError):
    """The run cannot continue: an auth failure, or a usage-limit wait past its cap.

    Adapters raise it instead of returning a Completion with `error`, because an
    error row is logged as done and `rulegen run --resume` would never redo it.
    The harness lets it propagate, so the chunk in flight is not logged at all.
    """


@dataclass
class GenRequest:
    messages: list[dict[str, str]]
    params: SamplingParams
    seed: int
    example: ExampleRecord | None = None  # for adapters that read the input, not the prompt
    round: int = 0  # repair round; 0 is the first attempt


@dataclass
class Completion:
    text: str = ''
    reasoning: str | None = None
    finish_reason: str = ''
    tokens_prompt: int | None = None
    tokens_completion: int | None = None  # every generated token, reasoning included
    tokens_reasoning: int | None = None
    tokens_cached: int | None = None  # prompt tokens served from the provider's cache
    cost_usd: float | None = None  # what the provider reported, when it reports one
    latency_s: float = 0.0
    request_id: str | None = None
    error: str | None = None  # set instead of raising; the row is logged, not lost
    attempts: int = 1
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


class Adapter(Protocol):
    id: str

    def complete(self, req: GenRequest) -> Completion: ...

    def describe(self) -> dict[str, Any]: ...


def make_adapter(model_cfg: Any) -> Adapter:
    """Dispatch on ModelConfig.adapter (imports are local to keep httpx optional)."""
    kind = model_cfg.adapter
    if kind == 'openai-compat':
        from rulegen.gen.adapters.openai_compat import OpenAICompatAdapter

        return OpenAICompatAdapter.from_config(model_cfg)
    if kind == 'fake':
        from rulegen.gen.adapters.fake import FakeAdapter

        return FakeAdapter([])
    if kind == 'claude-cli':
        from rulegen.gen.adapters.claude_cli import ClaudeCliAdapter

        return ClaudeCliAdapter.from_config(model_cfg)
    if kind == 'codex-cli':
        from rulegen.gen.adapters.codex_cli import CodexCliAdapter

        return CodexCliAdapter.from_config(model_cfg)
    if kind == 'mechanical':
        from rulegen.gen.mechanical import MechanicalAdapter

        return MechanicalAdapter()
    raise ValueError(f'unknown adapter {kind!r}')
