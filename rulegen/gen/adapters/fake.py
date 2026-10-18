"""A scripted adapter for tests and dry runs: canned completions, no network."""

from collections.abc import Callable, Sequence
from typing import Any

from rulegen.gen.adapters.base import Completion, GenRequest
from rulegen.tokens import approx_token_count

Script = Sequence[str] | Callable[[GenRequest, int], str]


def generic_rule(files: Sequence[str]) -> str:
    """A well-formed but content-free rule: exercises T0-T3 without any model.

    It stars an early return in any function of the first candidate file, so
    it parses, usually fires everywhere, and fails the fix-silence leg — the
    canonical over-broad candidate the smoke run should see rejected.
    """
    path = files[0] if files else 'init/main.c'
    return (
        'Here is the rule:\n```\n'
        f'/// Files: {path}\n\n'
        '@r@\nidentifier f;\nexpression e;\n@@\n\n'
        'f(...)\n{\n\t... when any\n*\treturn -e;\n\t... when any\n}\n'
        '```\n'
    )


class FakeAdapter:
    id = 'fake'

    def __init__(self, script: Script) -> None:
        self.script = script
        self.calls: list[GenRequest] = []

    def complete(self, req: GenRequest) -> Completion:
        index = len(self.calls)
        self.calls.append(req)
        if callable(self.script):
            text = self.script(req, index)
        elif self.script:
            text = self.script[index % len(self.script)]
        elif req.example is not None:
            text = generic_rule(req.example.files_candidates)
        else:
            text = ''
        prompt_text = '\n'.join(m['content'] for m in req.messages)
        return Completion(
            text=text,
            finish_reason='stop',
            tokens_prompt=approx_token_count(prompt_text),
            tokens_completion=approx_token_count(text) if text else 0,
        )

    def describe(self) -> dict[str, Any]:
        return {'adapter': 'fake', 'scripted': not callable(self.script)}
