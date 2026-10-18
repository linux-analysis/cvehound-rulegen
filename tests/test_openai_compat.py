"""OpenAI-compatible adapter against a mock transport: parsing, retries, errors."""

import json

import httpx
import pytest

from rulegen.gen.adapters.base import GenRequest, SamplingParams
from rulegen.gen.adapters.openai_compat import OpenAICompatAdapter

MESSAGES = [{'role': 'system', 'content': 's'}, {'role': 'user', 'content': 'u'}]


def _ok(content: str, reasoning: str | None = None) -> httpx.Response:
    message = {'role': 'assistant', 'content': content}
    if reasoning is not None:
        message['reasoning_content'] = reasoning
    return httpx.Response(
        200,
        json={
            'id': 'chatcmpl-1',
            'choices': [{'message': message, 'finish_reason': 'stop'}],
            'usage': {
                'prompt_tokens': 11,
                'completion_tokens': 7,
                'completion_tokens_details': {'reasoning_tokens': 3},
            },
        },
    )


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr('rulegen.gen.adapters.openai_compat.time.sleep', lambda _s: None)


def make(handler, **kw) -> OpenAICompatAdapter:
    return OpenAICompatAdapter(
        'http://x/v1', model='m', transport=httpx.MockTransport(handler), max_retries=2, **kw
    )


def test_request_body_and_usage_parsing():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen['url'] = str(request.url)
        seen['body'] = json.loads(request.content)
        return _ok('```\n/// Files: a.c\n```', reasoning='thinking...')

    adapter = make(handler, thinking=False, extra_body={'reasoning_effort': 'low'})
    comp = adapter.complete(GenRequest(MESSAGES, SamplingParams(max_tokens=99), seed=42))
    assert seen['url'] == 'http://x/v1/chat/completions'
    body = seen['body']
    assert body['seed'] == 42 and body['max_tokens'] == 99 and body['n'] == 1
    assert body['chat_template_kwargs'] == {'enable_thinking': False}
    assert body['reasoning_effort'] == 'low'
    assert comp.text.startswith('```') and comp.reasoning == 'thinking...'
    assert (comp.tokens_prompt, comp.tokens_completion, comp.tokens_reasoning) == (11, 7, 3)
    assert comp.error is None and comp.attempts == 1


def test_transient_failure_retries_then_succeeds():
    calls = {'n': 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls['n'] += 1
        return httpx.Response(503, text='busy') if calls['n'] == 1 else _ok('ok')

    comp = make(handler).complete(GenRequest(MESSAGES, SamplingParams(), seed=0))
    assert comp.text == 'ok' and comp.attempts == 2


def test_exhausted_retries_return_an_error_row_not_an_exception():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text='boom')

    comp = make(handler).complete(GenRequest(MESSAGES, SamplingParams(), seed=0))
    assert comp.text == '' and comp.error.startswith('http 500') and comp.attempts == 3


def test_non_retryable_status_fails_fast():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text='bad request')

    comp = make(handler).complete(GenRequest(MESSAGES, SamplingParams(), seed=0))
    assert comp.error.startswith('http 400') and comp.attempts == 1


def test_raw_completion_uses_server_root():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen['url'] = str(request.url)
        return httpx.Response(
            200, json={'content': ' rest', 'tokens_predicted': 2, 'tokens_evaluated': 5}
        )

    comp = make(handler).raw_complete('prefix', n_predict=16)
    assert seen['url'] == 'http://x/completion'
    assert comp.text == ' rest' and comp.tokens_completion == 2
