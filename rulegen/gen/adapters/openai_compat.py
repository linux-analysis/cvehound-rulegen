"""OpenAI-compatible chat completions over HTTP: llama-server, vLLM, OpenAI.

One adapter for local servers and hosted endpoints, so a config differs only
in endpoint and model id. Transient failures retry with backoff; exhaustion
returns a Completion carrying `error`, never an exception — a lost sample is
a logged row, not a crashed run.
"""

import os
import time
from typing import Any

import httpx

from rulegen.gen.adapters.base import Completion, GenRequest

RETRY_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


class OpenAICompatAdapter:
    def __init__(
        self,
        endpoint: str,
        model: str = '',
        api_key: str | None = None,
        thinking: bool | None = None,
        extra_body: dict[str, Any] | None = None,
        timeout_s: float = 600.0,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip('/')
        self.model = model
        self.thinking = thinking
        self.extra_body = dict(extra_body or {})
        self.max_retries = max_retries
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        self._client = httpx.Client(headers=headers, timeout=timeout_s, transport=transport)
        self.id = f'openai-compat:{self.endpoint}:{model}'

    @classmethod
    def from_config(cls, cfg: Any) -> 'OpenAICompatAdapter':
        key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        return cls(
            cfg.endpoint,
            model=cfg.model,
            api_key=key,
            thinking=cfg.thinking,
            extra_body=cfg.extra_body,
            timeout_s=cfg.timeout_s,
            max_retries=cfg.max_retries,
        )

    @property
    def server_root(self) -> str:
        """llama-server's native endpoints live beside /v1, not under it."""
        root = self.endpoint
        return root[: -len('/v1')] if root.endswith('/v1') else root

    def _post(self, url: str, body: dict[str, Any]) -> tuple[dict[str, Any] | None, str, int]:
        """(json, error, attempts) with retries on transient failures."""
        error = ''
        for attempt in range(1, self.max_retries + 2):
            try:
                resp = self._client.post(url, json=body)
            except httpx.TransportError as err:
                error = f'transport: {err!r}'
            else:
                if resp.status_code == 200:
                    try:
                        return resp.json(), '', attempt
                    except ValueError as err:
                        return None, f'bad json: {err!r}', attempt
                error = f'http {resp.status_code}: {resp.text[:500]}'
                if resp.status_code not in RETRY_STATUSES:
                    return None, error, attempt
            if attempt <= self.max_retries:
                time.sleep(min(30.0, 0.5 * 2 ** (attempt - 1)))
        return None, error, self.max_retries + 1

    def complete(self, req: GenRequest) -> Completion:
        body: dict[str, Any] = {
            'model': self.model,
            'messages': req.messages,
            'temperature': req.params.temperature,
            'top_p': req.params.top_p,
            'max_tokens': req.params.max_tokens,
            'seed': req.seed,
            'n': 1,
        }
        if req.params.stop:
            body['stop'] = list(req.params.stop)
        thinking = req.params.thinking if req.params.thinking is not None else self.thinking
        if thinking is not None:
            body['chat_template_kwargs'] = {'enable_thinking': bool(thinking)}
        body.update(self.extra_body)
        started = time.monotonic()
        data, error, attempts = self._post(f'{self.endpoint}/chat/completions', body)
        latency = time.monotonic() - started
        if data is None:
            return Completion(error=error, attempts=attempts, latency_s=round(latency, 3))
        try:
            choice = data['choices'][0]
            message = choice.get('message') or {}
        except (KeyError, IndexError, TypeError):
            return Completion(error=f'malformed response: {str(data)[:300]}', attempts=attempts)
        usage = data.get('usage') or {}
        details = usage.get('completion_tokens_details') or {}
        return Completion(
            text=message.get('content') or '',
            reasoning=message.get('reasoning_content') or message.get('reasoning'),
            finish_reason=choice.get('finish_reason') or '',
            tokens_prompt=usage.get('prompt_tokens'),
            tokens_completion=usage.get('completion_tokens'),
            tokens_reasoning=details.get('reasoning_tokens'),
            latency_s=round(latency, 3),
            request_id=data.get('id'),
            attempts=attempts,
            raw={'usage': usage, 'timings': data.get('timings')},
        )

    def raw_complete(
        self, prompt: str, n_predict: int, temperature: float = 0.0, cache_prompt: bool = True
    ) -> Completion:
        """llama-server's native /completion: raw prompt, no chat template (probes)."""
        body = {
            'prompt': prompt,
            'n_predict': n_predict,
            'temperature': temperature,
            'cache_prompt': cache_prompt,
        }
        started = time.monotonic()
        data, error, attempts = self._post(f'{self.server_root}/completion', body)
        latency = time.monotonic() - started
        if data is None:
            return Completion(error=error, attempts=attempts, latency_s=round(latency, 3))
        return Completion(
            text=data.get('content') or '',
            finish_reason=str(data.get('stop_type') or ''),
            tokens_prompt=data.get('tokens_evaluated'),
            tokens_completion=data.get('tokens_predicted'),
            latency_s=round(latency, 3),
            attempts=attempts,
            raw={'timings': data.get('timings')},
        )

    def describe(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            'endpoint': self.endpoint,
            'model': self.model,
            'thinking': self.thinking,
            'extra_body': self.extra_body,
        }
        for name, url in (
            ('props', f'{self.server_root}/props'),
            ('models', f'{self.endpoint}/models'),
        ):
            try:
                resp = self._client.get(url)
                if resp.status_code == 200:
                    info[name] = resp.json()
                    break
            except (httpx.HTTPError, ValueError) as err:
                info[f'{name}_error'] = repr(err)
        return info
