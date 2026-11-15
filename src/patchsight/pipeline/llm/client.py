"""An OpenAI-compatible chat client with a response cache and a token-bucket limiter.

* **Cache:** keyed by SHA-256 over the whole request: model, messages, schema, decoding
  parameters and prompt version. Changing any of them misses the cache, so a model swap
  never reuses stale answers. Hits are free and make re-runs deterministic.
* **Limiter:** a sliding 60-second window over estimated tokens. It keeps each provider
  under its tokens-per-minute cap and stops at the requests-per-day cap.
* **Backend:** injectable, so tests never call a provider.
"""

import hashlib
import json
import os
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.llm.config import LLMConfig


class QuotaExhaustedError(RuntimeError):
    """The provider's daily request cap for this run is used up."""


class ProviderRejectedError(RuntimeError):
    """The provider refused this one generation, for example output that failed its schema
    check or a request too large. Worth one retry; it does not mean the provider is down."""


class LLMRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str
    prompt_version: str
    messages: tuple[dict[str, str], ...]
    schema_name: str
    response_schema: dict[str, Any]
    max_tokens: int
    seed: int
    temperature: float = 0.0
    extra: dict[str, Any] = {}

    def cache_key(self) -> str:
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class LLMResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    content: str
    prompt_tokens: int
    completion_tokens: int
    cached: bool
    seconds: float


Backend = Callable[[LLMRequest], tuple[str, int, int]]


class RateLimiter:
    """Sliding-window token limiter, plus a per-run request cap."""

    def __init__(
        self,
        tokens_per_minute: int,
        requests_per_day: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.tokens_per_minute = tokens_per_minute
        self.requests_per_day = requests_per_day
        self._clock = clock
        self._sleep = sleep
        self._window: deque[tuple[float, int]] = deque()
        self.requests = 0
        self.waited = 0.0

    def _used(self, now: float) -> int:
        while self._window and now - self._window[0][0] >= 60.0:
            self._window.popleft()
        return sum(tokens for _, tokens in self._window)

    def acquire(self, tokens: int) -> None:
        if self.requests >= self.requests_per_day:
            raise QuotaExhaustedError(f"request cap of {self.requests_per_day} reached")
        tokens = min(tokens, self.tokens_per_minute)
        while self._used(self._clock()) + tokens > self.tokens_per_minute:
            wait = 60.0 - (self._clock() - self._window[0][0]) + 0.05
            self.waited += wait
            self._sleep(wait)
        self._window.append((self._clock(), tokens))
        self.requests += 1

    def settle(self, actual: int) -> None:
        """Replace the most recent estimate with the tokens the provider reported."""
        if self._window:
            when, _ = self._window.pop()
            self._window.append((when, min(actual, self.tokens_per_minute)))


def openai_backend(base_url: str, api_key: str) -> Backend:
    """A backend that calls any OpenAI-compatible endpoint with strict JSON-schema output."""
    # Imported lazily: offline tests never need the SDK.
    from openai import APIStatusError, BadRequestError, OpenAI

    client = OpenAI(base_url=base_url, api_key=api_key, max_retries=4, timeout=180.0)

    def call(request: LLMRequest) -> tuple[str, int, int]:
        try:
            return _create(request)
        except (BadRequestError, APIStatusError) as error:
            if isinstance(error, BadRequestError) or error.status_code == 413:
                raise ProviderRejectedError(str(error)[:300]) from error
            raise

    def _create(request: LLMRequest) -> tuple[str, int, int]:
        completion = client.chat.completions.create(
            model=request.model,
            messages=cast(Any, list(request.messages)),
            temperature=request.temperature,
            seed=request.seed,
            max_tokens=request.max_tokens,
            response_format=cast(
                Any,
                {
                    "type": "json_schema",
                    "json_schema": {
                        "name": request.schema_name,
                        "schema": request.response_schema,
                        "strict": True,
                    },
                },
            ),
            extra_body=request.extra or None,
        )
        usage = completion.usage
        content = completion.choices[0].message.content or ""
        return (
            content,
            usage.prompt_tokens if usage else 0,
            usage.completion_tokens if usage else 0,
        )

    return call


class LLMClient:
    def __init__(
        self,
        backend: Backend,
        limiter: RateLimiter,
        cache_dir: Path,
        chars_per_token: float = 3.0,
    ) -> None:
        self._backend = backend
        self._limiter = limiter
        self._cache_dir = cache_dir
        self._chars_per_token = chars_per_token
        self.network_calls = 0

    def estimate_tokens(self, text: str) -> int:
        return int(len(text) / self._chars_per_token) + 1

    def complete(self, request: LLMRequest) -> LLMResponse:
        key = request.cache_key()
        path = self._cache_dir / key[:2] / f"{key}.json"
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            return LLMResponse(**cached, cached=True, seconds=0.0)

        prompt_text = "".join(m["content"] for m in request.messages)
        estimate = self.estimate_tokens(prompt_text) + request.max_tokens
        self._limiter.acquire(estimate)
        started = time.monotonic()
        content, prompt_tokens, completion_tokens = self._backend(request)
        seconds = time.monotonic() - started
        self.network_calls += 1
        self._limiter.settle(prompt_tokens + completion_tokens)

        record = {
            "content": content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return LLMResponse(**record, cached=False, seconds=seconds)


def client_for(config: LLMConfig, role: str, cache_dir: Path) -> tuple[LLMClient, str]:
    """A live client for one configured model role, and that model's ID."""
    model = config.models[role]
    provider = config.providers[model.provider]
    api_key = os.environ.get(provider.api_key_env)
    if not api_key:
        raise RuntimeError(f"set {provider.api_key_env} to call {model.provider}")
    limiter = RateLimiter(provider.tokens_per_minute, provider.requests_per_day)
    backend = openai_backend(provider.base_url, api_key)
    return LLMClient(backend, limiter, cache_dir, config.budget.chars_per_token), model.model
