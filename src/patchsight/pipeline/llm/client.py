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
import re
import time
from collections import deque
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.llm.config import LLMConfig
from patchsight.pipeline.llm.tokens import CharEstimate, TokenCounter
from patchsight.pipeline.trace import Tracer

_ACCOUNT_ID = re.compile(r"\b(org|user|proj|acct)_[A-Za-z0-9]{6,}")
_SECRET = re.compile(r"(?i)\b(api[_-]?key|token|secret)\b(\W{1,3})\S+")


def redact(text: str) -> str:
    """Remove account identifiers and anything key-like from provider messages."""
    text = _ACCOUNT_ID.sub(lambda m: f"{m.group(1)}_[redacted]", text)
    return _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)


class QuotaExhaustedError(RuntimeError):
    """A daily cap for this model is used up: by the ledger's count before sending
    (``source`` "ledger"), or by the provider's own answer (``source`` "provider")."""

    def __init__(self, message: str, source: Literal["ledger", "provider"] = "ledger") -> None:
        super().__init__(message)
        self.source = source


class RateLimitedError(RuntimeError):
    """The provider kept refusing for rate limits after the SDK's own retries."""


class ProviderRejectedError(RuntimeError):
    """The provider refused this one generation, for example output that failed its schema
    check or a request too large. Worth one retry; it does not mean the provider is down."""


class PromptTooLargeError(ProviderRejectedError):
    """A request with more input tokens than the provider accepts in one request. It was
    never sent: the provider refuses it every time (HTTP 413), so a retry cannot help, and
    a refused request still counts against the daily ledger."""


TOO_LARGE = "too_large"  # the traced outcome of a request refused here, before sending


def input_tokens(counter: TokenCounter, messages: Sequence[dict[str, str]]) -> int:
    """A request's input tokens as the client counts them, for its limits and the plan."""
    return counter.count("".join(m["content"] for m in messages))


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
    """Token limits at two scales.

    * Per minute: a sliding 60-second window over estimated tokens, held in memory.
    * Per day: a rolling 24-hour ledger of actual usage, kept on disk when ``ledger`` is
      given, so separate runs share one daily budget. When the next call would exceed the
      daily token or request cap, the run stops with ``QuotaExhaustedError``; everything
      already answered is cached, so the next run resumes where this one stopped.
    """

    def __init__(
        self,
        tokens_per_minute: int,
        requests_per_day: int,
        tokens_per_day: int | None = None,
        ledger: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall: Callable[[], float] = time.time,
        output_tokens_per_minute: int | None = None,
    ) -> None:
        self.tokens_per_minute = tokens_per_minute
        self.output_tokens_per_minute = output_tokens_per_minute
        # Output tokens in the last 60 seconds: each request's allowance until it returns,
        # then what it actually produced.
        self._output: deque[tuple[float, int]] = deque()
        self.requests_per_day = requests_per_day
        self.tokens_per_day = tokens_per_day
        self._ledger = ledger
        self._clock = clock
        self._sleep = sleep
        self._wall = wall
        self._window: deque[tuple[float, int]] = deque()
        self._day: list[tuple[float, int]] = self._load_ledger()
        self.requests = 0
        self.waited = 0.0

    def _load_ledger(self) -> list[tuple[float, int]]:
        if self._ledger is None or not self._ledger.exists():
            return []
        entries = []
        for line in self._ledger.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                entries.append((float(record["t"]), int(record["tokens"])))
        return entries

    def _last_day(self) -> list[tuple[float, int]]:
        cutoff = self._wall() - 86_400.0
        self._day = [entry for entry in self._day if entry[0] > cutoff]
        return self._day

    def _used(self, now: float) -> int:
        while self._window and now - self._window[0][0] >= 60.0:
            self._window.popleft()
        return sum(tokens for _, tokens in self._window)

    def _output_used(self, now: float) -> int:
        while self._output and now - self._output[0][0] >= 60.0:
            self._output.popleft()
        return sum(tokens for _, tokens in self._output)

    def acquire(self, tokens: int, output: int = 0) -> None:
        """Wait until a call of about ``tokens`` in all, ``output`` of them its output
        allowance, fits the per-minute limits; stop if it would pass a daily cap."""
        day = self._last_day()
        requests_today = len(day) if self._ledger is not None else self.requests
        if requests_today >= self.requests_per_day:
            raise QuotaExhaustedError(f"daily request cap of {self.requests_per_day} reached")
        if self.tokens_per_day is not None:
            used_today = sum(t for _, t in day)
            if used_today + tokens > self.tokens_per_day:
                raise QuotaExhaustedError(
                    f"daily token cap: {used_today:,} used in the last 24 h, this call needs "
                    f"about {tokens:,}, cap {self.tokens_per_day:,}. Cached work resumes later."
                )
        tokens = min(tokens, self.tokens_per_minute)
        while self._used(self._clock()) + tokens > self.tokens_per_minute:
            wait = 60.0 - (self._clock() - self._window[0][0]) + 0.05
            self.waited += wait
            self._sleep(wait)
        self._window.append((self._clock(), tokens))
        if self.output_tokens_per_minute is not None:
            reserve = min(output, self.output_tokens_per_minute)
            while self._output_used(self._clock()) + reserve > self.output_tokens_per_minute:
                wait = 60.0 - (self._clock() - self._output[0][0]) + 0.05
                self.waited += wait
                self._sleep(wait)
            self._output.append((self._clock(), reserve))
        self.requests += 1

    def settle(self, actual: int, output: int | None = None) -> None:
        """Record the tokens the provider reported for the most recent call, and of them the
        output; without ``output`` the call keeps its whole output allowance."""
        if self._window:
            when, _ = self._window.pop()
            self._window.append((when, min(actual, self.tokens_per_minute)))
        if output is not None and self._output:
            when, _ = self._output.pop()
            self._output.append((when, output))
        entry = (self._wall(), actual)
        self._day.append(entry)
        if self._ledger is not None:
            self._ledger.parent.mkdir(parents=True, exist_ok=True)
            with self._ledger.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"t": entry[0], "tokens": actual}) + "\n")


def openai_backend(base_url: str, api_key: str) -> Backend:
    """A backend that calls any OpenAI-compatible endpoint with strict JSON-schema output."""
    # Imported lazily: offline tests never need the SDK.
    from openai import APIStatusError, BadRequestError, OpenAI, RateLimitError

    client = OpenAI(base_url=base_url, api_key=api_key, max_retries=4, timeout=180.0)

    def call(request: LLMRequest) -> tuple[str, int, int]:
        try:
            return _create(request)
        except RateLimitError as error:
            # Per-minute limits are retried by the SDK; a daily cap cannot be waited out.
            message = redact(str(error))
            if "per day" in message.lower():
                raise QuotaExhaustedError(message[:300], source="provider") from None
            raise RateLimitedError(message[:300]) from None
        except (BadRequestError, APIStatusError) as error:
            if isinstance(error, BadRequestError) or error.status_code == 413:
                raise ProviderRejectedError(redact(str(error))[:300]) from error
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
        counter: TokenCounter | None = None,
        tracer: Tracer | None = None,
        input_limit: int | None = None,
    ) -> None:
        self._backend = backend
        self._limiter = limiter
        self._cache_dir = cache_dir
        self._counter: TokenCounter = counter or CharEstimate()
        # The most input tokens the provider takes in one request; larger ones are not sent.
        self.input_limit = input_limit
        self.network_calls = 0
        self.tracer = tracer or Tracer()

    def _trace(
        self, request: LLMRequest, key: str, cached: bool, outcome: str, seconds: float,
        prompt_tokens: int = 0, completion_tokens: int = 0,
    ) -> None:  # fmt: skip
        self.tracer.emit(
            "llm_call", model=request.model, prompt_version=request.prompt_version,
            input_hash=key, cached=cached, outcome=outcome, prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens, seconds=round(seconds, 3),
        )  # fmt: skip

    def estimate_tokens(self, text: str) -> int:
        return self._counter.count(text)

    def complete(self, request: LLMRequest) -> LLMResponse:
        key = request.cache_key()
        path = self._cache_dir / key[:2] / f"{key}.json"
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            if "rejected" in cached:
                # Rejections are cached too, so a re-run gives the same outcome for free.
                self._trace(request, key, cached=True, outcome="rejected", seconds=0.0)
                raise ProviderRejectedError(cached["rejected"])
            response = LLMResponse(**cached, cached=True, seconds=0.0)
            self._trace(request, key, True, "ok", 0.0, response.prompt_tokens,
                        response.completion_tokens)  # fmt: skip
            return response

        prompt = input_tokens(self._counter, request.messages)
        if self.input_limit is not None and prompt > self.input_limit:
            # Not cached: the outcome follows from the request and the configured limit,
            # so a raised limit takes effect at once, and a cache-only replay agrees.
            self._trace(request, key, False, TOO_LARGE, 0.0)
            raise PromptTooLargeError(
                f"not sent: about {prompt:,} input tokens, over the provider's limit of "
                f"{self.input_limit:,} for one request"
            )
        estimate = prompt + request.max_tokens
        self._limiter.acquire(estimate, output=request.max_tokens)
        started = time.monotonic()
        try:
            content, prompt_tokens, completion_tokens = self._backend(request)
        except ProviderRejectedError as rejected:
            self.network_calls += 1
            self._limiter.settle(estimate)  # the provider may still count it; stay conservative
            self._trace(request, key, False, "rejected", time.monotonic() - started)
            message = redact(str(rejected))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"rejected": message}), encoding="utf-8")
            raise ProviderRejectedError(message) from rejected
        except ResponseNotCachedError:
            # A cache-only replay with no answer: nothing was sent anywhere.
            self._trace(request, key, False, NOT_CACHED, 0.0)
            raise
        except Exception as error:
            self._trace(request, key, False, type(error).__name__, time.monotonic() - started)
            raise
        seconds = time.monotonic() - started
        self.network_calls += 1
        self._limiter.settle(prompt_tokens + completion_tokens, completion_tokens)

        record = {
            "content": content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        self._trace(request, key, False, "ok", seconds, prompt_tokens, completion_tokens)
        return LLMResponse(**record, cached=False, seconds=seconds)


NOT_CACHED = "not_cached"  # the traced outcome of a cache-only miss


class ResponseNotCachedError(RuntimeError):
    """Cache-only mode: the response is not in the cache, and no model may be called."""


def cache_only_client(
    config: LLMConfig, role: str, cache_dir: Path, counter: TokenCounter
) -> tuple[LLMClient, str]:
    """A client that answers only from the cache, for replaying a run made elsewhere (such as
    on Kaggle) with no model server and no key. A miss raises ResponseNotCachedError."""

    def refuse(request: LLMRequest) -> tuple[str, int, int]:
        raise ResponseNotCachedError(f"no cached response for this {request.model} prompt")

    client = LLMClient(
        refuse, RateLimiter(10**9, 10**9), cache_dir, counter, input_limit=config.input_limit(role)
    )
    return client, config.models[role].model


def client_for(
    config: LLMConfig, role: str, cache_dir: Path, counter: TokenCounter
) -> tuple[LLMClient, str]:
    """A live client for one configured model role, and that model's ID."""
    model = config.models[role]
    provider = config.providers[model.provider]
    api_key = os.environ.get(provider.api_key_env)
    if not api_key:
        raise RuntimeError(f"set {provider.api_key_env} to call {model.provider}")
    ledger = cache_dir / "usage" / f"{model.model.replace('/', '__')}.jsonl"
    limiter = RateLimiter(
        provider.tokens_per_minute,
        provider.requests_per_day,
        tokens_per_day=provider.tokens_per_day,
        ledger=ledger,
        output_tokens_per_minute=model.output_tokens_per_minute,
    )
    backend = openai_backend(provider.base_url, api_key)
    client = LLMClient(backend, limiter, cache_dir, counter, input_limit=config.input_limit(role))
    return client, model.model
