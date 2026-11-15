from pathlib import Path

import pytest

from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    QuotaExhaustedError,
    RateLimiter,
)
from patchsight.pipeline.llm.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def _request(**overrides: object) -> LLMRequest:
    fields: dict[str, object] = {
        "model": "m",
        "prompt_version": "extract-v1",
        "messages": ({"role": "user", "content": "hello"},),
        "schema_name": "s",
        "response_schema": {"type": "object"},
        "max_tokens": 10,
        "seed": 1,
    }
    fields.update(overrides)
    return LLMRequest.model_validate(fields)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_cache_key_covers_everything_that_changes_the_answer() -> None:
    base = _request()
    assert base.cache_key() == _request().cache_key()
    for change in (
        {"model": "other"},
        {"prompt_version": "extract-v2"},
        {"seed": 2},
        {"max_tokens": 11},
        {"extra": {"reasoning_effort": "low"}},
        {"messages": ({"role": "user", "content": "hello!"},)},
    ):
        assert _request(**change).cache_key() != base.cache_key(), change


def test_cache_hit_skips_the_backend(tmp_path: Path) -> None:
    calls: list[LLMRequest] = []

    def backend(request: LLMRequest) -> tuple[str, int, int]:
        calls.append(request)
        return '{"ok": true}', 12, 3

    client = LLMClient(backend, RateLimiter(10_000, 100), tmp_path)
    first = client.complete(_request())
    second = client.complete(_request())
    assert (first.cached, second.cached) == (False, True)
    assert second.content == '{"ok": true}'
    assert (second.prompt_tokens, second.completion_tokens) == (12, 3)
    assert len(calls) == 1
    assert client.network_calls == 1


def test_limiter_waits_for_the_token_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1000, 100, clock=clock, sleep=clock.sleep)
    limiter.acquire(600)
    limiter.acquire(300)
    assert clock.now == 0.0
    limiter.acquire(600)  # 1,500 > 1,000: must wait for the first entry to expire
    assert clock.now == pytest.approx(60.05)
    assert limiter.waited == pytest.approx(60.05)


def test_limiter_uses_actual_usage_once_known() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1000, 100, clock=clock, sleep=clock.sleep)
    limiter.acquire(900)
    limiter.settle(200)  # the provider reported far fewer tokens than estimated
    limiter.acquire(700)
    assert clock.now == 0.0


def test_limiter_stops_at_the_daily_request_cap() -> None:
    limiter = RateLimiter(10_000, 2)
    limiter.acquire(1)
    limiter.acquire(1)
    with pytest.raises(QuotaExhaustedError):
        limiter.acquire(1)


def test_repository_config_loads_and_fits_one_request_per_window() -> None:
    config = load_config(ROOT / "configs" / "llm.toml")
    for role in ("extractor", "second_opinion"):
        model = config.models[role]
        provider = config.providers[model.provider]
        budget = config.prompt_budget(role)
        assert 0 < budget <= config.budget.max_prompt_tokens
        assert budget + model.max_output_tokens < provider.tokens_per_minute


class FakeWall:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_daily_token_cap_is_shared_across_runs(tmp_path: Path) -> None:
    ledger = tmp_path / "usage" / "model.jsonl"
    wall = FakeWall()
    first_run = RateLimiter(100_000, 1000, tokens_per_day=1000, ledger=ledger, wall=wall)
    first_run.acquire(500)
    first_run.settle(600)  # the provider reported 600 tokens

    second_run = RateLimiter(100_000, 1000, tokens_per_day=1000, ledger=ledger, wall=wall)
    second_run.acquire(300)  # 600 + 300 fits
    second_run.settle(300)
    with pytest.raises(QuotaExhaustedError, match="daily token cap"):
        second_run.acquire(200)  # 900 + 200 does not


def test_daily_window_rolls_over(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    wall = FakeWall()
    limiter = RateLimiter(100_000, 1000, tokens_per_day=1000, ledger=ledger, wall=wall)
    limiter.acquire(900)
    limiter.settle(900)
    wall.now += 86_401  # more than 24 hours later
    later = RateLimiter(100_000, 1000, tokens_per_day=1000, ledger=ledger, wall=wall)
    later.acquire(900)


def test_daily_request_cap_counts_the_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "usage.jsonl"
    wall = FakeWall()
    for _ in range(2):
        limiter = RateLimiter(100_000, 2, ledger=ledger, wall=wall)
        limiter.acquire(1)
        limiter.settle(1)
    with pytest.raises(QuotaExhaustedError, match="request cap"):
        RateLimiter(100_000, 2, ledger=ledger, wall=wall).acquire(1)
