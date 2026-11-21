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


def test_limiter_paces_output_tokens_per_minute() -> None:
    clock = FakeClock()
    limiter = RateLimiter(100_000, 100, clock=clock, sleep=clock.sleep,
                          output_tokens_per_minute=1000)  # fmt: skip
    limiter.acquire(2000, output=600)
    limiter.settle(1500, output=300)  # the answer used 300 of its 600 allowance
    limiter.acquire(2000, output=600)  # 300 + 600 fits under 1,000: no wait
    assert clock.now == 0.0
    limiter.acquire(2000, output=600)  # 300 + 600 + 600 does not: wait out the first
    assert clock.now == pytest.approx(60.05)
    # Without the limit, output is not paced at all.
    free = RateLimiter(100_000, 100, clock=clock, sleep=clock.sleep)
    for _ in range(5):
        free.acquire(10, output=1000)
    assert clock.now == pytest.approx(60.05)


def test_the_client_reserves_each_requests_output_allowance(tmp_path: Path) -> None:
    clock = FakeClock()

    def backend(request: LLMRequest) -> tuple[str, int, int]:
        return '{"ok": true}', 100, 900  # a long answer

    limiter = RateLimiter(100_000, 100, clock=clock, sleep=clock.sleep,
                          output_tokens_per_minute=1000)  # fmt: skip
    client = LLMClient(backend, limiter, tmp_path)
    client.complete(_request(max_tokens=1000))
    assert clock.now == 0.0
    client.complete(_request(max_tokens=1000, seed=2))  # 900 used: wait for the minute to pass
    assert clock.now == pytest.approx(60.05)


def test_limiter_stops_at_the_daily_request_cap() -> None:
    limiter = RateLimiter(10_000, 2)
    limiter.acquire(1)
    limiter.acquire(1)
    with pytest.raises(QuotaExhaustedError):
        limiter.acquire(1)


def test_repository_config_loads_and_fits_one_request_per_window() -> None:
    config = load_config(ROOT / "configs" / "llm.toml")
    # Kaggle and Groq must see identical prompts for their results to compare.
    assert config.prompt_budget("kaggle_extractor") == config.prompt_budget("extractor")
    # The self-hosted second opinion must see the same prompts as the hosted one (ADR 0007).
    assert config.prompt_budget("kaggle_second_opinion") == config.prompt_budget("second_opinion")
    for role in ("extractor", "second_opinion", "kaggle_extractor", "kaggle_second_opinion"):
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


def test_redact_removes_account_ids_and_keys() -> None:
    from patchsight.pipeline.llm.client import redact

    message = "Request too large in organization `org_01abcDEF234567` (api_key=gsk_secret123)"
    cleaned = redact(message)
    assert "org_01abcDEF234567" not in cleaned
    assert "gsk_secret123" not in cleaned
    assert "org_[redacted]" in cleaned


def test_rejections_are_cached_and_redacted(tmp_path: Path) -> None:
    from patchsight.pipeline.llm.client import ProviderRejectedError

    calls = 0

    def backend(request: LLMRequest) -> tuple[str, int, int]:
        nonlocal calls
        calls += 1
        raise ProviderRejectedError("Failed to generate JSON for org_01abcDEF234567")

    client = LLMClient(backend, RateLimiter(100_000, 100), tmp_path)
    for _ in range(2):
        with pytest.raises(ProviderRejectedError) as raised:
            client.complete(_request())
        assert "org_01abcDEF234567" not in str(raised.value)
    assert calls == 1  # the second attempt replays the cached rejection
    stored = next(tmp_path.rglob("*.json")).read_text()
    assert "org_01abcDEF234567" not in stored


def test_prompt_budget_leaves_room_for_the_repair_round() -> None:
    from patchsight.pipeline.llm.config import LLMConfig

    config = LLMConfig.model_validate(
        {
            "providers": {
                "p": {"base_url": "u", "api_key_env": "K", "tokens_per_minute": 8000,
                      "requests_per_day": 10, "input_tokens_per_minute": 5000},
            },
            "models": {"m": {"provider": "p", "model": "x", "max_output_tokens": 1500, "seed": 1}},
            "budget": {"max_prompt_tokens": 9999, "max_hunk_lines": 80},
            "tokenizer": {"repo": "r", "revision": "v", "sha256": "s"},
        }
    )  # fmt: skip
    # TPM: 8,000 - 2 x 1,500 - 400 = 4,600. ITPM: 5,000 - 1,500 - 400 = 3,100 (binding).
    assert config.prompt_budget("m") == 3100


def test_an_output_allowance_over_the_providers_limit_is_refused() -> None:
    from pydantic import ValidationError

    from patchsight.pipeline.llm.config import ModelConfig

    fields = {"provider": "groq", "model": "q", "seed": 1, "output_tokens_per_minute": 1000}
    assert (
        ModelConfig.model_validate({**fields, "max_output_tokens": 1000}).max_output_tokens == 1000
    )
    with pytest.raises(ValidationError, match="every request would be refused"):
        ModelConfig.model_validate({**fields, "max_output_tokens": 1500})


def test_the_shipped_extractor_fits_groqs_output_limit_with_the_same_prompts() -> None:
    from patchsight.pipeline.llm.config import load_config

    config = load_config(Path(__file__).resolve().parents[1] / "configs" / "llm.toml")
    extractor = config.models["extractor"]
    assert extractor.output_tokens_per_minute == 1000  # measured on Groq, 2026-11-21
    assert extractor.max_output_tokens <= extractor.output_tokens_per_minute
    # Every role keeps the 4,600-token prompt budget.
    assert {config.prompt_budget(role) for role in config.models} == {4600}
    # Only the nightly's Groq extractor is capped, so its answers fit 1,000 tokens; the
    # Kaggle roles' prompts, and so the backfill and the benchmarks, are unchanged (#52).
    assert config.candidate_limit("extractor") == 9
    assert config.candidate_limit("kaggle_extractor") is None
    assert config.candidate_limit("kaggle_second_opinion") is None


def test_candidate_limit_follows_the_output_limit() -> None:
    from patchsight.pipeline.llm.config import LLMConfig

    def config(**budget: int) -> LLMConfig:
        return LLMConfig.model_validate(
            {
                "providers": {"p": {"base_url": "u", "api_key_env": "K",
                                    "tokens_per_minute": 8000, "requests_per_day": 10}},
                "models": {"m": {"provider": "p", "model": "x", "max_output_tokens": 1500,
                                 "seed": 1}},
                "budget": {"max_prompt_tokens": 4600, "max_hunk_lines": 80, **budget},
                "tokenizer": {"repo": "r", "revision": "v", "sha256": "s"},
            }
        )  # fmt: skip

    assert config().candidate_limit("m") is None  # off unless configured
    role_cap = LLMConfig.model_validate(
        {**config().model_dump(), "models": {"m": {"provider": "p", "model": "x",
         "max_output_tokens": 1000, "seed": 1, "output_tokens_per_candidate": 105}}}
    )  # fmt: skip
    assert role_cap.candidate_limit("m") == 9  # the role's own cap: 1,000 // 105
    assert config(output_tokens_per_candidate=105).candidate_limit("m") == 14  # 1,500 // 105
    assert config(output_tokens_per_candidate=5000).candidate_limit("m") == 1


def test_tokenizer_file_must_match_its_pin(tmp_path: Path) -> None:
    pytest.importorskip("tokenizers")
    from patchsight.pipeline.llm.tokens import HfTokenizer, TokenizerConfig, TokenizerMismatchError

    pin = TokenizerConfig(repo="o/m", revision="abc", sha256="0" * 64)
    path = tmp_path / "o__m" / "abc" / "tokenizer.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    with pytest.raises(TokenizerMismatchError):
        HfTokenizer(pin, tmp_path)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Rate limit on tokens per day (TPD): Limit 200000, Used 197108 for org_01abcDEF234567",
         "QuotaExhaustedError"),
        ("Rate limit on tokens per minute (TPM): Limit 8000", "RateLimitedError"),
    ],
)  # fmt: skip
def test_rate_limits_map_to_typed_redacted_errors(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: str
) -> None:
    openai = pytest.importorskip("openai")
    import httpx

    from patchsight.pipeline.llm import client as client_module

    class FakeCompletions:
        def create(self, **_: object) -> object:
            response = httpx.Response(429, request=httpx.Request("POST", "https://x/v1"))
            raise openai.RateLimitError(message, response=response, body=None)

    class FakeOpenAI:
        def __init__(self, **_: object) -> None:
            self.chat = type("Chat", (), {"completions": FakeCompletions()})()

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    backend = client_module.openai_backend("https://x/v1", "key")
    with pytest.raises(getattr(client_module, expected)) as raised:
        backend(_request())
    assert "org_01abcDEF234567" not in str(raised.value)
