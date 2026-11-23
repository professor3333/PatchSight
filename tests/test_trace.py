"""Run traces (#60): every model call is recorded, and a trace never stops a run."""

import json
from pathlib import Path

import pytest

from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    ProviderRejectedError,
    RateLimiter,
)
from patchsight.pipeline.trace import Tracer, trace_path


def _request(content: str = "hello") -> LLMRequest:
    return LLMRequest(
        model="m", prompt_version="extract-v1", messages=({"role": "user", "content": content},),
        schema_name="s", response_schema={"type": "object"}, max_tokens=10, seed=1,
    )  # fmt: skip


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_events_carry_the_time_the_kind_and_the_advisory(tmp_path: Path) -> None:
    tracer = Tracer(tmp_path / "t.jsonl")
    tracer.emit("run_start", command="x")
    with tracer.advisory("GHSA-1"):
        tracer.emit("extraction", status="ok")
    tracer.emit("run_end")
    events = _events(tmp_path / "t.jsonl")
    assert [e["kind"] for e in events] == ["run_start", "extraction", "run_end"]
    assert [e.get("advisory") for e in events] == [None, "GHSA-1", None]
    assert str(events[0]["ts"]).endswith("+00:00")


def test_a_tracer_without_a_file_does_nothing(tmp_path: Path) -> None:
    Tracer().emit("run_start")
    assert not list(tmp_path.iterdir())


def test_a_trace_that_cannot_be_written_never_stops_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocked = tmp_path / "file"
    blocked.write_text("")
    tracer = Tracer(blocked / "t.jsonl")  # a file where a directory should be
    tracer.emit("run_start")
    tracer.emit("run_end")
    assert capsys.readouterr().err.count("tracing stopped") == 1


def test_every_model_call_is_traced_and_no_prompt_or_answer_is(tmp_path: Path) -> None:
    def backend(request: LLMRequest) -> tuple[str, int, int]:
        if "reject" in request.messages[0]["content"]:
            raise ProviderRejectedError("Failed to generate JSON for org_01abcDEF234567")
        if "fail" in request.messages[0]["content"]:
            raise TimeoutError("slow")
        return '{"secret answer": true}', 12, 3

    tracer = Tracer(tmp_path / "t.jsonl")
    client = LLMClient(backend, RateLimiter(100_000, 100), tmp_path / "cache", tracer=tracer)
    with tracer.advisory("GHSA-1"):
        client.complete(_request())
        client.complete(_request())  # answered from the cache
        for _ in range(2):  # live, then the cached rejection
            with pytest.raises(ProviderRejectedError):
                client.complete(_request("reject"))
        with pytest.raises(TimeoutError):
            client.complete(_request("fail"))
    calls = _events(tmp_path / "t.jsonl")
    assert [(c["cached"], c["outcome"]) for c in calls] == [
        (False, "ok"), (True, "ok"), (False, "rejected"), (True, "rejected"),
        (False, "TimeoutError"),
    ]  # fmt: skip
    assert {c["advisory"] for c in calls} == {"GHSA-1"}
    assert (calls[0]["prompt_tokens"], calls[0]["completion_tokens"]) == (12, 3)
    assert calls[0]["input_hash"] == _request().cache_key()
    text = (tmp_path / "t.jsonl").read_text()
    for private in ("hello", "secret answer", "org_01abcDEF234567"):
        assert private not in text


def test_a_cache_only_miss_is_traced_as_not_cached(tmp_path: Path) -> None:
    from patchsight.pipeline.llm.client import ResponseNotCachedError

    def refuse(request: LLMRequest) -> tuple[str, int, int]:
        raise ResponseNotCachedError("no cached response")

    tracer = Tracer(tmp_path / "t.jsonl")
    client = LLMClient(refuse, RateLimiter(100_000, 100), tmp_path / "cache", tracer=tracer)
    with pytest.raises(ResponseNotCachedError):
        client.complete(_request())
    assert [(c["cached"], c["outcome"]) for c in _events(tmp_path / "t.jsonl")] == [
        (False, "not_cached")
    ]
    assert client.network_calls == 0


def test_each_run_gets_its_own_file(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    started = datetime(2026, 11, 21, 3, 4, 5, tzinfo=UTC)
    path = trace_path(tmp_path, "pypi-extract-kaggle_extractor-shard4of4", started)
    assert (
        path
        == tmp_path
        / "data/interim/traces/pypi-extract-kaggle_extractor-shard4of4-20261121T030405Z.jsonl"
    )


def _client_for_run(tmp_path: Path) -> LLMClient:
    return LLMClient(lambda r: ("{}", 1, 1), RateLimiter(100_000, 100), tmp_path / "cache")


def _run_events(tmp_path: Path) -> list[dict[str, object]]:
    (trace,) = (tmp_path / "data" / "interim" / "traces").glob("*.jsonl")
    return _events(trace)


def test_a_run_is_traced_from_start_to_end(tmp_path: Path) -> None:
    from patchsight.pipeline.__main__ import _run_trace

    llm = _client_for_run(tmp_path)
    with _run_trace(tmp_path, "pypi-extract-x", "pypi-extract", llm, shard="4/4") as end:
        llm.complete(_request())
        end.update(outcome="time budget", processed=3)
    events = _run_events(tmp_path)
    assert [e["kind"] for e in events] == ["run_start", "llm_call", "run_end"]
    assert (events[0]["command"], events[0]["shard"]) == ("pypi-extract", "4/4")
    assert "code_commit" in events[0]
    assert (events[-1]["outcome"], events[-1]["processed"], events[-1]["network_calls"]) == (
        "time budget", 3, 1,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("error", "outcome"),
    [("quota", "stopped"), ("crash", "crashed")],
)
def test_a_stopped_or_crashed_run_still_ends_its_trace(
    tmp_path: Path, error: str, outcome: str
) -> None:
    from patchsight.pipeline.__main__ import _run_trace
    from patchsight.pipeline.llm.client import QuotaExhaustedError

    llm = _client_for_run(tmp_path)
    raised: Exception = QuotaExhaustedError("cap") if error == "quota" else KeyError("x")
    with pytest.raises(type(raised)), _run_trace(tmp_path, "run", "pypi-extract", llm):
        raise raised
    end = _run_events(tmp_path)[-1]
    assert (end["kind"], end["outcome"], end["reason"]) == (
        "run_end",
        outcome,
        type(raised).__name__,
    )
