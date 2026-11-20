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


def test_each_run_gets_its_own_file(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    started = datetime(2026, 11, 21, 3, 4, 5, tzinfo=UTC)
    path = trace_path(tmp_path, "pypi-extract-kaggle_extractor-shard4of4", started)
    assert (
        path
        == tmp_path
        / "data/interim/traces/pypi-extract-kaggle_extractor-shard4of4-20261121T030405Z.jsonl"
    )
