from pathlib import Path

import httpx
import pytest
from tenacity import wait_none

from patchsight.pipeline.http import CachedJsonClient, HttpError, NotFoundError, RateLimitError


def _client(tmp_path: Path, handler: httpx.MockTransport) -> CachedJsonClient:
    return CachedJsonClient(
        "https://api.example.org",
        tmp_path / "cache",
        headers={"Authorization": "Bearer secret-token"},
        transport=handler,
        max_attempts=3,
        wait=wait_none(),
    )


def test_responses_are_cached_and_reused(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"value": 1})

    client = _client(tmp_path, httpx.MockTransport(handler))
    assert client.get_json("/thing", {"page": 1}) == {"value": 1}
    assert client.get_json("/thing", {"page": 1}) == {"value": 1}
    assert len(calls) == 1
    assert client.network_requests == 1
    cached = list((tmp_path / "cache").rglob("*.json"))
    assert len(cached) == 1
    assert "secret-token" not in cached[0].read_text()


def test_not_found_is_cached_and_raised(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(404)

    client = _client(tmp_path, httpx.MockTransport(handler))
    for _ in range(2):
        with pytest.raises(NotFoundError):
            client.get_json("/missing")
    assert calls == 1


def test_server_errors_are_retried(tmp_path: Path) -> None:
    responses = iter([httpx.Response(502), httpx.Response(503), httpx.Response(200, json=[1])])
    client = _client(tmp_path, httpx.MockTransport(lambda request: next(responses)))
    assert client.get_json("/flaky") == [1]
    assert client.network_requests == 3


def test_persistent_server_errors_give_up(tmp_path: Path) -> None:
    client = _client(tmp_path, httpx.MockTransport(lambda request: httpx.Response(500)))
    with pytest.raises(Exception, match="HTTP 500"):
        client.get_json("/down")
    assert not list((tmp_path / "cache").rglob("*.json"))


def test_exhausted_rate_limit_stops_immediately(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1"}
        return httpx.Response(403, headers=headers)

    client = _client(tmp_path, httpx.MockTransport(handler))
    with pytest.raises(RateLimitError):
        client.get_json("/limited")
    assert client.network_requests == 1


def test_other_client_errors_are_not_cached(tmp_path: Path) -> None:
    client = _client(tmp_path, httpx.MockTransport(lambda request: httpx.Response(401)))
    with pytest.raises(HttpError, match="HTTP 401"):
        client.get_json("/private")
    assert not list((tmp_path / "cache").rglob("*.json"))
