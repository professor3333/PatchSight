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


def _limited_then_ok(reset_in: float, clock: list[float]) -> httpx.MockTransport:
    responses = iter(
        [
            httpx.Response(403, headers={"x-ratelimit-remaining": "0",
                                         "x-ratelimit-reset": str(int(clock[0] + reset_in))}),
            httpx.Response(200, json={"ok": True}),
        ]
    )  # fmt: skip
    return httpx.MockTransport(lambda request: next(responses))


def test_waits_out_a_rate_limit_that_resets_soon(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    slept: list[float] = []
    client = CachedJsonClient(
        "https://api.example.org", tmp_path, transport=_limited_then_ok(60, clock),
        wait=wait_none(), wait_for_rate_limit=3900, sleep=slept.append, clock=lambda: clock[0],
    )  # fmt: skip
    assert client.get_json("/x") == {"ok": True}
    assert client.rate_limit_waits == 1
    assert slept == [pytest.approx(65.0)]


def test_does_not_wait_for_a_distant_reset(tmp_path: Path) -> None:
    clock = [1_000_000.0]
    client = CachedJsonClient(
        "https://api.example.org", tmp_path, transport=_limited_then_ok(7200, clock),
        wait=wait_none(), wait_for_rate_limit=3900, sleep=lambda s: None, clock=lambda: clock[0],
    )  # fmt: skip
    with pytest.raises(RateLimitError):
        client.get_json("/x")


def test_exhausted_retries_raise_a_catchable_http_error(tmp_path: Path) -> None:
    client = _client(tmp_path, httpx.MockTransport(lambda request: httpx.Response(502)))
    with pytest.raises(HttpError, match="gave up after 3 attempts"):
        client.get_json("/flaky")


def test_offline_mode_serves_the_cache_and_never_uses_the_network(tmp_path: Path) -> None:
    from patchsight.pipeline.http import CacheMissError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": 1})

    _client(tmp_path, httpx.MockTransport(handler)).get_json("/cached")

    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError("offline mode used the network")

    offline = CachedJsonClient(
        "https://api.example.org", tmp_path / "cache", transport=httpx.MockTransport(refuse),
        offline=True,
    )  # fmt: skip
    assert offline.get_json("/cached") == {"value": 1}
    with pytest.raises(CacheMissError):
        offline.get_json("/missing")
    assert offline.network_requests == 0
    assert [p.name for p in offline.cache_files_used] == [
        next((tmp_path / "cache").rglob("*.json")).name
    ]
    assert issubclass(CacheMissError, HttpError)


def test_a_refused_token_raises_at_once_and_is_never_cached(tmp_path: Path) -> None:
    from patchsight.pipeline.http import AuthError

    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"message": "Bad credentials"})

    client = _client(tmp_path, httpx.MockTransport(handler))
    for _ in range(2):
        with pytest.raises(AuthError, match="HTTP 401"):
            client.get_json("/repos/o/r/tags")
    assert calls == 2  # not retried, and not cached: a valid token later gets the real answer
    assert not list((tmp_path / "cache").rglob("*.json"))


def test_the_token_check_asks_github_itself() -> None:
    from patchsight.pipeline.diffs.github import check_token
    from patchsight.pipeline.http import AuthError

    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Authorization"))
        if request.headers.get("Authorization") == "Bearer good":
            return httpx.Response(200, json={"resources": {"core": {"remaining": 4321}}})
        return httpx.Response(401, json={"message": "Bad credentials"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert check_token("good", client) == 4321
    with pytest.raises(AuthError):
        check_token("expired", client)
    assert seen == ["Bearer good", "Bearer expired"]
