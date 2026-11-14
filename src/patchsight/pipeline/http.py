"""A JSON-over-HTTP client with an on-disk response cache, retries and typed errors.

Offline pipeline only. Responses, including "not found", are cached by request, so
re-runs make no network calls and give the same answers. The cache can hold third-party
code (diff patches), so it lives in an ignored directory and is never committed.
Credentials are sent as headers but never become part of a cache key.
"""

import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx
from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from tenacity.wait import wait_base

NOT_FOUND_STATUSES = frozenset({404, 409, 410, 422, 451})
RETRY_STATUSES = frozenset({500, 502, 503, 504})


class HttpError(RuntimeError):
    """A request failed in a way that retrying will not fix."""


class NotFoundError(HttpError):
    """The resource does not exist, or never will for this request."""


class RateLimitError(HttpError):
    """The server's rate limit is exhausted."""


class _RetryableError(Exception):
    pass


class CachedJsonClient:
    def __init__(
        self,
        base_url: str,
        cache_dir: Path,
        headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        max_attempts: int = 4,
        wait: wait_base | None = None,
    ) -> None:
        self._cache_dir = cache_dir
        self._http = httpx.Client(
            base_url=base_url,
            headers=dict(headers or {}),
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            transport=transport,
        )
        self._retrying: Callable[[], Retrying] = lambda: Retrying(
            retry=retry_if_exception_type(_RetryableError),
            stop=stop_after_attempt(max_attempts),
            wait=wait or wait_exponential(multiplier=1, max=30),
            reraise=True,
        )
        self.network_requests = 0

    def close(self) -> None:
        self._http.close()

    def _cache_path(self, path: str, params: Mapping[str, str | int]) -> Path:
        query = "&".join(f"{k}={params[k]}" for k in sorted(params))
        key = hashlib.sha256(f"{self._http.base_url}{path}?{query}".encode()).hexdigest()
        return self._cache_dir / key[:2] / f"{key}.json"

    def get_json(self, path: str, params: Mapping[str, str | int] | None = None) -> Any:
        params = dict(params or {})
        cache_file = self._cache_path(path, params)
        if cache_file.exists():
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
        else:
            cached = self._fetch(path, params)
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cached), encoding="utf-8")
        if cached["status"] != 200:
            raise NotFoundError(f"{path}: HTTP {cached['status']}")
        return cached["body"]

    def _fetch(self, path: str, params: Mapping[str, str | int]) -> dict[str, Any]:
        for attempt in self._retrying():
            with attempt:
                return self._fetch_once(path, params)
        raise AssertionError("unreachable")  # pragma: no cover

    def _fetch_once(self, path: str, params: Mapping[str, str | int]) -> dict[str, Any]:
        self.network_requests += 1
        try:
            response = self._http.get(path, params=dict(params))
        except httpx.TransportError as error:
            raise _RetryableError(str(error)) from error
        status = response.status_code
        if status == 200:
            return {"status": 200, "body": response.json()}
        if status in NOT_FOUND_STATUSES:
            return {"status": status, "body": None}
        if status in (403, 429) and response.headers.get("x-ratelimit-remaining") == "0":
            reset = response.headers.get("x-ratelimit-reset", "unknown")
            raise RateLimitError(f"{path}: rate limit exhausted until {reset}")
        if status in RETRY_STATUSES or status == 429:
            raise _RetryableError(f"{path}: HTTP {status}")
        raise HttpError(f"{path}: HTTP {status}")
