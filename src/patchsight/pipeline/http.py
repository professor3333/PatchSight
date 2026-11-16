"""A JSON-over-HTTP client with an on-disk response cache, retries and typed errors.

Offline pipeline only. Responses, including "not found", are cached by request, so
re-runs make no network calls and give the same answers. The cache can hold third-party
code (diff patches), so it lives in an ignored directory and is never committed.
Credentials are sent as headers but never become part of a cache key.
"""

import hashlib
import json
import time
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


class CacheMissError(HttpError):
    """Offline mode: the response is not in the cache, and the network may not be used."""


class RateLimitError(HttpError):
    """The server's rate limit is exhausted."""

    def __init__(self, message: str, reset_at: float | None = None) -> None:
        super().__init__(message)
        self.reset_at = reset_at


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
        wait_for_rate_limit: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        offline: bool = False,
    ) -> None:
        """``wait_for_rate_limit``: the longest wait, in seconds, for an exhausted rate
        limit to reset before retrying. Zero raises ``RateLimitError`` at once.

        ``offline``: answer only from the cache; a miss raises ``CacheMissError``."""
        self._cache_dir = cache_dir
        self._offline = offline
        # Every cache file a request used, so a run's exact inputs can be exported.
        self.cache_files_used: set[Path] = set()
        self._max_attempts = max_attempts
        self._wait_for_rate_limit = wait_for_rate_limit
        self._sleep = sleep
        self._clock = clock
        self.rate_limit_waits = 0
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
        elif self._offline:
            raise CacheMissError(f"{path}: not in the offline cache")
        else:
            cached = self._fetch(path, params)
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cached), encoding="utf-8")
        self.cache_files_used.add(cache_file)
        if cached["status"] != 200:
            raise NotFoundError(f"{path}: HTTP {cached['status']}")
        return cached["body"]

    def _fetch(self, path: str, params: Mapping[str, str | int]) -> dict[str, Any]:
        while True:
            try:
                for attempt in self._retrying():
                    with attempt:
                        return self._fetch_once(path, params)
            except _RetryableError as error:
                # Out of retries: an ordinary, catchable failure, not an internal type.
                raise HttpError(f"gave up after {self._max_attempts} attempts: {error}") from None
            except RateLimitError as limited:
                if limited.reset_at is None:
                    raise
                wait = limited.reset_at - self._clock() + 5.0
                if not 0 < wait <= self._wait_for_rate_limit:
                    raise
                self.rate_limit_waits += 1
                self._sleep(wait)
            else:  # pragma: no cover - the loop above always returns or raises
                raise AssertionError("unreachable")

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
            reset = response.headers.get("x-ratelimit-reset")
            reset_at = float(reset) if reset and reset.isdigit() else None
            raise RateLimitError(f"{path}: rate limit exhausted until {reset}", reset_at)
        if status in RETRY_STATUSES or status == 429:
            raise _RetryableError(f"{path}: HTTP {status}")
        raise HttpError(f"{path}: HTTP {status}")
