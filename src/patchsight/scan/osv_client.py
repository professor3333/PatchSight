"""Match pinned dependencies to advisories with OSV's batch API.

This is the scan path's only network call apart from downloading the database. It sends
package names and versions, never code. ``querybatch`` returns only vulnerability IDs,
which is all the scanner needs to look records up in the local database.
"""

from collections.abc import Sequence
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 1000  # OSV's documented maximum queries per batch


class OsvError(RuntimeError):
    """OSV could not be reached or returned an unexpected response."""


class _Retryable(Exception):
    pass


@retry(
    retry=retry_if_exception_type(_Retryable),
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, max=10),
    reraise=True,
)
def _post(client: httpx.Client, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        response = client.post(OSV_QUERYBATCH, json={"queries": queries})
    except httpx.TransportError as error:
        raise _Retryable(str(error)) from error
    if response.status_code >= 500 or response.status_code == 429:
        raise _Retryable(f"OSV returned HTTP {response.status_code}")
    if response.status_code != 200:
        raise OsvError(f"OSV returned HTTP {response.status_code}")
    results = response.json().get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        raise OsvError("OSV returned a malformed batch response")
    return results


def query(
    packages: Sequence[tuple[str, str]], client: httpx.Client | None = None
) -> dict[tuple[str, str], list[str]]:
    """Vulnerability IDs for each ``(package, version)`` pair, following pagination."""
    owns = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
    found: dict[tuple[str, str], list[str]] = {pair: [] for pair in packages}
    pending: list[tuple[tuple[str, str], str | None]] = [
        (pair, None) for pair in dict.fromkeys(packages)
    ]
    try:
        while pending:
            batch, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]
            queries = []
            for (name, version), token in batch:
                q: dict[str, Any] = {
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                }
                if token:
                    q["page_token"] = token
                queries.append(q)
            try:
                results = _post(client, queries)
            except _Retryable as error:
                raise OsvError(f"OSV is unreachable: {error}") from None
            for (pair, _), result in zip(batch, results, strict=True):
                found[pair].extend(v["id"] for v in result.get("vulns") or [])
                if result.get("next_page_token"):
                    pending.append((pair, result["next_page_token"]))
    finally:
        if owns:
            client.close()
    return {pair: sorted(set(ids)) for pair, ids in found.items()}
