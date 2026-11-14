"""Shared test factories. All OSV records here are synthetic, not copied advisory text."""

import copy
from collections.abc import Callable
from typing import Any

import pytest

from patchsight.pipeline.ingest.osv import Advisory, normalise

SHA_A = "a" * 40
SHA_B = "b" * 40

RecordFactory = Callable[..., dict[str, Any]]
AdvisoryFactory = Callable[..., Advisory]

_BASE: dict[str, Any] = {
    "schema_version": "1.7.3",
    "id": "GHSA-aaaa-bbbb-cccc",
    "modified": "2026-11-01T00:00:00Z",
    "published": "2026-10-01T00:00:00Z",
    "aliases": ["CVE-2099-0001"],
    "summary": "Synthetic advisory",
    "details": "A synthetic advisory used only in tests.",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Some_Pkg"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}],
            "versions": ["1.0", "1.1"],
        }
    ],
    "references": [
        {"type": "FIX", "url": f"https://github.com/example/some-pkg/commit/{SHA_A}"},
        {"type": "WEB", "url": "https://example.org/blog/post"},
    ],
}


@pytest.fixture
def make_record() -> RecordFactory:
    def factory(**overrides: Any) -> dict[str, Any]:
        record = copy.deepcopy(_BASE)
        record.update(overrides)
        return {k: v for k, v in record.items() if v is not None}

    return factory


@pytest.fixture
def make_advisory(make_record: RecordFactory) -> AdvisoryFactory:
    def factory(**overrides: Any) -> Advisory:
        result = normalise(make_record(**overrides), "test.json")
        assert isinstance(result, Advisory), result
        return result

    return factory
