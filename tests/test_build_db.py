"""The fallback database builder, with GitHub and PyPI replaced by stubs."""

from datetime import UTC, datetime
from typing import Any

import pytest

from conftest import SHA_A, AdvisoryFactory
from patchsight.pipeline import build_db
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping
from patchsight.pipeline.ingest.aliases import alias_groups

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _mapping(repo: str, files: dict[str, list[tuple[str, str]]]) -> CommitMapping:
    mapped = tuple(
        MappedFile(
            mapping=FileMapping(
                path=path,
                changed=tuple(
                    ChangedDefinition(path=path, name=n, kind=k, sides=("post",), hunks=(0,))
                    for n, k in names
                ),
                module_level_hunks=(),
                parse_errors=False,
            ),
            status="modified",
            previous_path=None,
            diff_source="github_patch",
        )
        for path, names in files.items()
    )
    return CommitMapping(
        repo=repo, sha=SHA_A, parent="p", files=mapped, skipped=(), truncated=False
    )


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"repos": frozenset({"example/some-pkg"}), "mapping": None}
    monkeypatch.setattr(
        build_db, "package_repos", lambda g, b, gh, p: (("some-pkg",), state["repos"])
    )
    monkeypatch.setattr(build_db, "map_commit", lambda gh, repo, sha, include: state["mapping"])
    return state


def _build(make_advisory: AdvisoryFactory) -> tuple[list[Any], Any]:
    advisory = make_advisory()
    group = alias_groups([advisory])[0]
    return build_db.fallback_records(group, {advisory.id: advisory}, None, None, NOW)  # type: ignore[arg-type]


def test_fallback_record_is_low_confidence_and_module_qualified(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    stub["mapping"] = _mapping(
        "example/some-pkg",
        {"src/some_pkg/loader.py": [("Loader.read", "method"), ("load", "function")],
         "tools/my-script/run.py": [("main", "function")]},
    )  # fmt: skip
    records, outcome = _build(make_advisory)
    assert (outcome.status, outcome.records, outcome.symbols) == ("built", 1, 3)
    (record,) = records
    assert (record.confidence, record.source, record.package) == ("low", "fallback", "some-pkg")
    assert [s.qualified_name for s in record.symbols] == [
        "main",  # no importable module for that path: bare name only
        "some_pkg.loader.Loader.read",
        "some_pkg.loader.load",
    ]
    assert record.import_roots == ("some_pkg",)
    assert record.entry_points == ()


def test_commits_off_the_package_repo_are_ignored(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    stub["mapping"] = _mapping("fork/some-pkg", {"src/some_pkg/loader.py": [("load", "function")]})
    records, outcome = _build(make_advisory)
    assert records == []
    assert outcome.status == "no_python_fix"


def test_fix_without_python_changes_builds_nothing(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    stub["mapping"] = _mapping("example/some-pkg", {})
    records, outcome = _build(make_advisory)
    assert (records, outcome.status) == ([], "no_python_fix")


def test_input_hash_tracks_only_extraction_inputs(make_advisory: AdvisoryFactory) -> None:
    def digest(**overrides: object) -> str:
        advisory = make_advisory(**overrides)
        return build_db.input_hash(alias_groups([advisory])[0], {advisory.id: advisory})

    base = digest()
    assert digest(modified="2026-12-01T00:00:00Z") == base  # a timestamp bump alone
    assert digest(details="Rewritten details.") != base
    assert digest(references=[]) != base  # fix candidates changed


def test_module_level_only_fixes_are_reported_as_such(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    from patchsight.pipeline.diffs.mapping import FileMapping as FM

    mapping = _mapping("example/some-pkg", {"src/some_pkg/registry.py": []})
    file = mapping.files[0].model_copy(
        update={"mapping": FM(path="src/some_pkg/registry.py", changed=(), module_level_hunks=(0,),
                              parse_errors=False)}
    )  # fmt: skip
    stub["mapping"] = mapping.model_copy(update={"files": (file,)})
    records, outcome = _build(make_advisory)
    assert (records, outcome.status) == ([], "module_level_only")


def test_fixes_touching_too_many_functions_get_no_record(
    stub: dict[str, Any], make_advisory: AdvisoryFactory
) -> None:
    names = [(f"f{i}", "function") for i in range(build_db.MAX_SYMBOLS + 1)]
    stub["mapping"] = _mapping("example/some-pkg", {"src/some_pkg/big.py": names})
    records, outcome = _build(make_advisory)
    assert records == []
    assert (outcome.status, outcome.symbols) == ("too_broad", build_db.MAX_SYMBOLS + 1)
