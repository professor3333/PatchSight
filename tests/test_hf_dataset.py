"""Publishing a database release as a Hugging Face dataset."""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.db import FixCommitRef, Record, Symbol
from patchsight.pipeline import hf_dataset
from patchsight.pipeline.__main__ import app
from patchsight.pipeline.attribution import ATTRIBUTION

NOW = datetime(2026, 11, 21, tzinfo=UTC)


def _asset(tmp_path: Path, version: str = "2026.11.21.1") -> Path:
    symbol = Symbol(qualified_name="yaml.load", module="yaml", name="load", kind="function",
                    path="lib/yaml/__init__.py")  # fmt: skip
    commit = FixCommitRef(repo="y/p", sha="a" * 40)
    records = [
        Record(vulnerability=f"GHSA-{n}", package="pyyaml", confidence="low", source=source,
               import_roots=("yaml",), entry_points=(), fix_commits=(commit,), symbols=(symbol,),
               model=None, prompt_version=None, input_hash="h", advisory_modified=NOW,
               truncated=False, extracted_at=NOW)
        for n, source in (("b", "fallback"), ("a", "llm"))
    ]  # fmt: skip
    sqlite = tmp_path / "p.sqlite"
    db.write(sqlite, records, {"GHSA-a": "GHSA-a", "CVE-1": "GHSA-a", "GHSA-b": "GHSA-b"},
             {"db_version": version})  # fmt: skip
    asset = tmp_path / f"patchsight-db-{version}.sqlite.gz"
    asset.write_bytes(gzip.compress(sqlite.read_bytes(), mtime=0))
    return asset


def test_the_folder_holds_records_aliases_the_asset_and_a_card(tmp_path: Path) -> None:
    asset = _asset(tmp_path)
    summary = hf_dataset.build(asset, "db-2026.11.21.1", tmp_path / "hf")
    folder = tmp_path / "hf"
    assert sorted(p.name for p in folder.iterdir()) == sorted(summary.files)
    records = [json.loads(line) for line in (folder / "records.jsonl").read_text().splitlines()]
    assert [r["vulnerability"] for r in records] == ["GHSA-a", "GHSA-b"]  # sorted, every field
    assert records[0]["symbols"][0]["qualified_name"] == "yaml.load"
    aliases = (folder / "aliases.jsonl").read_text().splitlines()
    assert json.loads(aliases[0]) == {"identifier": "CVE-1", "vulnerability": "GHSA-a"}
    assert (folder / asset.name).read_bytes() == asset.read_bytes()
    card = (folder / "README.md").read_text()
    assert card.startswith("---\nlicense: cc-by-4.0\n")
    assert "data_files: records.jsonl" in card
    assert f"SHA-256 `{hf_dataset.asset_sha256(asset)}`" in card
    assert "releases/tag/db-2026.11.21.1" in card
    assert ATTRIBUTION in card  # the same credit and change notice as the release notes
    assert (summary.records, summary.vulnerabilities, summary.identifiers) == (2, 2, 3)
    with pytest.raises(ValueError, match=r"not the release db-2026\.11\.22"):
        hf_dataset.build(asset, "db-2026.11.22", tmp_path / "hf2")


class _Hub:
    def __init__(self, tags: set[str]) -> None:
        self.tags = tags
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_repo_refs(self, repo_id: str, *, repo_type: str | None = None) -> Any:
        return SimpleNamespace(tags=[SimpleNamespace(name=t) for t in self.tags])

    def upload_folder(self, **kwargs: Any) -> Any:
        self.calls.append(("upload", kwargs))
        return SimpleNamespace(oid="c0ffee")

    def create_tag(self, repo_id: str, **kwargs: Any) -> None:
        self.calls.append(("tag", {"repo_id": repo_id, **kwargs}))


def test_a_release_is_one_tagged_commit_and_never_published_twice(tmp_path: Path) -> None:
    summary = hf_dataset.build(_asset(tmp_path), "db-2026.11.21.1", tmp_path / "hf")
    hub = _Hub(tags={"db-2026.11.21"})
    assert hf_dataset.publish(hub, tmp_path / "hf", summary, "o/d") is True
    (kind, upload), (_, tag) = hub.calls
    assert (kind, upload["repo_id"], upload["repo_type"]) == ("upload", "o/d", "dataset")
    assert upload["delete_patterns"] == ["patchsight-db-*.sqlite.gz"]  # the last version's asset
    assert (tag["tag"], tag["revision"], tag["repo_type"]) == (
        "db-2026.11.21.1",
        "c0ffee",
        "dataset",
    )
    again = _Hub(tags={"db-2026.11.21.1"})
    assert hf_dataset.publish(again, tmp_path / "hf", summary, "o/d") is False
    assert again.calls == []


def test_the_command_checks_the_asset_against_its_release(tmp_path: Path) -> None:
    asset = _asset(tmp_path)
    runner = CliRunner()
    base = ["hf-publish", str(asset), "--tag", "db-2026.11.21.1", "--out", str(tmp_path / "hf"),
            "--root", str(tmp_path)]  # fmt: skip
    wrong = runner.invoke(app, [*base, "--expect-sha256", "0" * 64, "--dry-run"])
    assert wrong.exit_code == 2
    assert "nothing published" in wrong.output
    assert not (tmp_path / "hf").exists()
    sha = hf_dataset.asset_sha256(asset)
    dry = runner.invoke(app, [*base, "--expect-sha256", sha, "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert (tmp_path / "hf" / "records.jsonl").exists()
    no_token = runner.invoke(app, [*base, "--expect-sha256", sha], env={"HF_TOKEN": ""})
    assert no_token.exit_code == 2
    assert "set HF_TOKEN" in no_token.output
