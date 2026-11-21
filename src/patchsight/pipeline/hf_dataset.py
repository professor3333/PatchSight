"""Publish a database release as a Hugging Face dataset (proposal §11: releases go to GitHub
Releases and a Hugging Face dataset).

Each release is one commit on the dataset repository, tagged like its GitHub release
(``db-2026.11.21.1``), so a version there is as fixed as the GitHub one: a tag that exists
is never published again. The folder holds:

* ``records.jsonl``: one line per record, every field the database has (the dataset
  viewer's default table);
* ``aliases.jsonl``: every advisory ID and alias, with the vulnerability it belongs to;
* ``patchsight-db-<version>.sqlite.gz``: the release asset itself, as the CLI downloads it;
* ``README.md``: the dataset card, with the version, the asset's SHA-256, the record
  counts and the attribution CC BY 4.0 requires.

No third-party code: records hold names, paths, line ranges and commit SHAs (rule 13).
Offline pipeline only.
"""

import gzip
import hashlib
import json
import shutil
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from patchsight import db
from patchsight.pipeline.attribution import ATTRIBUTION

REPO = "professor3333/patchsight"
GITHUB = "https://github.com/professor3333/PatchSight"


class Published(BaseModel):
    model_config = ConfigDict(frozen=True)

    tag: str
    db_version: str
    asset: str
    asset_sha256: str
    records: int
    vulnerabilities: int
    identifiers: int
    files: tuple[str, ...]


def asset_sha256(asset: Path) -> str:
    return hashlib.sha256(asset.read_bytes()).hexdigest()


def _counts(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT confidence, source FROM records").fetchall()
    finally:
        connection.close()
    return dict(Counter(f"{source}, {confidence}" for confidence, source in rows))


def card(summary: Published, by_kind: dict[str, int]) -> str:
    """The dataset card: metadata for the Hub, then what this version holds and how to use it."""
    kinds = "\n".join(f"| {k} | {v:,} |" for k, v in sorted(by_kind.items()))
    return f"""---
license: cc-by-4.0
pretty_name: PatchSight symbol database
language:
- en
tags:
- security
- vulnerabilities
- python
- pypi
- osv
size_categories:
- 1K<n<10K
configs:
- config_name: records
  data_files: records.jsonl
  default: true
- config_name: aliases
  data_files: aliases.jsonl
---

# PatchSight symbol database

For each PyPI security advisory with a fix on GitHub, the functions and classes its fix \
changed, and the ones a language model picked as vulnerable, with the hunks it cites. \
[PatchSight]({GITHUB}) uses it to tell which dependency alerts your code actually calls, \
with no model at scan time.

This is version **{summary.db_version}** (tag `{summary.tag}`), the same as the \
[GitHub release]({GITHUB}/releases/tag/{summary.tag}).

- **{summary.vulnerabilities:,} vulnerabilities, {summary.records:,} records.** \
{summary.identifiers:,} advisory IDs and aliases point at them.
- `{summary.asset}`: SHA-256 `{summary.asset_sha256}`.

| Records by source and confidence | Records |
|---|---:|
{kinds}

**Every record is low confidence, by policy.** It lists every definition the fix changed; \
the model's picks are kept as evidence. A low-confidence record can mark an alert as called, \
never as "imported, not called". See the [dataset card]({GITHUB}/blob/main/docs/dataset_card.md) \
and the [model card]({GITHUB}/blob/main/docs/model_card.md) for how records are made, what \
the tiers mean and what is measured.

## Use

```bash
pip install patchsight
patchsight db update   # the latest database, SHA-256 checked
patchsight scan .
```

Or read the records directly, at a fixed version:

```python
from datasets import load_dataset

records = load_dataset("{REPO}", "records", revision="{summary.tag}", split="train")
```

## Files

- `records.jsonl`: one record per line: vulnerability, package, confidence, source, import \
roots, symbols, entry points, fix commits, model and prompt version, input hash, the \
advisory's `modified` time, truncation, the tier reason and, for model picks, each symbol's \
rationale and cited hunks (commit, path and line ranges).
- `aliases.jsonl`: every advisory ID and alias (GHSA, PYSEC, CVE, ...) with the \
vulnerability it belongs to.
- `{summary.asset}`: the SQLite database the CLI downloads.

No third-party source code is included.

{ATTRIBUTION}"""


def build(asset: Path, tag: str, target: Path) -> Published:
    """Write the dataset folder for one release asset (a ``.sqlite.gz``) into ``target``."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as scratch:
        sqlite_path = Path(scratch) / "patchsight.sqlite"
        with gzip.open(asset, "rb") as source, sqlite_path.open("wb") as sink:
            shutil.copyfileobj(source, sink)
        database = db.SymbolDatabase(sqlite_path)
        try:
            version = database.meta["db_version"]
            records = sorted(database.all_records(), key=lambda r: (r.vulnerability, r.package))
            aliases = sorted(database.alias_map().items())
        finally:
            database.close()
        by_kind = _counts(sqlite_path)
    if tag != f"db-{version}":
        raise ValueError(f"the asset holds database {version}, not the release {tag}")
    with (target / "records.jsonl").open("w", encoding="utf-8") as out:
        for record in records:
            out.write(json.dumps(record.model_dump(mode="json"), ensure_ascii=False) + "\n")
    with (target / "aliases.jsonl").open("w", encoding="utf-8") as out:
        for identifier, vulnerability in aliases:
            out.write(json.dumps({"identifier": identifier, "vulnerability": vulnerability}) + "\n")
    shutil.copyfile(asset, target / asset.name)
    summary = Published(
        tag=tag, db_version=version, asset=asset.name, asset_sha256=asset_sha256(asset),
        records=len(records), vulnerabilities=len({r.vulnerability for r in records}),
        identifiers=len(aliases),
        files=("README.md", "aliases.jsonl", asset.name, "records.jsonl"),
    )  # fmt: skip
    (target / "README.md").write_text(card(summary, by_kind), "utf-8")
    return summary


class Hub(Protocol):
    """The part of ``huggingface_hub.HfApi`` that publishing uses."""

    def list_repo_refs(self, repo_id: str, *, repo_type: str | None = None) -> Any: ...

    def upload_folder(
        self,
        *,
        repo_id: str,
        folder_path: str | Path,
        commit_message: str | None = None,
        repo_type: str | None = None,
        delete_patterns: list[str] | str | None = None,
    ) -> Any: ...

    def create_tag(
        self,
        repo_id: str,
        *,
        tag: str,
        revision: str | None = None,
        repo_type: str | None = None,
        tag_message: str | None = None,
    ) -> None: ...


def describe_token(whoami: dict[str, Any]) -> str:
    """What a token may do, from ``whoami``: its account, its type and, for a fine-grained
    token, the repositories it is scoped to. Never the token itself."""
    token = (whoami.get("auth") or {}).get("accessToken") or {}
    lines = [
        f"account: {whoami.get('name', '?')}; token: {token.get('displayName', '?')} "
        f"({token.get('role', '?')})"
    ]
    for scope in (token.get("fineGrained") or {}).get("scoped") or []:
        entity = scope.get("entity") or {}
        permissions = ", ".join(sorted(scope.get("permissions") or [])) or "none"
        lines.append(
            f"  scoped to {entity.get('type', '?')} {entity.get('name', '?')}: {permissions}"
        )
    if len(lines) == 1 and token.get("role") == "fineGrained":
        lines.append("  scoped to no repository")
    return "\n".join(lines)


def describe_error(error: Exception) -> str:
    """An HTTP error from the Hub as status and message, with anything shaped like a token
    redacted, so a refused token and a rate limit can be told apart in a public log."""
    import re

    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    text = ""
    if response is not None:
        try:
            body = response.json()
            text = str(body.get("error") or body) if isinstance(body, dict) else str(body)
        except Exception:  # not JSON: keep the start of the text
            text = str(getattr(response, "text", ""))
    text = re.sub(r"hf_[A-Za-z0-9]{8,}", "hf_[redacted]", text or str(error))
    return f"{type(error).__name__}, HTTP {status}: {text.strip()[:300]}"


def publish(hub: Hub, folder: Path, summary: Published, repo: str = REPO) -> bool:
    """Upload the folder as one commit and tag it. False, with nothing uploaded, when the tag
    already exists: a published version is never replaced."""
    tags = {t.name for t in hub.list_repo_refs(repo, repo_type="dataset").tags}
    if summary.tag in tags:
        return False
    commit = hub.upload_folder(
        repo_id=repo, folder_path=folder, repo_type="dataset",
        commit_message=f"Symbol database {summary.db_version}",
        delete_patterns=["patchsight-db-*.sqlite.gz"],  # one version's asset at the head
    )  # fmt: skip
    hub.create_tag(
        repo, tag=summary.tag, revision=commit.oid, repo_type="dataset",
        tag_message=f"Symbol database {summary.db_version}",
    )  # fmt: skip
    return True
