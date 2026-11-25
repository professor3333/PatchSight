"""The robustness suite (proposal section 10, issue #55), for every part that needs no model.

Each case is an input the offline pipeline must handle before a model sees it: a very
large diff, a fix squashed with a refactor, a fix that only adds a function, a renamed
file, and a commit message in another language. What the model then does with them is
measured on cached answers; these tests pin the deterministic behaviour that decides what
it is shown and what a record holds without it.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from tenacity import wait_none

from conftest import SHA_A, AdvisoryFactory
from patchsight.pipeline import build_db
from patchsight.pipeline.diffs import github as github_module
from patchsight.pipeline.diffs.commits import CommitMapping, MappedFile
from patchsight.pipeline.diffs.github import ChangeSet, GitHubClient
from patchsight.pipeline.diffs.hunks import diff_hunks
from patchsight.pipeline.diffs.mapping import ChangedDefinition, FileMapping, map_hunks
from patchsight.pipeline.extract import prompt as prompts
from patchsight.pipeline.ingest.aliases import alias_groups
from patchsight.pipeline.llm.tokens import CharEstimate

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 18, tzinfo=UTC)


def _mapping(files: list[MappedFile]) -> CommitMapping:
    return CommitMapping(repo="example/some-pkg", sha=SHA_A, parent="p", files=tuple(files),
                         skipped=(), truncated=False)  # fmt: skip


def _file(path: str, names: list[str], previous: str | None = None,
          sides: tuple[Any, ...] = ("pre", "post")) -> MappedFile:  # fmt: skip
    changed = tuple(ChangedDefinition(path=path, name=n, kind="function", sides=sides,
                                      hunks=(0,)) for n in names)  # fmt: skip
    return MappedFile(
        mapping=FileMapping(path=path, changed=changed, module_level_hunks=(), parse_errors=False),
        status="renamed" if previous else "modified", previous_path=previous,
        diff_source="github_patch",
    )  # fmt: skip


# --- very large diffs ------------------------------------------------------------------


def test_a_commit_with_more_files_than_the_api_pages_is_marked_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(github_module, "MAX_COMMIT_PAGES", 2)
    page = [{"filename": f"pkg/m{i}.py", "status": "modified"}
            for i in range(github_module.COMMIT_FILES_PER_PAGE)]  # fmt: skip

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "sha": SHA_A, "html_url": f"https://github.com/o/r/commit/{SHA_A}", "parents": [],
            "files": page,
        })  # fmt: skip

    client = GitHubClient(tmp_path, transport=httpx.MockTransport(handler), wait=wait_none())
    change: ChangeSet = client.commit("o/r", SHA_A)
    assert change.truncated  # recorded, never silently treated as the whole fix
    assert len(change.files) == 2 * github_module.COMMIT_FILES_PER_PAGE


def test_a_fix_that_changes_too_many_definitions_gets_no_record(
    make_advisory: AdvisoryFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = [f"f{i}" for i in range(build_db.MAX_SYMBOLS + 1)]
    huge = _mapping([_file("src/some_pkg/big.py", names)])
    monkeypatch.setattr(
        build_db, "fix_mappings",
        lambda g, b, gh, p: build_db.FixMappings(status="mapped", packages=("some-pkg",),
                                                 mappings=(huge,), commits=1),
    )  # fmt: skip
    advisories = [make_advisory()]
    records, outcome = build_db.fallback_records(
        alias_groups(advisories)[0], {a.id: a for a in advisories}, None, None, NOW,  # type: ignore[arg-type]
    )  # fmt: skip
    assert records == []
    assert (outcome.status, outcome.symbols) == ("too_broad", build_db.MAX_SYMBOLS + 1)


def test_a_prompt_over_budget_is_cut_by_rank_and_marked_truncated() -> None:
    template = prompts.load_template(ROOT / "prompts" / "extract_v1.md")
    advisory = prompts.AdvisoryText(id="GHSA-x", summary="Path traversal in safe_join",
                                    details="safe_join accepts absolute paths.")  # fmt: skip
    hunk = diff_hunks("a\n", "b\n")[0]
    inputs = [prompts.CandidateInput(path="pkg/m.py", name=f"helper_{i}", kind="function",
                                     hunks=(hunk,), source="s") for i in range(300)]  # fmt: skip
    inputs.append(prompts.CandidateInput(path="pkg/security.py", name="safe_join",
                                         kind="function", hunks=(hunk,), source="s"))  # fmt: skip
    rendered = prompts.render(template, advisory, inputs, 2_000, CharEstimate(3.0), 80)
    assert rendered.truncated  # a truncated prompt can only ever give a low-confidence record
    assert "safe_join" in {c.name for c in rendered.candidates}  # BM25 keeps the named one


# --- a fix squashed with a refactor ----------------------------------------------------

SQUASHED_BEFORE = """def safe_join(base, name):
    return base + "/" + name


def old_helper(x):
    return x


def render(x):
    return old_helper(x)
"""
SQUASHED_AFTER = """def safe_join(base, name):
    if name.startswith("/"):
        raise ValueError(name)
    return base + "/" + name


def new_helper(x):
    return x


def render(x):
    return new_helper(x)
"""


def test_a_fix_squashed_with_a_refactor_keeps_every_changed_definition() -> None:
    before, after = SQUASHED_BEFORE.encode(), SQUASHED_AFTER.encode()
    hunks = diff_hunks(before.decode(), after.decode())
    mapping = map_hunks("pkg/web.py", "python", before, after, hunks)
    names = {c.name for c in mapping.changed}
    assert {"safe_join", "render"} <= names  # the fix and the refactor's call site
    assert {"old_helper", "new_helper"} & names  # the rename shows as a changed definition
    symbols = build_db.changed_symbols(
        [
            _mapping(
                [
                    MappedFile(
                        mapping=mapping,
                        status="modified",
                        previous_path=None,
                        diff_source="computed",
                    )
                ]
            )
        ]
    )
    # The fallback lists them all, so the vulnerable one is never lost among refactors.
    assert "pkg.web.safe_join" in symbols


# --- a fix that only adds a function ---------------------------------------------------

ADD_BEFORE = """def load(path):
    return open(path).read()
"""
ADD_AFTER = """def _check(path):
    if ".." in path:
        raise ValueError(path)


def load(path):
    _check(path)
    return open(path).read()
"""


def test_a_fix_that_adds_a_helper_also_changes_its_caller() -> None:
    before, after = ADD_BEFORE.encode(), ADD_AFTER.encode()
    hunks = diff_hunks(before.decode(), after.decode())
    mapping = map_hunks("pkg/io.py", "python", before, after, hunks)
    by_name = {c.name: c.sides for c in mapping.changed}
    assert by_name["_check"] == ("post",)  # new: not in the vulnerable release
    assert "post" in by_name["load"]  # the vulnerable caller, changed to call it


# --- renamed files ---------------------------------------------------------------------


def test_a_renamed_file_keeps_the_old_module_for_code_that_existed_before() -> None:
    renamed = _file("src/some_pkg/new_name.py", ["load"], previous="src/some_pkg/old_name.py")
    added = _file("src/some_pkg/new_name.py", ["added_later"], previous="src/some_pkg/old_name.py",
                  sides=("post",))  # fmt: skip
    symbols = build_db.changed_symbols([_mapping([renamed, added])])
    assert set(symbols) == {"some_pkg.old_name.load", "some_pkg.new_name.added_later"}


def test_the_old_side_of_a_renamed_file_is_read_from_its_old_path() -> None:
    from patchsight.pipeline.diffs import commits

    asked: list[tuple[str, str]] = []

    class Client:
        def file_content(self, repo: str, path: str, ref: str) -> bytes:
            asked.append((path, ref))
            return b"def load():\n    return 1\n"

    changed = github_module.ChangedFile(filename="pkg/new.py", status="renamed",
                                        previous_filename="pkg/old.py", patch=None)  # fmt: skip
    commits._map_file(Client(), "o/r", "fix", "parent", changed, "python")  # type: ignore[arg-type]
    assert asked == [("pkg/old.py", "parent"), ("pkg/new.py", "fix")]


# --- commit messages in another language -----------------------------------------------


def test_commit_messages_never_reach_a_prompt_or_a_record() -> None:
    # A message in any language cannot change extraction: nothing downstream reads one.
    for model in (ChangeSet, CommitMapping, MappedFile, FileMapping, prompts.CandidateInput):
        assert not {f for f in model.model_fields if "message" in f}, model


def test_non_ascii_advisory_text_and_code_render() -> None:
    template = prompts.load_template(ROOT / "prompts" / "extract_v1.md")
    advisory = prompts.AdvisoryText(id="GHSA-y", summary="路径遍历 (path traversal)",
                                    details="Ataque de inyección en «load»: ✓")  # fmt: skip
    hunk = diff_hunks("# 旧\n", "# 新的注释 ✓\n")[0]
    inputs = [prompts.CandidateInput(path="pkg/m.py", name="load", kind="function",
                                     hunks=(hunk,), source="s")]  # fmt: skip
    rendered = prompts.render(template, advisory, inputs, 5_000, CharEstimate(3.0), 80)
    user = rendered.messages[1]["content"]
    assert "路径遍历" in user
    assert "新的注释" in user
    assert [c.name for c in rendered.candidates] == ["load"]
