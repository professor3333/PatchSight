"""Shadow against production: the record-by-record comparison and the review sample."""

from datetime import UTC, datetime
from pathlib import Path

from patchsight import db
from patchsight.pipeline import db_diff

NOW = datetime(2026, 11, 21, tzinfo=UTC)


def _record(key: str, picks: tuple[str, ...] = (), **changes: object) -> db.Record:
    record = db.Record(
        vulnerability=key, package="pkg", confidence="low", source="llm", import_roots=("pkg",),
        entry_points=("pkg.load",),
        symbols=tuple(db.Symbol(qualified_name=f"pkg.{n}", module="pkg", name=n, kind="function",
                                path="pkg/__init__.py") for n in ("load", "dump")),
        fix_commits=(db.FixCommitRef(repo="o/pkg", sha="a" * 40),), model="m",
        prompt_version="extract-v1", input_hash="h" * 64, advisory_modified=NOW, truncated=False,
        extracted_at=NOW, tier_reason="no valid second opinion",
        evidence=tuple(db.SymbolEvidence(qualified_name=p, rationale="r", hunks=()) for p in picks),
    )  # fmt: skip
    return record.model_copy(update=changes)


def test_a_prompt_change_shows_up_in_the_picks_not_the_symbols() -> None:
    before = _record("A", picks=("pkg.load",))
    after = _record("A", picks=("pkg.dump",), truncated=True, prompt_version="extract-v2")
    change = db_diff.compare(before, after)
    assert change is not None
    assert change.fields == ("prompt_version", "truncated", "picks")
    assert (change.added, change.removed) == ({"picks": ("pkg.dump",)}, {"picks": ("pkg.load",)})
    assert db_diff.compare(before, _record("A", picks=("pkg.load",))) is None
    assert db_diff.compare(None, before).kind == "added"  # type: ignore[union-attr]
    assert db_diff.compare(before, None).kind == "removed"  # type: ignore[union-attr]


def _write(path: Path, records: list[db.Record], version: str) -> Path:
    db.write(path, records, {r.vulnerability: r.vulnerability for r in records},
             {"db_version": version})  # fmt: skip
    return path


def test_the_diff_counts_every_change_and_draws_a_seeded_review_sample(tmp_path: Path) -> None:
    production = [_record(f"GHSA-{i:02d}", picks=("pkg.load",)) for i in range(30)]
    shadow = [r.model_copy(update={"evidence": ()}) if i % 3 == 0 else r
              for i, r in enumerate(production) if i != 29]  # fmt: skip
    shadow.append(_record("GHSA-new"))
    old = _write(tmp_path / "old.sqlite", production, "2026.11.20")
    new = _write(tmp_path / "new.sqlite", shadow, "2026.11.21-shadow")
    result = db_diff.diff(old, new, review=5)
    assert (result.production, result.shadow) == ("2026.11.20", "2026.11.21-shadow")
    assert (result.records_before, result.records_after) == (30, 30)
    assert result.kinds == {"added": 1, "changed": 10, "removed": 1}
    assert result.unchanged == 19  # 29 shared records, 10 of them changed
    assert result.fields == {"picks": 10}
    assert len(result.review) == 5
    assert set(result.review) <= {f"{c.vulnerability}/{c.package}" for c in result.changes}
    assert result.review == db_diff.diff(old, new, review=5).review  # reproducible
    text = db_diff.render_markdown(result, "cap the candidates by output capacity (#52)")
    assert "- **The change:** cap the candidates by output capacity (#52)" in text
    assert "| Record | Change | Verdict | Reason |" in text
    assert text.count("| | |") == 5  # each sampled record awaits a verdict


def test_identical_databases_have_nothing_to_review(tmp_path: Path) -> None:
    records = [_record("A"), _record("B")]
    result = db_diff.diff(_write(tmp_path / "a.sqlite", records, "1"),
                          _write(tmp_path / "b.sqlite", records, "2"))  # fmt: skip
    assert (result.unchanged, result.kinds, result.review) == (2, {}, ())
