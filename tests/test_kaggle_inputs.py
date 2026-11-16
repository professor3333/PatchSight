"""The offline Kaggle input bundle: written, restored from a zip or a directory, refused when
unsafe or incomplete."""

import zipfile
from pathlib import Path

import pytest

from patchsight.pipeline import kaggle_inputs

DUMP = "data/raw/osv-pypi/all.zip"


def _bundle(tmp_path: Path) -> Path:
    http = tmp_path / "src" / ".cache" / "http"
    files = []
    for service, key in (("github", "ab/abc.json"), ("pypi", "cd/cde.json")):
        path = http / service / key
        path.parent.mkdir(parents=True)
        path.write_text('{"status": 200, "body": {}}')
        files.append(path)
    dump = tmp_path / "src" / "all.zip"
    dump.write_bytes(b"PK-dump-bytes")
    out = tmp_path / "bundle.zip"
    kaggle_inputs.write_bundle(out, dump, "sha", files, http, {"mapped": 2})
    return out


def test_bundle_round_trips_through_a_zip(tmp_path: Path) -> None:
    out = _bundle(tmp_path)
    names = zipfile.ZipFile(out).namelist()
    assert not any(part.startswith(".") for n in names for part in n.split("/"))
    root = tmp_path / "kaggle"
    info = kaggle_inputs.restore(out, root, DUMP, root / ".cache")
    assert (info.files, info.dump_sha256, info.vulnerabilities) == (2, "sha", {"mapped": 2})
    assert (root / DUMP).read_bytes() == b"PK-dump-bytes"
    assert (root / ".cache/http/github/ab/abc.json").is_file()
    assert (root / ".cache/http/pypi/cd/cde.json").is_file()


def test_bundle_restores_from_the_directory_kaggle_extracts(tmp_path: Path) -> None:
    extracted = tmp_path / "input"
    zipfile.ZipFile(_bundle(tmp_path)).extractall(extracted)
    root = tmp_path / "kaggle"
    assert kaggle_inputs.restore(extracted, root, DUMP, root / ".cache").files == 2
    assert (root / DUMP).read_bytes() == b"PK-dump-bytes"


@pytest.mark.parametrize(
    "member", ["../escape.json", "/abs.json", "http-cache/gitlab/ab/x.json", "notes.txt"]
)
def test_unexpected_or_unsafe_members_are_refused(tmp_path: Path, member: str) -> None:
    out = _bundle(tmp_path)
    with zipfile.ZipFile(out, "a") as bundle:
        bundle.writestr(member, "{}")
    with pytest.raises(ValueError, match="bundle"):
        kaggle_inputs.restore(out, tmp_path / "kaggle", DUMP, tmp_path / "kaggle" / ".cache")


def test_an_incomplete_bundle_is_refused(tmp_path: Path) -> None:
    extracted = tmp_path / "input"
    zipfile.ZipFile(_bundle(tmp_path)).extractall(extracted)
    (extracted / "http-cache/pypi/cd/cde.json").unlink()
    with pytest.raises(ValueError, match="incomplete bundle: 1 of 2"):
        kaggle_inputs.restore(extracted, tmp_path / "k", DUMP, tmp_path / "k" / ".cache")
