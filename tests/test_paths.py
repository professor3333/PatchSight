import pytest
from hypothesis import given
from hypothesis import strategies as st

from patchsight.pipeline.diffs.paths import SOURCE_KINDS, classify_path, is_source


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("lib/yaml/constructor.py", "python"),
        ("src/pkg/_speedups.pyx", "python"),
        ("src/pkg/module.pyi", "python"),
        ("src/_imaging.c", "native"),
        ("src/lib.rs", "native"),
        ("django/contrib/admin/templates/admin/base.html", "other_source"),
        ("pkg/static/app.js", "other_source"),
        ("tests/test_loader.py", "test"),
        ("src/pkg/tests/helpers.py", "test"),
        ("pkg/loader_test.py", "test"),
        ("conftest.py", "test"),
        ("docs/security.rst", "docs"),
        ("examples/demo.py", "docs"),
        ("README.md", "docs"),
        ("CHANGES.rst", "changelog"),
        ("CHANGELOG", "changelog"),
        ("changelog.d/123.bugfix", "changelog"),
        ("newsfragments/42.security.rst", "changelog"),
        ("requirements-dev.txt", "lockfile"),
        ("poetry.lock", "lockfile"),
        (".github/workflows/ci.yml", "ci"),
        ("tox.ini", "ci"),
        ("setup.py", "packaging"),
        ("pyproject.toml", "packaging"),
        ("src/pkg/_version.py", "packaging"),
        ("src/pkg/_vendor/six.py", "vendored"),
        ("third_party/zlib/inflate.c", "vendored"),
        ("data/sample.bin", "other"),
    ],
)
def test_classify_path(path: str, kind: str) -> None:
    assert classify_path(path) == kind


@pytest.mark.parametrize(
    "path",
    [
        # Real modules whose names look like changelogs or test directories must be kept.
        "IPython/core/history.py",
        "app/news/views.py",
        "pkg/changes/models.py",
        "numpy/testing/_private/utils.py",
    ],
)
def test_code_with_changelog_or_test_like_names_is_kept(path: str) -> None:
    assert classify_path(path) == "python"
    assert is_source(path)


@given(st.text())
def test_every_path_gets_a_kind(path: str) -> None:
    kind = classify_path(path)
    assert is_source(path) == (kind in SOURCE_KINDS)
