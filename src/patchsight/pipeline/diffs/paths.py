"""Classify changed file paths, so tests, docs, changelogs and vendored code are dropped.

Proposal §4, preprocessing step 3. Only source kinds go on to hunk mapping; ``python`` is
the kind tree-sitter maps to functions. Rules are checked in a fixed order, so a test file
inside a vendored directory counts as vendored, and so on.

Dropping real source loses recall, which is the dangerous direction, so rules lean towards
keeping code. Known limitation: a package that ships a ``test/`` module as public API (for
example ``django/test/``) is classified as tests; such misses are tagged in failure analysis.
"""

from pathlib import PurePosixPath
from typing import Literal

PathKind = Literal[
    "python",
    "native",
    "other_source",
    "vendored",
    "test",
    "docs",
    "changelog",
    "lockfile",
    "ci",
    "packaging",
    "other",
]
SOURCE_KINDS: frozenset[PathKind] = frozenset({"python", "native", "other_source"})

_VENDORED_DIRS = frozenset(
    {"vendor", "vendored", "_vendor", "third_party", "thirdparty", "externals", "node_modules"}
)
_TEST_DIRS = frozenset({"test", "tests", "unittests", "unit_tests", "testdata"})
_DOC_DIRS = frozenset({"doc", "docs", "documentation", "example", "examples", "benchmarks"})
_CHANGELOG_DIRS = frozenset({"changelog.d", "newsfragments", "changes", "news"})
_CHANGELOG_STEMS = frozenset(
    {"CHANGES", "CHANGELOG", "HISTORY", "NEWS", "RELEASE_NOTES", "RELEASES", "WHATSNEW"}
)
_CI_DIRS = frozenset({".github", ".circleci", ".gitlab", ".azure-pipelines"})
_CI_FILES = frozenset(
    {
        ".gitlab-ci.yml",
        ".travis.yml",
        "azure-pipelines.yml",
        "tox.ini",
        "noxfile.py",
        "appveyor.yml",
    }
)
_PACKAGING_FILES = frozenset(
    {
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "manifest.in",
        "_version.py",
        "version.py",
        "__about__.py",
        "__version__.py",
    }
)
_LOCKFILE_NAMES = frozenset(
    {"pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "package-lock.json", "yarn.lock"}
)
_DOC_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc"})
_PYTHON_SUFFIXES = frozenset({".py", ".pyi", ".pyx", ".pxd", ".pyw"})
_NATIVE_SUFFIXES = frozenset(
    {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".rs", ".go", ".m", ".f90"}
)
_OTHER_SOURCE_SUFFIXES = frozenset(
    {".js", ".mjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".jinja", ".jinja2", ".j2",
     ".mako", ".xml", ".xsl", ".sql", ".sh", ".vue", ".css"}
)  # fmt: skip


def _is_test_file(name: str) -> bool:
    stem = name.rsplit(".", 1)[0]
    return (
        name == "conftest.py"
        or name in ("tests.py", "test.py")
        or (
            name.endswith(".py")
            and (stem.startswith("test_") or stem.endswith(("_test", "_tests")))
        )
    )


def classify_path(path: str) -> PathKind:
    """Classify one repository-relative path from a diff."""
    pure = PurePosixPath(path.strip("/"))
    parts = [p.lower() for p in pure.parts]
    directories = set(parts[:-1])
    name = pure.name
    lower = name.lower()
    suffix = pure.suffix.lower()
    stem_upper = name.split(".", 1)[0].upper()

    if directories & _VENDORED_DIRS:
        return "vendored"
    if directories & _TEST_DIRS or _is_test_file(lower):
        return "test"
    if directories & _CI_DIRS or lower in _CI_FILES:
        return "ci"
    code_suffix = suffix in _PYTHON_SUFFIXES or suffix in _NATIVE_SUFFIXES
    if (stem_upper in _CHANGELOG_STEMS or directories & _CHANGELOG_DIRS) and not code_suffix:
        return "changelog"
    if (
        lower in _LOCKFILE_NAMES
        or suffix == ".lock"
        or (suffix == ".txt" and lower.startswith(("requirements", "constraints")))
    ):
        return "lockfile"
    if directories & _DOC_DIRS or suffix in _DOC_SUFFIXES:
        return "docs"
    if lower in _PACKAGING_FILES:
        return "packaging"
    if suffix in _PYTHON_SUFFIXES:
        return "python"
    if suffix in _NATIVE_SUFFIXES:
        return "native"
    if suffix in _OTHER_SOURCE_SUFFIXES:
        return "other_source"
    return "other"


def is_source(path: str) -> bool:
    return classify_path(path) in SOURCE_KINDS
