"""Design rule: no LLM at scan time.

Every module outside ``patchsight.pipeline`` and ``patchsight.eval`` is on the scan path
and must not import the offline pipeline, the evaluation harness, or any LLM, tracing or
diff-parsing dependency. Checked two ways: statically over the source tree, and at
runtime by importing the CLI in a clean interpreter.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "patchsight"
OFFLINE_PACKAGES = ("pipeline", "eval")
FORBIDDEN_PREFIXES = (
    "patchsight.pipeline",
    "patchsight.eval",
    "openai",
    "langfuse",
    "tree_sitter",
    "unidiff",
    "bm25s",
    "rank_bm25",
)


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _module_name(path)
    if path.name != "__init__.py":
        package = package.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                prefix = ".".join([*base, node.module] if node.module else base)
            else:
                prefix = node.module or ""
            found.add(prefix)
            found.update(f"{prefix}.{alias.name}" for alias in node.names)
    return found


def _scan_path_files() -> list[Path]:
    files = []
    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC).parts
        if relative[0] in OFFLINE_PACKAGES:
            continue
        files.append(path)
    return files


def _is_forbidden(module: str) -> bool:
    return any(module == p or module.startswith(f"{p}.") for p in FORBIDDEN_PREFIXES)


def test_scan_path_files_exist() -> None:
    assert _scan_path_files(), "expected at least one scan-path module"


@pytest.mark.parametrize("path", _scan_path_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_scan_path_module_has_no_offline_imports(path: Path) -> None:
    offenders = sorted(m for m in _imported_modules(path) if _is_forbidden(m))
    assert not offenders, f"{path.relative_to(SRC)} imports offline-only modules: {offenders}"


def test_cli_import_loads_no_offline_modules() -> None:
    code = (
        "import sys, patchsight.cli\n"
        f"bad = [m for m in sys.modules if m.startswith({FORBIDDEN_PREFIXES!r})]\n"
        "print(','.join(sorted(bad)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"CLI import loaded: {result.stdout.strip()}"
