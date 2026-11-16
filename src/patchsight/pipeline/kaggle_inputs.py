"""The input bundle for an offline PyPI backfill run on Kaggle.

The bundle lets Kaggle spend its GPU time on inference only: no GitHub requests, so no rate
limits and no shared quota with the owner's other work. Kaggle extracts uploaded archives,
so the layout avoids dot-directories and nested zips:

    patchsight-pypi-inputs.json        manifest: dump SHA-256, file count, build statuses
    osv-pypi/all.zip.bin               the pinned OSV dump, byte for byte
    http-cache/github/<xx>/<key>.json  cached GitHub responses
    http-cache/pypi/<xx>/<key>.json    cached PyPI responses

The cached responses include third-party source code (diff patches and file contents), so
the bundle may only ever be a PRIVATE Kaggle dataset (rule 13). ``restore`` puts the files
back where the pipeline expects them; ``pypi-extract`` then verifies the dump against the
snapshot manifest before using it.
"""

import hashlib
import json
import shutil
import zipfile
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline import build_db
from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.http import CacheMissError
from patchsight.pipeline.ingest.aliases import AliasGroup
from patchsight.pipeline.ingest.osv import Advisory
from patchsight.pipeline.pypi import PyPIClient

MANIFEST = "patchsight-pypi-inputs.json"
DUMP_MEMBER = "osv-pypi/all.zip.bin"
CACHE_PREFIX = "http-cache/"
CACHE_SERVICES = ("github", "pypi")


class BundleInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    dump_sha256: str
    files: int
    vulnerabilities: dict[str, int]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def walk(
    groups: Sequence[AliasGroup],
    by_id: dict[str, Advisory],
    github: GitHubClient,
    pypi: PyPIClient,
) -> dict[str, int]:
    """Map every vulnerability's fixes, as pypi-extract will, so the clients record exactly
    which cached responses the backfill reads. Returns the build statuses."""
    statuses: Counter[str] = Counter()
    for group in sorted(groups, key=lambda g: g.key):
        try:
            statuses[build_db.fix_mappings(group, by_id, github, pypi).status] += 1
        except CacheMissError:
            statuses["cache_miss"] += 1
    return dict(sorted(statuses.items()))


def write_bundle(
    out: Path,
    dump: Path,
    dump_sha256: str,
    cache_files: Iterable[Path],
    http_cache: Path,
    statuses: dict[str, int],
) -> BundleInfo:
    """Write the bundle. ``cache_files`` must lie under ``http_cache``."""
    ordered = sorted(cache_files)
    info = BundleInfo(dump_sha256=dump_sha256, files=len(ordered), vulnerabilities=statuses)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MANIFEST, info.model_dump_json(indent=2) + "\n")
        bundle.write(dump, DUMP_MEMBER)
        for path in ordered:
            bundle.write(path, CACHE_PREFIX + path.relative_to(http_cache).as_posix())
    return info


def _target(member: str, dump_path: Path, cache: Path) -> Path | None:
    """Where a bundle member goes, or None for the manifest. Refuses anything unexpected."""
    parts = PurePosixPath(member).parts
    if member.startswith("/") or ".." in parts:
        raise ValueError(f"unsafe path in the bundle: {member!r}")
    if member == MANIFEST:
        return None
    if member == DUMP_MEMBER:
        return dump_path
    in_cache = member.startswith(CACHE_PREFIX) and len(parts) == 4
    if in_cache and parts[1] in CACHE_SERVICES and parts[3].endswith(".json"):
        return cache / "http" / parts[1] / parts[2] / parts[3]
    raise ValueError(f"unexpected file in the bundle: {member!r}")


def restore(source: Path, root: Path, dump_relative: str, cache: Path) -> BundleInfo:
    """Restore a bundle, given as the zip or as the directory Kaggle extracted it into.

    ``dump_relative`` is the dump's path in the snapshot manifest; ``cache`` is the cache
    root (its ``http`` subdirectory receives the responses).
    """
    dump_path = root / dump_relative
    restored = 0
    if source.is_dir():
        info = BundleInfo.model_validate_json((source / MANIFEST).read_text("utf-8"))
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            target = _target(path.relative_to(source).as_posix(), dump_path, cache)
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                restored += target != dump_path
    else:
        with zipfile.ZipFile(source) as bundle:
            info = BundleInfo.model_validate(json.loads(bundle.read(MANIFEST)))
            for item in bundle.infolist():
                if item.is_dir():
                    continue
                target = _target(item.filename, dump_path, cache)
                if target is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(bundle.read(item))
                    restored += target != dump_path
    if restored != info.files or not dump_path.is_file():
        raise ValueError(
            f"incomplete bundle: {restored} of {info.files} responses, "
            f"dump {'present' if dump_path.is_file() else 'missing'}"
        )
    return info
