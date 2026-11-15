"""Canonical names shared by the offline pipeline and the scan path.

Both halves must use these functions, so that a package or symbol name written into the
database always matches the name the scanner looks up.
"""

from packaging.utils import canonicalize_name


def canonical_package_name(name: str) -> str:
    """Return the PEP 503 normalised form of a distribution name.

    >>> canonical_package_name("PyYAML")
    'pyyaml'
    >>> canonical_package_name("zope.interface")
    'zope-interface'
    """
    return str(canonicalize_name(name.strip()))


_SOURCE_PREFIXES = frozenset({"lib", "lib3", "python", "py", "Lib"})
_PYTHON_SUFFIXES = (".py", ".pyi", ".pyx")

# Distributions whose import name differs from their distribution name. Used only as a
# hint alongside the import roots recorded in the database; an unknown mapping makes a
# verdict UNKNOWN, never NOT_IMPORTED.
KNOWN_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "pyjwt": ("jwt",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "opencv-python": ("cv2",),
    "protobuf": ("google.protobuf",),
    "setuptools": ("setuptools", "pkg_resources"),
    "msgpack-python": ("msgpack",),
    "python-multipart": ("multipart", "python_multipart"),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "attrs": ("attr", "attrs"),
}


def module_for_path(path: str) -> str | None:
    """The importable module a repository path defines, or None if it cannot be told.

    >>> module_for_path("lib/yaml/constructor.py")
    'yaml.constructor'
    >>> module_for_path("airflow-core/src/airflow/models/dag.py")
    'airflow.models.dag'
    >>> module_for_path("src/flask/__init__.py")
    'flask'
    """
    if not path.endswith(_PYTHON_SUFFIXES):
        return None
    parts = path.strip("/").rsplit(".", 1)[0].split("/")
    if "src" in parts[:-1]:
        parts = parts[len(parts) - 1 - parts[::-1].index("src") + 1 :]
    else:
        while len(parts) > 1 and (parts[0] in _SOURCE_PREFIXES or not parts[0].isidentifier()):
            parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def import_names(package: str, roots: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Names a distribution may be imported as: recorded roots, known exceptions, default."""
    canonical = canonical_package_name(package)
    names = list(roots) + list(KNOWN_IMPORT_NAMES.get(canonical, ()))
    names.append(canonical.replace("-", "_"))
    return tuple(dict.fromkeys(names))
