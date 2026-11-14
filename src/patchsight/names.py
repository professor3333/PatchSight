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
