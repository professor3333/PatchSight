import pytest

from patchsight.names import canonical_package_name


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PyYAML", "pyyaml"),
        ("zope.interface", "zope-interface"),
        ("Foo__Bar", "foo-bar"),
        ("foo-._bar", "foo-bar"),
        ("  requests  ", "requests"),
    ],
)
def test_canonical_package_name(raw: str, expected: str) -> None:
    assert canonical_package_name(raw) == expected


def test_canonical_package_name_is_idempotent() -> None:
    once = canonical_package_name("Django_REST.framework")
    assert canonical_package_name(once) == once
