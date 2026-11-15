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


@pytest.mark.parametrize(
    ("path", "module"),
    [
        ("lib/yaml/constructor.py", "yaml.constructor"),
        ("lib3/yaml/__init__.py", "yaml"),
        ("src/flask/app.py", "flask.app"),
        ("airflow-core/src/airflow/models/dag.py", "airflow.models.dag"),
        ("llama-index-core/llama_index/core/base.py", "llama_index.core.base"),
        ("django/db/models/query.py", "django.db.models.query"),
        ("six.py", "six"),
        ("src/pkg/_speedups.pyx", "pkg._speedups"),
        ("src/my-pkg/x.py", None),
        ("pkg/module.c", None),
        ("src/__init__.py", None),
    ],
)
def test_module_for_path(path: str, module: str | None) -> None:
    from patchsight.names import module_for_path

    assert module_for_path(path) == module


def test_import_names_combine_roots_exceptions_and_default() -> None:
    from patchsight.names import import_names

    assert import_names("PyYAML") == ("yaml", "pyyaml")
    assert import_names("python-dateutil", ("dateutil",)) == ("dateutil", "python_dateutil")
    assert import_names("requests") == ("requests",)
