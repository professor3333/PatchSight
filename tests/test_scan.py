"""Scan path: requirements parsing, the AST scanner, verdicts, and the CLI end to end."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from patchsight import db
from patchsight.cli import app
from patchsight.scan import ast_scanner, run
from patchsight.scan.lockfiles import requirements
from patchsight.scan.verdicts import decide, matches

NOW = datetime(2026, 11, 15, tzinfo=UTC)


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _record(
    confidence: str = "high", entry_points: tuple[str, ...] = ("yaml.full_load",)
) -> db.Record:
    return db.Record(
        vulnerability="GHSA-0001-0001-0001",
        package="pyyaml",
        confidence=confidence,  # type: ignore[arg-type]
        source="llm" if confidence == "high" else "fallback",
        import_roots=("yaml",),
        entry_points=entry_points,
        symbols=(
            db.Symbol(qualified_name="yaml.constructor.FullConstructor.construct_object",
                      module="yaml.constructor", name="FullConstructor.construct_object",
                      kind="method", path="lib/yaml/constructor.py"),
        ),
        fix_commits=(db.FixCommitRef(repo="yaml/pyyaml", sha="a" * 40),),
        model=None, prompt_version=None, input_hash="h", advisory_modified=NOW,
        truncated=False, extracted_at=NOW,
    )  # fmt: skip


def _verdict(tmp_path: Path, code: str, record: db.Record | None = None) -> str:
    usage = ast_scanner.scan(_write(tmp_path, {"app/main.py": code}))
    return decide("GHSA-1", "pyyaml", "5.3.1", record or _record(), usage).verdict


# --- requirements.txt ----------------------------------------------------------------


def test_requirements_pins_and_reasons(tmp_path: Path) -> None:
    _write(tmp_path, {
        "requirements.txt": (
            "# comment\nPyYAML==5.3.1\nrequests[socks]==2.31.0 ; python_version >= '3.8'\n"
            "flask>=2.0\nDjango\nnumpy==1.*\n-r more.txt\n"
            "cryptography==41.0.0 \\\n    --hash=sha256:abc\n--index-url https://example.org/simple\n"
            "-e ./local\ngit+https://github.com/o/r.git#egg=r\n"
        ),
        "more.txt": "Jinja2==3.1.2\n-r requirements.txt\n",
    })  # fmt: skip
    found = {d.name: d for d in requirements.parse(tmp_path / "requirements.txt")}
    assert (found["pyyaml"].version, found["pyyaml"].raw_name) == ("5.3.1", "PyYAML")
    assert found["requests"].version == "2.31.0"
    assert found["cryptography"].version == "41.0.0"
    assert found["jinja2"].version == "3.1.2"
    assert found["flask"].unpinned_reason == "not an exact pin (>=2.0)"
    assert found["django"].unpinned_reason == "no version specified"
    assert found["numpy"].unpinned_reason == "wildcard pin ==1.*"
    assert (
        sum(1 for d in found.values() if d.unpinned_reason == "URL, path or editable install") == 2
    )


# --- AST scanner -----------------------------------------------------------------------


def test_scanner_resolves_aliases_and_chains(tmp_path: Path) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"m.py": (
        "import yaml as y\nfrom yaml import safe_load as sl\nimport yaml.constructor\n\n"
        "def f(text):\n    sl(text)\n    y.dump({})\n    yaml.constructor.FullConstructor.x\n"
        "    getattr(y, 'load')\n    yaml = None\n"
    )}))  # fmt: skip
    names = sorted(r.name for r in usage.references)
    assert names == [
        "yaml.constructor.FullConstructor.x",
        "yaml.dump",
        "yaml.load",
        "yaml.safe_load",
    ]
    assert set(usage.imports) == {"yaml", "yaml.constructor"}
    assert usage.dynamic == ()  # an assignment target is not a use


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        ("import yaml\nhandler(yaml)\n", "module yaml used as a value"),
        ("import yaml\ngetattr(yaml, name)\n", "getattr(yaml, <computed>)"),
        ("import importlib\nimportlib.import_module('yaml')\n", "importlib.import_module('yaml')"),
        ("m = __import__(name)\n", "__import__('?')"),
        ("from yaml import *\n", "from yaml import *"),
    ],
)
def test_scanner_flags_dynamic_use(tmp_path: Path, code: str, reason: str) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"m.py": code}))
    assert reason in {d.reason for d in usage.dynamic}


def test_scanner_skips_virtualenvs_and_records_unparsable_files(tmp_path: Path) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {
        "ok.py": "import yaml\n", ".venv/lib/x.py": "import yaml\nyaml.load(1)\n",
        "broken.py": "import yaml\ndef (:\n",
    }))  # fmt: skip
    assert usage.files == 2
    assert list(usage.unparsable) == ["broken.py"]
    assert not any(".venv" in r.location.path for r in usage.references)


# --- verdicts --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "import yaml\nyaml.full_load(s)\n",
        "import yaml as y\ny.full_load(s)\n",
        "from yaml import full_load\nfull_load(s)\n",
        "from yaml import full_load as fl\nfl(s)\n",
        "import yaml\ngetattr(yaml, 'full_load')(s)\n",
        "from yaml.constructor import FullConstructor\nFullConstructor()\n",
        "import yaml.constructor\nyaml.constructor.FullConstructor.construct_object(x)\n",
        "import yaml\nyaml.construct_object(x)\n",  # re-export of the vulnerable leaf name
    ],
)
def test_every_supported_call_form_is_called(tmp_path: Path, code: str) -> None:
    """Zero false suppressions: reaching a vulnerable symbol is never 'not called'."""
    assert _verdict(tmp_path, code) == "CALLED"


def test_safe_use_is_imported_not_called(tmp_path: Path) -> None:
    assert _verdict(tmp_path, "import yaml\nyaml.safe_load(s)\n") == "IMPORTED_NOT_CALLED"


def test_low_confidence_never_lowers_an_alert(tmp_path: Path) -> None:
    low = _record(confidence="low", entry_points=())
    assert _verdict(tmp_path, "import yaml\nyaml.safe_load(s)\n", low) == "UNKNOWN"
    assert _verdict(tmp_path, "import yaml\nyaml.construct_object(s)\n", low) == "CALLED"


@pytest.mark.parametrize(
    "code",
    ["import yaml\nhandler(yaml)\n", "import yaml\ngetattr(yaml, name)\n", "from yaml import *\n"],
)
def test_dynamic_use_is_unknown(tmp_path: Path, code: str) -> None:
    assert _verdict(tmp_path, code) == "UNKNOWN"


def test_not_imported_and_its_exceptions(tmp_path: Path) -> None:
    assert _verdict(tmp_path / "a", "import requests\n") == "NOT_IMPORTED"
    assert _verdict(tmp_path / "b", "mod = __import__(name)\n") == "UNKNOWN"
    usage = ast_scanner.scan(_write(tmp_path / "c", {"x.py": "import yaml\ndef (:\n"}))
    assert decide("A", "pyyaml", "1", _record(), usage).verdict == "UNKNOWN"


def test_a_vulnerability_without_a_record_is_one_alert_that_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _write(
        tmp_path / "p", {"requirements.txt": "PyYAML==5.3.1\n", "a.py": "import yaml\n"}
    )
    database = tmp_path / "db.sqlite"
    db.write(database, [_record()],
             {"GHSA-0001-0001-0001": "GHSA-0001-0001-0001", "GHSA-0002": "GHSA-0002",
              "PYSEC-2": "GHSA-0002"},
             {"built_at": datetime.now(UTC).isoformat()},
             builds=[db.BuildEntry(vulnerability="GHSA-0002", input_hash="h",
                                   status="no_python_fix")])  # fmt: skip
    ids = ["GHSA-0002", "PYSEC-2", "MAL-2099-1", "GHSA-other"]
    monkeypatch.setattr(
        run.osv_client, "query", lambda packages, client=None: dict.fromkeys(packages, ids)
    )
    alerts, _, _ = run.run_scan(project, project / "requirements.txt", database)
    by_id = {a.advisory: a for a in alerts}
    assert set(by_id) == {"GHSA-0002", "MAL-2099-1", "GHSA-other"}  # PYSEC-2 joined GHSA-0002
    assert by_id["GHSA-0002"].aliases == ("PYSEC-2",)
    assert by_id["GHSA-0002"].reason == "no symbol data: the fix changes no Python code"
    assert by_id["MAL-2099-1"].reason.startswith("no symbol data: a malicious-package report")
    assert by_id["GHSA-other"].reason == "no symbol data for this advisory"
    assert {a.verdict for a in alerts} == {"UNKNOWN"}


def test_no_record_is_unknown(tmp_path: Path) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"x.py": "import yaml\n"}))
    alert = decide("A", "pyyaml", "1", None, usage)
    assert (alert.verdict, alert.reason) == ("UNKNOWN", "no symbol data for this advisory")


def test_matching_rules() -> None:
    assert matches("yaml.full_load", "yaml.full_load")
    assert matches("yaml.constructor.FullConstructor", "yaml.constructor.FullConstructor.make")
    assert matches("yaml.Loader.get", "yaml.Loader")
    assert matches("pkg.load", "pkg.loader.load")
    assert not matches("yaml", "yaml.load")  # a bare module is not a hit
    assert not matches("yaml.safe_load", "yaml.full_load")


def test_parser_warnings_in_scanned_code_are_not_printed(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"m.py": "import yaml\nP = '\\d+ \\ '\n"}))
    assert usage.files == 1
    assert not [w for w in recwarn if issubclass(w.category, SyntaxWarning)]


def test_references_are_indexed_by_their_top_level_name(tmp_path: Path) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"m.py": (
        "import yaml\nimport requests as r\nimport yamlish\n"
        "yaml.load(s)\nr.get(u)\nyamlish.x(s)\nyaml.dump(s)\n"
    )}))  # fmt: skip
    assert sorted(x.name for x in usage.references_into({"yaml"})) == ["yaml.dump", "yaml.load"]
    both = usage.references_into({"yaml", "requests"})
    assert sorted(x.name for x in both) == ["requests.get", "yaml.dump", "yaml.load"]
    assert usage.references_into({"absent"}) == []


def test_an_unused_from_import_counts_as_a_reexported_reference(tmp_path: Path) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {
        "helpers.py": "from yaml import full_load\nfrom yaml import safe_load\nsafe_load(s)\n",
        "main.py": "from helpers import full_load\nfull_load(s)\n",
    }))  # fmt: skip
    found = sorted((r.name, r.location.path, r.location.line) for r in usage.references)
    assert ("yaml.full_load", "helpers.py", 1) in found  # at the import: never used there
    assert [n for n, *_ in found].count("yaml.safe_load") == 1  # used: only the use counts
    assert _verdict(tmp_path / "v", "from yaml import full_load as fl\n") == "CALLED"


def test_a_vulnerable_name_on_an_untyped_object_withholds_not_called(tmp_path: Path) -> None:
    record = _record(entry_points=("yaml.full_load", "yaml.Loader.__init__"))
    instance = _verdict(tmp_path / "a", "import yaml\nloader.full_load(s)\n", record)
    project = _write(tmp_path / "b", {
        "helpers.py": "import yaml\n",
        "main.py": "import yaml\nimport helpers\nhelpers.yaml.full_load(s)\n",
    })  # fmt: skip
    own_module = decide("A", "pyyaml", "1", record, ast_scanner.scan(project)).verdict
    assert (instance, own_module) == ("UNKNOWN", "UNKNOWN")
    usage = ast_scanner.scan(_write(tmp_path / "c", {"m.py": "import yaml\nx.__init__(s)\n"}))
    alert = decide("A", "pyyaml", "1", record, usage)
    assert alert.verdict == "IMPORTED_NOT_CALLED"  # dunders are not called by name
    assert "loader" not in usage.attributes  # the receiver is a name, not an attribute


def test_a_vulnerable_name_in_a_template_withholds_not_called(tmp_path: Path) -> None:
    record = _record(entry_points=("yaml.full_load",))
    inline = "import yaml\nT = '<p>{{ text|construct_object }}</p>'\n"
    assert _verdict(tmp_path / "a", inline, record) == "UNKNOWN"
    plain = "import yaml\nT = 'construct_object, but not in a template tag'\n"
    assert _verdict(tmp_path / "b", plain, record) == "IMPORTED_NOT_CALLED"
    project = _write(tmp_path / "c", {
        "app.py": "import yaml\n",
        "templates/page.html": "<p>\n{% if x %}\n  {{ x|full_load }}\n{% endif %}\n</p>\n",
        ".venv/t.html": "{{ x|construct_object }}",
    })  # fmt: skip
    usage = ast_scanner.scan(project)
    assert usage.template_names["full_load"] == ast_scanner.Location(
        path="templates/page.html", line=3
    )
    assert "construct_object" not in usage.template_names  # virtualenvs are skipped
    assert decide("A", "pyyaml", "1", record, usage).verdict == "UNKNOWN"


def test_an_unknown_import_name_is_never_not_imported(tmp_path: Path) -> None:
    unmapped = _record().model_copy(update={"package": "langgraph-checkpoint-sqlite",
                                            "import_roots": ()})  # fmt: skip
    usage = ast_scanner.scan(_write(tmp_path, {"a.py": "from langgraph.store import x\n"}))
    alert = decide("A", "langgraph-checkpoint-sqlite", "1", unmapped, usage)
    assert alert.verdict == "UNKNOWN"
    assert "import name of langgraph-checkpoint-sqlite is not known" in alert.reason
    known = _record().model_copy(update={"import_roots": ()})  # pyyaml -> yaml is known
    assert decide("A", "pyyaml", "1", known, usage).verdict == "NOT_IMPORTED"


def _as(package: str, *roots: str) -> db.Record:
    return _record().model_copy(update={"package": package, "import_roots": roots})


@pytest.mark.parametrize(
    ("name", "launches"),
    [
        ("Dockerfile", True), ("production.Dockerfile", True), ("Containerfile", True),
        ("Procfile", True), ("docker-compose.dev.yml", True), ("compose.yaml", True),
        ("bin/start.sh", True), ("Makefile", True), ("deploy/app.service", True),
        ("deploy/supervisord.conf", True), (".github/workflows/ci.yml", True),
        ("requirements.txt", False), ("pyproject.toml", False), ("poetry.lock", False),
        ("setup.cfg", False), ("tox.ini", False), ("docs/workflows/ci.yml", False),
        ("deploy/nginx.conf", False),
    ],
)  # fmt: skip
def test_which_files_start_processes(tmp_path: Path, name: str, launches: bool) -> None:
    path = _write(tmp_path, {name: "x\n"}) / name
    assert ast_scanner.is_launch_file(path) is launches


def test_an_extensionless_script_starts_processes_only_with_a_shebang(tmp_path: Path) -> None:
    root = _write(tmp_path, {"bin/docker-server": "#!/bin/bash\nexec gunicorn app.wsgi\n",
                             "bin/NOTES": "gunicorn is configured elsewhere\n"})  # fmt: skip
    assert ast_scanner.is_launch_file(root / "bin/docker-server")
    assert not ast_scanner.is_launch_file(root / "bin/NOTES")


def test_a_package_run_as_a_command_is_never_not_imported(tmp_path: Path) -> None:
    script = "#!/bin/bash\n# start\nexec gunicorn app.wsgi\n"
    root = _write(tmp_path, {"app/main.py": "import os\n", "bin/docker-server": script})
    alert = decide("A", "gunicorn", "20.1.0", _as("gunicorn", "gunicorn"), ast_scanner.scan(root))
    assert alert.verdict == "UNKNOWN"
    assert alert.reason.startswith("your project may run gunicorn as a command (bin/docker-server")
    assert [(e.path, e.line) for e in alert.evidence] == [("bin/docker-server", 3)]


@pytest.mark.parametrize(
    "line",
    ["CMD /venv/bin/gunicorn app.wsgi", "RUN pip install gunicorn==21.2.0",
     "COPY gunicorn.conf.py ./", "web: python -m gunicorn app:application"],
)  # fmt: skip
def test_the_forms_a_command_takes(tmp_path: Path, line: str) -> None:
    usage = ast_scanner.scan(_write(tmp_path, {"Dockerfile": f"FROM python\n{line}\n"}))
    assert usage.launched_as(("gunicorn",), "gunicorn") is not None


def test_an_import_name_counts_only_after_python_m(tmp_path: Path) -> None:
    root = _write(tmp_path / "a", {"Procfile": "release: python -m dotenv.cli run\n"})
    found = ast_scanner.scan(root).launched_as(("dotenv",), "python-dotenv")
    assert found is not None
    assert found[0] == "-m dotenv"
    # A bare import name is too often another word: the git binary, a compose dns: key.
    other = _write(tmp_path / "b", {"compose.yaml": "dns: 8.8.8.8\n", "Makefile": "git pull\n"})
    usage = ast_scanner.scan(other)
    assert usage.launched_as(("dns",), "dnspython") is None
    assert usage.launched_as(("git",), "gitpython") is None


def test_comments_and_other_cases_do_not_name_a_package(tmp_path: Path) -> None:
    dockerfile = "# we used to run gunicorn\nRUN apt-get install -y openssl\n"
    root = _write(tmp_path, {"app.py": "import os\n", "Dockerfile": dockerfile})
    usage = ast_scanner.scan(root)
    assert decide("A", "gunicorn", "1", _as("gunicorn", "gunicorn"), usage).verdict == (
        "NOT_IMPORTED"
    )
    # Import names are case-sensitive: the system library is not pyOpenSSL.
    assert decide("A", "pyopenssl", "1", _as("pyopenssl", "OpenSSL"), usage).verdict == (
        "NOT_IMPORTED"
    )


def test_a_distribution_name_in_a_launch_file_counts(tmp_path: Path) -> None:
    dockerfile = "RUN pip install python_dotenv\n"
    root = _write(tmp_path, {"app.py": "import os\n", "Dockerfile": dockerfile})
    alert = decide(
        "A", "python-dotenv", "1", _as("python-dotenv", "dotenv"), ast_scanner.scan(root)
    )
    assert alert.verdict == "UNKNOWN"


def test_a_package_run_as_a_command_is_never_imported_not_called(tmp_path: Path) -> None:
    code = {"app/main.py": "import yaml\nyaml.safe_load(s)\n"}
    usage = ast_scanner.scan(_write(tmp_path / "a", {**code, "Procfile": "w: python -m yaml\n"}))
    alert = decide("A", "pyyaml", "5.3.1", _record(), usage)  # high confidence, no reference
    assert alert.verdict == "UNKNOWN"
    assert "(Procfile names -m yaml)" in alert.reason
    called = ast_scanner.scan(
        _write(
            tmp_path / "b",
            {"app/main.py": "import yaml\nyaml.full_load(s)\n", "Procfile": "w: pyyaml\n"},
        )
    )
    assert decide("A", "pyyaml", "5.3.1", _record(), called).verdict == "CALLED"
    other = ast_scanner.scan(_write(tmp_path / "c", {**code, "Procfile": "w: yaml run\n"}))
    assert decide("A", "pyyaml", "5.3.1", _record(), other).verdict == "IMPORTED_NOT_CALLED"


# --- end to end ------------------------------------------------------------------------


def test_scan_cli_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _write(tmp_path / "project", {
        "requirements.txt": "PyYAML==5.3.1\nrequests==2.31.0\n",
        "app/config.py": "import yaml\n\ndef load(path):\n    return yaml.full_load(open(path))\n",
    })  # fmt: skip
    database = tmp_path / "db.sqlite"
    db.write(database, [_record()], {"CVE-2020-14343": "GHSA-0001-0001-0001"},
             {"db_version": "2026.11.15", "built_at": datetime.now(UTC).isoformat(),
              "builder": "test"})  # fmt: skip
    queried: list[tuple[str, str]] = []

    def fake_query(
        packages: list[tuple[str, str]], client: object = None
    ) -> dict[tuple[str, str], list[str]]:
        queried.extend(packages)
        return {p: (["CVE-2020-14343"] if p[0] == "pyyaml" else ["GHSA-unknown"]) for p in packages}

    monkeypatch.setattr(run.osv_client, "query", fake_query)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(project), "--db", str(database)])
    assert result.exit_code == 0, result.output
    assert "CALLED (fix first)  1" in result.output
    assert "app/config.py:4" in result.output
    assert "UNKNOWN" in result.output  # requests' advisory has no record
    assert sorted(queried) == [("pyyaml", "5.3.1"), ("requests", "2.31.0")]

    failing = runner.invoke(
        app, ["scan", str(project), "--db", str(database), "--fail-on", "called"]
    )
    assert failing.exit_code == 1
    as_json = runner.invoke(app, ["scan", str(project), "--db", str(database), "--format", "json"])
    verdicts = {a["package"]: a["verdict"] for a in json.loads(as_json.output)["alerts"]}
    assert verdicts == {"pyyaml": "CALLED", "requests": "UNKNOWN"}
    as_markdown = runner.invoke(
        app, ["scan", str(project), "--db", str(database), "--format", "markdown"]
    )
    assert as_markdown.exit_code == 0, as_markdown.output
    assert as_markdown.output.startswith("<!-- patchsight -->\n## PatchSight: 2 dependency alerts")
    assert "`app/config.py:4`" in as_markdown.output


def test_scan_cli_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    missing_lockfile = runner.invoke(app, ["scan", str(tmp_path)])
    assert missing_lockfile.exit_code == 2
    _write(tmp_path, {"requirements.txt": "x==1\n"})
    missing_db = runner.invoke(app, ["scan", str(tmp_path), "--db", str(tmp_path / "none.sqlite")])
    assert missing_db.exit_code == 2


def test_ids_of_one_vulnerability_become_one_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _write(
        tmp_path / "p", {"requirements.txt": "PyYAML==5.3.1\n", "a.py": "import yaml\n"}
    )
    database = tmp_path / "db.sqlite"
    db.write(database, [_record()],
             {"GHSA-0001-0001-0001": "GHSA-0001-0001-0001", "PYSEC-2021-1": "GHSA-0001-0001-0001"},
             {"built_at": datetime.now(UTC).isoformat()})  # fmt: skip
    ids = ["PYSEC-2021-1", "GHSA-0001-0001-0001", "GHSA-other"]
    monkeypatch.setattr(
        run.osv_client, "query", lambda packages, client=None: dict.fromkeys(packages, ids)
    )
    alerts, _, _ = run.run_scan(project, project / "requirements.txt", database)
    by_id = {a.advisory: a for a in alerts}
    assert set(by_id) == {"GHSA-0001-0001-0001", "GHSA-other"}
    assert by_id["GHSA-0001-0001-0001"].aliases == ("PYSEC-2021-1",)
    assert by_id["GHSA-other"].verdict == "UNKNOWN"
