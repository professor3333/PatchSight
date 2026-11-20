# ADR 0012: A package the project runs as a command is never "not imported"

- **Status:** accepted
- **Date:** 2026-11-20

## Context

`NOT_IMPORTED` meant "no Python file in the project imports the package". The terminal labels it "transitive only". That label is wrong for a package the project *runs*:

- posthog's `bin/docker-server` runs `exec gunicorn posthog.wsgi`. gunicorn serves every request, and its request-smuggling advisories apply in full. No Python file imports it, so both of its alerts on the [repository panel](../reports/panel-db-2026.11.19.md) were `NOT_IMPORTED`.
- open-webui's CI installs and runs `black`. Its three alerts were `NOT_IMPORTED` too.

A wrong "not imported" invites someone to deprioritise exactly the alert that matters. Design rule 3 says to fail towards noise.

## Decision

The scanner also reads the files that start processes: Dockerfiles and Containerfiles, Procfiles, Compose files, shell scripts and other scripts with a shebang, Makefiles and justfiles, systemd and supervisor units, and CI workflows. It skips comment lines.

A package is **named** there when:

- a word is its distribution name, normalised (`gunicorn`, `pip install python_dotenv`, `/venv/bin/gunicorn`, `gunicorn.conf.py`); or
- `python -m` runs one of its import names (`python -m dotenv`).

A bare import name does not count. On the panel, matching import names gave wrong reasons: `git` (the git binary, not GitPython), `dns` (a Compose key, not dnspython), `py` (pytest), and `tests` (a stray top-level package in Authlib's wheel).

A named package gets:

- `UNKNOWN` instead of `NOT_IMPORTED`;
- never `IMPORTED_NOT_CALLED`, because the command runs its code without any reference;
- the file and line as evidence.

A reference to a vulnerable symbol still gives `CALLED`.

Lockfiles, requirements files, `setup.cfg`, `tox.ini` and `pyproject.toml` are not read for this. They name every dependency, so they say nothing about what is run.

## Measured

On the 20-project panel, against the same database (`db-2026.11.19`), before and after this change:

| | Before | After |
|---|---:|---:|
| `CALLED` | 182 | 182 |
| `NOT_IMPORTED` | 178 | 173 |
| `UNKNOWN` | 3,219 | 3,224 |
| `UNKNOWN` because the project runs the package | — | 49 alerts, 7 projects |

- **The 5 alerts that leave `NOT_IMPORTED`** are posthog's gunicorn (2) and open-webui's black (3).
- **The other 44 were already `UNKNOWN`** for another reason, such as a computed import or low confidence, and now give the more specific one. The packages are: gunicorn in ctfd's entrypoint, pymysql, wheel and pytest in CI workflows, setuptools in warehouse's Dockerfile, sentence-transformers, brotli, django and requests.
- **Cost:** the extra pass takes 0 to 0.06 s on posthog, saleor and zulip. That is the median of 6 scans each, with the pass switched on and then off.

## Consequences

- **Some matches are the same word for something else.** posthog's devcontainer installs the system `brotli` tool, not the Python binding. Such matches only withhold "not imported" or "not called", which is the direction rule 3 allows.
- **A command whose name differs from its distribution is missed,** for example `aws` from `awscli` or `http` from `httpie`. Those alerts keep today's behaviour. Wheel metadata (`entry_points.txt`) lists each package's console scripts and could close this gap. It would need an additive DB table, as [ADR 0009](0009-import-names-from-wheels.md) did for import names. Measured on 2026-11-20, before building it: of the 35 package-and-project pairs still `NOT_IMPORTED` on the panel, 11 packages ship console scripts, and 6 of those have one whose name differs from the distribution (`pygmentize`, `markdown_py`, `mako-render`, `pyreverse`, `blackd`, `dotenv`). None appears in any project's launch files. It would change no verdict there, so it is not built yet.
- **`NOT_IMPORTED` still does not mean safe.** It now says that no Python file imports the package and no launch file names it. Transitive use is still not analysed.
- **The repository panel** fetches these files, so later panel reports measure the rule. The panel fetches extensionless scripts from `bin/` and `scripts/` only, while the scanner reads them anywhere.
- **Computed imports were measured and left alone.** Narrowing the rule for `import_module(f"pkg.{x}")` was considered. Of 87 computed imports on the panel, 77 take a plain variable, usually a settings value. Only 5 have a static prefix, and every project with one also has the variable kind. Narrowing would unblock no project, so a computed import still blocks `NOT_IMPORTED` everywhere.
