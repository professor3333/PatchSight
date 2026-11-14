# PatchSight

Symbol-level vulnerability triage for Python dependencies.

PatchSight will read the fix commit behind each PyPI security advisory, work out which functions actually carry the bug, and then check whether your code references them. The goal is to rank dependency alerts by call-site evidence, with no LLM call at scan time.

**Status: early development.** The ingestion pipeline exists; extraction and scanning do not yet. The full design is in [docs/proposal.md](docs/proposal.md). The first measurements are in the [Week 1 data report](docs/reports/week1-data-gate.md): of 7,105 PyPI vulnerabilities, 2 carry upstream data on which functions are vulnerable.

## Licence

- **Code:** Apache License 2.0. See [LICENSE](LICENSE).
- **Advisory data:** PatchSight processes advisory data from [OSV.dev](https://osv.dev), the [GitHub Advisory Database](https://github.com/github/advisory-database) and the [PyPA Advisory Database](https://github.com/pypa/advisory-database), all under CC BY 4.0.
- **Published datasets:** any dataset PatchSight publishes credits those sources and states what was changed.
- **Third-party source code:** never redistributed. Only commit SHAs, file paths, line ranges and symbol names are stored.
