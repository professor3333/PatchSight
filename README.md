# PatchSight

Symbol-level vulnerability triage for Python dependencies.

PatchSight will read the fix commit behind each PyPI security advisory, work out which functions actually carry the bug, and then check whether your code references them. The goal is to rank dependency alerts by call-site evidence, with no LLM call at scan time.

**Status: early development. Nothing is built or measured yet.** The full design is in [docs/proposal.md](docs/proposal.md).
