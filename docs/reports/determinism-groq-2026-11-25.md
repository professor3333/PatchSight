# Groq run-to-run determinism, 2026-11-25

A recorded measurement for [E13](../experiments.md#e13-run-to-run-determinism-of-hosted-extraction).

**What was compared:**
- **Night:** the 2026-11-24 nightly's answers ([run](https://github.com/professor3333/PatchSight/actions/runs/45405184914)), kept in its artifact and imported by `fetch-nightly`.
- **Morning:** the same vulnerabilities asked again on 2026-11-25, around 04:40 UTC, from an empty response cache.
- **Both:** model `qwen/qwen3.8-27b` on Groq, prompt `extract-v1`, role `extractor`, temperature 0, seed 20261114.

A request has the **same prompt** when its cache key, a hash of the whole request, is the night's.
An answer is **identical** when its text is byte-for-byte the same.
The **decisions** are the vulnerable symbols, the entry points and each symbol's cited hunks.

| Vulnerability | Outcome | Requests | Same prompt | Identical answers | Same decisions |
|---|---|---:|---|---:|---|
| `GHSA-394h-qwmc-48pf` | ok | 1 | yes | 0 of 1 | yes |
| `GHSA-43mp-35q3-x3fq` | ok | 1 | yes | 1 of 1 | yes |
| `GHSA-558c-9hv2-4prj` | ok | 1 | yes | 0 of 1 | yes |
| `GHSA-c978-59m8-c77v` | repaired | 2 | yes | 2 of 2 | yes |
| `GHSA-cx28-75q4-x26q` | repaired | 2 | yes | 2 of 2 | yes |

**Total:** 7 requests, all with the night's prompt; **5 of 7 answers identical**; decisions identical in 5 of 5 vulnerabilities. The answers that differ reword a rationale.
