# Release gate rehearsal: a deliberately bad build is blocked

- **Date:** 2026-11-18
- **Gate:** `gate-db` at PatchSight commit `57ff5b7` (`src/patchsight/pipeline/gate.py`)
- **Previous release:** `db-2026.11.17`, downloaded through the public pointer
- **Candidate:** a copy of `db-2026.11.17.1`, which had passed the gate and been published, with three faults added on purpose

## The faults

| Fault | What a real cause could be | Check that should catch it |
|---|---|---|
| Every record of 100 vulnerabilities removed, with their aliases | a truncated snapshot or a broken builder | `no_mass_loss` (at most 70 of 3,525 may go at once) |
| One record left with no symbols | a mapping bug | `symbols` |
| An alias pointing at a vulnerability with no record | an alias-grouping bug | `aliases` |

They were made with this script, run on a copy:

```python
import shutil, sqlite3, sys

source, target = sys.argv[1], sys.argv[2]
shutil.copyfile(source, target)
c = sqlite3.connect(target)
lost = [v for (v,) in c.execute("SELECT DISTINCT vulnerability FROM records ORDER BY 1 LIMIT 100")]
for table in ("symbols", "evidence", "extraction", "records"):
    c.executemany(f"DELETE FROM {table} WHERE vulnerability = ?", [(v,) for v in lost])
c.executemany("DELETE FROM aliases WHERE vulnerability = ?", [(v,) for v in lost])
(empty,) = c.execute("SELECT vulnerability FROM records ORDER BY 1 DESC LIMIT 1").fetchone()
c.execute("DELETE FROM symbols WHERE vulnerability = ?", (empty,))
c.execute("INSERT INTO aliases VALUES ('CVE-0000-00000', 'GHSA-none-none-none')")
c.execute("UPDATE meta SET value = 'rehearsal-bad' WHERE key = 'db_version'")
c.commit()
```

## Result

```bash
python -m patchsight.pipeline gate-db bad.sqlite --previous patchsight-db-2026.11.17.sqlite
```

The command exited with status **1**, and the report read:

| Check | Result | Detail |
|---|---|---|
| `ledger` | pass | 4820 entries |
| `symbols` | **FAIL** | 3584 records; outside 1 to 500 symbols: PYSEC-2026-4324/vllm (0) |
| `aliases` | **FAIL** | 10332 identifiers; aliases without a record: CVE-0000-00000 |
| `no_mass_loss` | **FAIL** | 100 of 3525 vulnerabilities lost their records (at most 70 allowed): GHSA-227r-w5j2-6243, GHSA-22c2-9gwg-mj59, GHSA-22fp-mf44-f2mq, GHSA-22hf-vx2v-gjff, GHSA-22hg-r758-rrw9, GHSA-22jm-4hxw-35jf, GHSA-22jr-vc7j-g762, GHSA-22m3-c7vp-49fj, GHSA-22p3-qrh9-cx32, GHSA-22p9-r2f5-22mf and 90 more |
| `high_kept` | pass | unchanged high-confidence records stay high |

Each fault was caught by the check meant for it, and each failure names the records involved.

## What the nightly does with this

In [`nightly.yml`](../../.github/workflows/nightly.yml) the gate is its own step. Exit status 1 fails the job, so the packaging, release and pointer steps are skipped: no release is created and `latest.json` keeps naming the previous release. The last step then opens an issue labelled `nightly` that holds this report.

## Not exercised here

- **`high_kept`:** no published record is high confidence yet, so it has nothing to check on real data. Unit tests cover it (`tests/test_gate.py`).
- **`ledger`:** the faults removed records, not ledger entries. Unit tests cover a missing ledger.
- **The issue step** has not run for real yet, because no nightly has failed.
