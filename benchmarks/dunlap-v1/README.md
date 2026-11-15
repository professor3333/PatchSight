# Dunlap Go benchmark bundle (v1)

`candidates.json` holds what `make reproduce` needs to recompute the benchmark tables offline,
without network access or API keys.

## Contents

For each of the 280 GoVulnDB reports in the benchmark:

- `symbols`: the ground-truth vulnerable symbols;
- `commits`: the fix commits (SHAs);
- `candidates`: every function, method and class those commits change, as file path, name and
  kind, under the paper's path rule (Go files whose path does not contain "test").

No source code is included. Candidates were produced by PatchSight's own pipeline: diffs fetched
from GitHub, then hunks mapped to definitions with tree-sitter.

## Sources and licences

- **Benchmark and ground truth:** Dunlap et al., "Pairing Security Advisories with Vulnerable
  Functions Using Open-Source LLMs", DIMVA 2024. Data released under Apache-2.0 at
  <https://github.com/s3c2/llm-vulnerable-functions>. The dataset commit and the SHA-256 of the
  CSV used are recorded in the bundle's `source` field.
- **Vulnerable symbols:** from the Go vulnerability database (CC BY 4.0), as included in that
  dataset (cloned 2023-10-26).
- **Candidate metadata:** derived by PatchSight from the public fix commits. Function names and
  paths only.

## Regenerating

```bash
python -m patchsight.pipeline fetch-dunlap
GITHUB_TOKEN=... python -m patchsight.pipeline export-dunlap-bundle
```
