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

## LLM runs

Each `extraction-<tag>.json` is a replay bundle for one extraction run. For every report it holds:

- the candidates as the model saw them: ID, function name, path, and the hunk IDs each may cite;
- the model's raw answers, in order (`null` where the provider rejected an attempt).

`make reproduce` re-runs the live validator and attempt logic on those answers, and checks the
scores against `docs/reports/extraction-dunlap-{all,dev,test}-<tag>.json`. No prompts are
stored, because prompts contain the fix diffs.

| Tag | Model | Prompt | Where it ran |
|---|---|---|---|
| `extract-v1-qwen3.8-27b-q4km` | `ggml-org/Qwen3.8-27B-GGUF@c1869413` (Q4_K_M) | `extract-v1` | Kaggle, 2× T4, llama.cpp `b12024` (`docs/reports/kaggle-run-extract-v1-qwen3.8-27b-q4km.json`) |

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
GITHUB_TOKEN=... python -m patchsight.pipeline export-replay <tag>   # needs that run's response cache
```
