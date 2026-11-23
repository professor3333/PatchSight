#!/usr/bin/env bash
# Build a shadow database for a configuration change (shadow-then-promote, docs/architecture.md):
# every PyPI prompt replayed under the new configuration from the response cache, merged into a
# copy of the current release, gated, and compared with it. Publishes nothing.
#
#   scripts/prepare-shadow.sh <name> <config> <plan> [<purpose>]
#   scripts/prepare-shadow.sh cap-dotted configs/experiments/llm-cap-dotted.toml \
#     configs/experiments/llm-cap-dotted-topup.json
#
# <plan> is the change's topup-plan: the prompts it alters. Every one of them must already
# have its answer in the cache (its top-up run, imported); one without stops the script, so a
# shadow is never built from part of a change. A prompt the change leaves as it is keeps
# production's state, answered or not. Writes docs/reports/shadow-<name>.{md,json}: what
# changed, by field, and a seeded sample of changed records to review by hand.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  sed -n '2,14p' "$0"
  exit 2
fi
name=$1
config=$2
plan=$3
purpose=${4:-"the configuration $config"}
root=$(git rev-parse --show-toplevel)
pipeline=(uv run --project "$root" python -I -m patchsight.pipeline)
version="$(date -u +%Y.%m.%d)-shadow-$name"
out="data/interim/pypi-extract-shadow-$name"

outcomes=()
for k in 1 2 3 4; do
  echo "== PyPI shard $k/4 under $config, from the cache"
  "${pipeline[@]}" pypi-extract --role kaggle_extractor --config "$config" --offline \
    --cache-only --shard "$k/4" --out "$out" --root "$root"
  summary="$root/$out-kaggle_extractor-shard${k}of4-summary.json"
  # Prints the altered prompts without an answer (or why it cannot tell), then the unaltered
  # ones, which keep production's state.
  check=$(python3 -I -c 'import json, sys
summary, plan = (json.load(open(p)) for p in sys.argv[1:])
altered = {c["id"] for part in plan["parts"] if part["benchmark"] == "pypi" for c in part["changed"]}
named = summary.get("not_cached", [])
misses = summary["skipped"].get("cache_miss", 0)
if misses:
    print(f"{misses} HTTP cache misses")
elif summary["skipped"].get("not_cached", 0) != len(named):
    print("its summary does not name the prompts it could not answer")
elif set(named) & altered:
    print("no cached answer for " + " ".join(sorted(set(named) & altered)))
else:
    print("")
print(" ".join(sorted(set(named) - altered)))' "$summary" "$plan")
  gaps=$(sed -n 1p <<<"$check")
  kept=$(sed -n 2p <<<"$check")
  if [ -n "$gaps" ]; then
    echo "error: shard $k/4 under $config: $gaps; import the rest of the top-up" \
      "run first. No shadow built." >&2
    exit 1
  fi
  if [ -n "$kept" ]; then
    echo "note: never answered under any configuration, so production's record stays: $kept"
  fi
  outcomes+=("$root/$out-kaggle_extractor-shard${k}of4.jsonl")
done

echo "== The shadow database $version"
"$root/scripts/prepare-merged-release.sh" "$version" "${outcomes[@]}"

work="$root/data/build/release-$version"
echo "== Compared with the current release"
"${pipeline[@]}" db-diff "$work/cache/patchsight.sqlite" "$work/patchsight-$version.sqlite" \
  --name "$name" --purpose "$purpose" --root "$root"

cat <<NEXT

Shadow $version is in $work; nothing is published. Review the sample in
docs/reports/shadow-$name.md (patchsight explain <id> --db $work/patchsight-$version.sqlite),
and after a week of releases build it again on the latest one before promoting.
NEXT
