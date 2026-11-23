#!/usr/bin/env bash
# Build a shadow database for a configuration change (shadow-then-promote, docs/architecture.md):
# every PyPI prompt replayed under the new configuration from the response cache, merged into a
# copy of the current release, gated, and compared with it. Publishes nothing.
#
#   scripts/prepare-shadow.sh <name> <config> [<purpose>]
#   scripts/prepare-shadow.sh switch-on configs/experiments/llm-switch-on.toml
#
# Every prompt the change alters must already have its answer in the cache (its top-up run,
# imported). A prompt without one stops the script, so a shadow is never built from part of
# a change. Writes docs/reports/shadow-<name>.{md,json}: what changed, by field, and a seeded
# sample of changed records to review by hand.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  sed -n '2,12p' "$0"
  exit 2
fi
name=$1
config=$2
purpose=${3:-"the configuration $config"}
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
  missing=$(python3 -I -c 'import json, sys
skipped = json.load(open(sys.argv[1]))["skipped"]
print(skipped.get("not_cached", 0) + skipped.get("cache_miss", 0))' "$summary")
  if [ "$missing" -ne 0 ]; then
    echo "error: $missing prompts of shard $k/4 have no cached answer under $config;" \
      "import the rest of the top-up run first. No shadow built." >&2
    exit 1
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
