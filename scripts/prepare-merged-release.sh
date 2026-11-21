#!/usr/bin/env bash
# Prepare a database release that merges new LLM extractions into the current release:
# every step up to publishing, in the order that keeps the data whole. It stops at the
# first failure, and publishes nothing: it prints the two commands that would.
#
#   scripts/prepare-merged-release.sh <version> <pypi-extract outcomes>...
#   scripts/prepare-merged-release.sh 2026.11.21.1 data/interim/pypi-extract-kaggle_extractor-shard{1,2,3,4}of4.jsonl
#
# Steps: download the current release as users get it (SHA-256 checked); merge-llm into a
# new version; import-names again, because a merge writes the records without that table
# (the wheel cache answers, so no network is needed); the release gate against the current
# release; package-db; release-notes with the merge and gate reports.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  sed -n '2,8p' "$0"
  exit 2
fi
version=$1
shift
root=$(git rev-parse --show-toplevel)
work="$root/data/build/release-$version"
if [ -e "$work" ]; then
  echo "error: $work exists; choose a new version or remove it" >&2
  exit 2
fi
mkdir -p "$work/cache"
pipeline=(uv run --project "$root" python -I -m patchsight.pipeline)
outcomes=()
for path in "$@"; do
  outcomes+=(--llm "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")")
done

echo "== The current release"
PATCHSIGHT_CACHE="$work/cache" uv run --project "$root" patchsight db update
base="$work/cache/patchsight.sqlite"
PATCHSIGHT_CACHE="$work/cache" uv run --project "$root" patchsight db info

echo "== Merge into $version"
"${pipeline[@]}" merge-llm "$base" --version "$version" "${outcomes[@]}" \
  --out "$work/patchsight-$version" --root "$root"
candidate="$work/patchsight-$version.sqlite"

echo "== Import names"
"${pipeline[@]}" import-names "$candidate" --root "$root"

echo "== Release gate"
"${pipeline[@]}" gate-db "$candidate" --previous "$base" --out "$work/gate-$version" --root "$root"

echo "== Package"
"${pipeline[@]}" package-db "$candidate" --pointer "$work/latest.json" --root "$root"

echo "== Release notes"
"${pipeline[@]}" release-notes "$candidate" --pointer "$work/latest.json" \
  --merge "$work/patchsight-$version-merge.json" --gate "$work/gate-$version.json" \
  --out "$work/notes.md" --root "$root"

asset="data/build/release/patchsight-db-$version.sqlite.gz"
cat <<NEXT

Prepared in $work. Nothing is published. Read notes.md and the gate report, then:
  gh release create db-$version $asset --latest=false --title "Symbol database $version" --notes-file $work/notes.md
  and commit $work/latest.json as latest.json on the db-pointer branch.
NEXT
