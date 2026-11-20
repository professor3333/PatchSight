#!/usr/bin/env bash
# Post PatchSight's markdown report on a pull request, or update the comment it posted
# before. action.yml calls it with GH_TOKEN, REPOSITORY, NUMBER and REPORT set.
#
# Failing to comment is a warning, never a failed job: a pull request from a fork gets a
# read-only token, and the scan itself has already succeeded.
set -uo pipefail

marker='<!-- patchsight -->'

warn() {
  echo "::warning::PatchSight could not $1 its pull-request comment. The job needs" \
    "'pull-requests: write'; a pull request from a fork gets a read-only token."
  exit 0
}

if [[ ! "$NUMBER" =~ ^[0-9]+$ ]] || [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::warning::PatchSight comments on pull requests only; nothing posted"
  exit 0
fi
if [ ! -s "$REPORT" ] || [ "$(head -n 1 "$REPORT")" != "$marker" ]; then
  echo "::warning::PatchSight's markdown report is missing; nothing posted"
  exit 0
fi

# Its own earlier comment: posted by a bot, starting with the marker.
existing=$(gh api "repos/$REPOSITORY/issues/$NUMBER/comments" --paginate \
  --jq '.[] | select(.user.type == "Bot" and (.body | startswith("<!-- patchsight -->"))) | .id' \
  | head -n 1) || warn "read"

if [ -n "$existing" ]; then
  gh api --method PATCH "repos/$REPOSITORY/issues/comments/$existing" -F "body=@$REPORT" \
    > /dev/null || warn "update"
  echo "Updated the pull-request comment ($existing)."
else
  gh api "repos/$REPOSITORY/issues/$NUMBER/comments" -F "body=@$REPORT" > /dev/null || warn "post"
  echo "Posted a pull-request comment."
fi
