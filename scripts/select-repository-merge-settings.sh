#!/usr/bin/env bash

set -euo pipefail

repository="${1:?usage: select-repository-merge-settings.sh <repository>}"
api_version="2026-03-10"

if [[ ! "$repository" =~ ^[^/]+/[^/]+$ ]]; then
  printf 'Invalid GitHub repository: %s\n' "$repository" >&2
  exit 1
fi

owner="${repository%%/*}"
name="${repository#*/}"
query='query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    deleteBranchOnMerge
    mergeCommitAllowed
    rebaseMergeAllowed
    squashMergeAllowed
  }
}'

graphql="$(
  gh api graphql \
    -H "X-GitHub-Api-Version: $api_version" \
    -f query="$query" \
    -F owner="$owner" \
    -F name="$name"
)"

if ! jq -e '
  (has("errors") | not) and
  (.data.repository | type == "object") and
  (.data.repository.deleteBranchOnMerge | type == "boolean") and
  (.data.repository.mergeCommitAllowed | type == "boolean") and
  (.data.repository.rebaseMergeAllowed | type == "boolean") and
  (.data.repository.squashMergeAllowed | type == "boolean")
' <<< "$graphql" >/dev/null; then
  echo "Invalid or incomplete GraphQL repository merge-settings snapshot" >&2
  exit 1
fi

jq -c '.data.repository | {
  deleteBranchOnMerge,
  mergeCommitAllowed,
  rebaseMergeAllowed,
  squashMergeAllowed
}' <<< "$graphql"
