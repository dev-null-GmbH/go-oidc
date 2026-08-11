#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
selector="$tool_root/scripts/select-repository-merge-settings.sh"
repository="dev-null-GmbH/go-oidc"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/bin"
write_fixture() {
  printf '%s\n' "$1" > "$test_root/graphql.json"
}

mock_gh='#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "api" || "${2:-}" != "graphql" ]]; then
  echo "unexpected gh invocation: $*" >&2
  exit 1
fi

query=""
owner=""
name=""
while (( $# > 0 )); do
  case "$1" in
    -f)
      if [[ "${2:-}" == query=* ]]; then
        query="${2#query=}"
      fi
      shift 2
      ;;
    -F)
      case "${2:-}" in
        owner=*) owner="${2#owner=}" ;;
        name=*) name="${2#name=}" ;;
      esac
      shift 2
      ;;
    *) shift ;;
  esac
done

if [[ "$owner" != "dev-null-GmbH" || "$name" != "go-oidc" ||
      "$query" != *"deleteBranchOnMerge"* ||
      "$query" != *"mergeCommitAllowed"* ||
      "$query" != *"rebaseMergeAllowed"* ||
      "$query" != *"squashMergeAllowed"* ]]; then
  echo "GraphQL request did not read the exact repository merge settings" >&2
  exit 1
fi

exec sed -n "1,\$p" "$MOCK_GRAPHQL_FIXTURE"
'
printf '%s' "$mock_gh" > "$test_root/bin/gh"
chmod +x "$test_root/bin/gh"

run_selector() {
  PATH="$test_root/bin:$PATH" MOCK_GRAPHQL_FIXTURE="$test_root/graphql.json" \
    "$selector" "$repository"
}

assert_rejected() {
  local label="$1"
  local response="$2"
  write_fixture "$response"
  if run_selector >"$test_root/out" 2>"$test_root/err"; then
    printf '%s unexpectedly passed\n' "$label" >&2
    exit 1
  fi
}

valid='{
  "data": {
    "repository": {
      "deleteBranchOnMerge": true,
      "mergeCommitAllowed": false,
      "rebaseMergeAllowed": false,
      "squashMergeAllowed": true
    }
  }
}'
write_fixture "$valid"
selected="$(run_selector)"
jq -e '
  . == {
    deleteBranchOnMerge: true,
    mergeCommitAllowed: false,
    rebaseMergeAllowed: false,
    squashMergeAllowed: true
  }
' <<< "$selected" >/dev/null

assert_rejected "GraphQL errors" '{"errors":[{"message":"denied"}],"data":null}'
assert_rejected "null repository" '{"data":{"repository":null}}'
assert_rejected "missing merge setting" \
  '{"data":{"repository":{"deleteBranchOnMerge":true,"mergeCommitAllowed":false,"squashMergeAllowed":true}}}'
assert_rejected "non-boolean merge setting" \
  '{"data":{"repository":{"deleteBranchOnMerge":true,"mergeCommitAllowed":false,"rebaseMergeAllowed":false,"squashMergeAllowed":"true"}}}'
assert_rejected "invalid repository" '{}'

echo "Repository merge settings use a complete read-only GraphQL snapshot"
