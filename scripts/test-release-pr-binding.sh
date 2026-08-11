#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
selector="$tool_root/scripts/select-release-pull-request.sh"
commit="1111111111111111111111111111111111111111"
other_commit="2222222222222222222222222222222222222222"
repository="dev-null-GmbH/go-oidc"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/bin"
cat > "$test_root/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "api" || "${2:-}" != "graphql" ]]; then
  echo "unexpected gh invocation: $*" >&2
  exit 1
fi

query=""
owner=""
name=""
oid=""
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
        oid=*) oid="${2#oid=}" ;;
      esac
      shift 2
      ;;
    *) shift ;;
  esac
done

if [[ "$owner" != "dev-null-GmbH" || "$name" != "go-oidc" ||
      "$oid" != "1111111111111111111111111111111111111111" ||
      "$query" != *'object(oid: $oid)'* ||
      "$query" != *'associatedPullRequests(first: 100)'* ]]; then
  echo "GraphQL request did not use the exact commit association snapshot" >&2
  exit 1
fi

exec sed -n '1,$p' "$MOCK_GRAPHQL_FIXTURE"
EOF
chmod +x "$test_root/bin/gh"

pull_request() {
  jq -n --arg commit "$commit" '{
    number: 17,
    url: "https://github.com/dev-null-GmbH/go-oidc/pull/17",
    state: "MERGED",
    merged: true,
    mergedAt: "2026-08-11T10:00:00Z",
    mergeCommit: {oid: $commit},
    author: {__typename: "User", login: "author", databaseId: 1},
    mergedBy: {__typename: "User", login: "merger", databaseId: 2},
    baseRefName: "main",
    baseRefOid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    headRefName: "codex/change",
    headRefOid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }'
}

graphql_response() {
  local nodes="$1"
  jq -n --arg oid "$commit" --argjson nodes "$nodes" '{
    data: {
      repository: {
        object: {
          __typename: "Commit",
          oid: $oid,
          associatedPullRequests: {
            totalCount: ($nodes | length),
            pageInfo: {hasNextPage: false},
            nodes: $nodes
          }
        }
      }
    }
  }'
}

run_selector() {
  PATH="$test_root/bin:$PATH" MOCK_GRAPHQL_FIXTURE="$test_root/graphql.json" \
    "$selector" "$repository" "$commit"
}

assert_rejected() {
  local label="$1"
  local response="$2"
  printf '%s\n' "$response" > "$test_root/graphql.json"
  if run_selector >"$test_root/out" 2>"$test_root/err"; then
    printf '%s unexpectedly passed\n' "$label" >&2
    exit 1
  fi
}

valid_pull="$(pull_request)"
valid_response="$(graphql_response "$(jq -n --argjson pull "$valid_pull" '[$pull]')")"
printf '%s\n' "$valid_response" > "$test_root/graphql.json"
selected="$(run_selector)"
jq -e --arg commit "$commit" '
  . == {
    number: 17,
    html_url: "https://github.com/dev-null-GmbH/go-oidc/pull/17",
    state: "closed",
    merged_at: "2026-08-11T10:00:00Z",
    merge_commit_sha: $commit,
    user: {login: "author", id: 1},
    merged_by: {login: "merger", id: 2},
    base: {ref: "main", sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    head: {ref: "codex/change", sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  }
' <<< "$selected" >/dev/null

wrong_pull="$(
  jq --arg oid "$other_commit" '
    .number = 18 |
    .url = "https://github.com/dev-null-GmbH/go-oidc/pull/18" |
    .mergeCommit.oid = $oid
  ' <<< "$valid_pull"
)"
mixed_response="$(
  graphql_response "$(jq -n --argjson valid "$valid_pull" --argjson wrong "$wrong_pull" '[$valid, $wrong]')"
)"
printf '%s\n' "$mixed_response" > "$test_root/graphql.json"
mixed_selected="$(run_selector)"
jq -e --arg commit "$commit" '
  .number == 17 and .merge_commit_sha == $commit
' <<< "$mixed_selected" >/dev/null

assert_rejected "wrong commit object oid" \
  "$(jq --arg oid "$other_commit" '.data.repository.object.oid = $oid' <<< "$valid_response")"
assert_rejected "null commit object oid" \
  "$(jq '.data.repository.object.oid = null' <<< "$valid_response")"
assert_rejected "non-Commit object" \
  "$(jq '.data.repository.object.__typename = "Tag"' <<< "$valid_response")"
assert_rejected "null repository" \
  "$(jq '.data.repository = null' <<< "$valid_response")"
assert_rejected "null object" \
  "$(jq '.data.repository.object = null' <<< "$valid_response")"
assert_rejected "GraphQL errors" \
  "$(jq '.errors = [{message: "denied"}]' <<< "$valid_response")"
assert_rejected "paginated associations" \
  "$(jq '.data.repository.object.associatedPullRequests.pageInfo.hasNextPage = true' <<< "$valid_response")"
assert_rejected "association count mismatch" \
  "$(jq '.data.repository.object.associatedPullRequests.totalCount = 2' <<< "$valid_response")"
assert_rejected "zero associated pull requests" \
  "$(graphql_response '[]')"
assert_rejected "multiple matching pull requests" \
  "$(graphql_response "$(jq -n --argjson pull "$valid_pull" '[$pull, ($pull | .number = 18 | .url = "https://github.com/dev-null-GmbH/go-oidc/pull/18")]')")"
assert_rejected "wrong merge commit" \
  "$(jq --arg oid "$other_commit" '.data.repository.object.associatedPullRequests.nodes[0].mergeCommit.oid = $oid' <<< "$valid_response")"
assert_rejected "null merge commit" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].mergeCommit = null' <<< "$valid_response")"
assert_rejected "wrong base" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].baseRefName = "develop"' <<< "$valid_response")"
assert_rejected "incomplete base oid" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].baseRefOid = null' <<< "$valid_response")"
assert_rejected "unmerged pull request" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].merged = false' <<< "$valid_response")"
assert_rejected "non-MERGED state" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].state = "CLOSED"' <<< "$valid_response")"
assert_rejected "missing mergedAt" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].mergedAt = null' <<< "$valid_response")"
assert_rejected "incomplete author" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].author.databaseId = null' <<< "$valid_response")"
assert_rejected "incomplete merger" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].mergedBy.__typename = "Bot"' <<< "$valid_response")"
assert_rejected "incomplete head ref" \
  "$(jq '.data.repository.object.associatedPullRequests.nodes[0].headRefOid = null' <<< "$valid_response")"

echo "Release PR binding requires one complete GraphQL commit association"
