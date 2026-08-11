#!/usr/bin/env bash

set -euo pipefail

repository="${1:?usage: select-release-pull-request.sh <repository> <commit>}"
commit="${2:?usage: select-release-pull-request.sh <repository> <commit>}"
api_version="2026-03-10"

if [[ ! "$repository" =~ ^[^/]+/[^/]+$ ]]; then
  printf 'Invalid GitHub repository: %s\n' "$repository" >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Release commit must be a full SHA: %s\n' "$commit" >&2
  exit 1
fi

owner="${repository%%/*}"
name="${repository#*/}"
query='query($owner: String!, $name: String!, $oid: GitObjectID!) {
  repository(owner: $owner, name: $name) {
    object(oid: $oid) {
      __typename
      oid
      ... on Commit {
        associatedPullRequests(first: 100) {
          totalCount
          pageInfo { hasNextPage }
          nodes {
            number
            url
            state
            merged
            mergedAt
            mergeCommit { oid }
            author {
              __typename
              login
              ... on User { databaseId }
            }
            mergedBy {
              __typename
              login
              ... on User { databaseId }
            }
            baseRefName
            baseRefOid
            headRefName
            headRefOid
          }
        }
      }
    }
  }
}'

graphql="$(
  gh api graphql \
    -H "X-GitHub-Api-Version: $api_version" \
    -f query="$query" \
    -F owner="$owner" \
    -F name="$name" \
    -F oid="$commit"
)"

if ! jq -e --arg commit "$commit" '
  def nonnegative_int:
    type == "number" and floor == . and . >= 0;

  (has("errors") | not) and
  (.data.repository.object as $object |
    $object.__typename == "Commit" and
    $object.oid == $commit and
    ($object.associatedPullRequests as $pulls |
      ($pulls.totalCount | nonnegative_int) and
      $pulls.totalCount <= 100 and
      $pulls.pageInfo.hasNextPage == false and
      ($pulls.nodes | type == "array") and
      ($pulls.nodes | length) == $pulls.totalCount
    )
  )
' <<< "$graphql" >/dev/null; then
  echo "Invalid or incomplete GraphQL commit association snapshot" >&2
  exit 1
fi

matches="$(
  jq -c --arg commit "$commit" --arg repository "$repository" '
    def positive_int:
      type == "number" and floor == . and . > 0;
    def nonempty_string:
      type == "string" and length > 0;
    def full_sha:
      type == "string" and test("^[0-9a-f]{40}$");

    [
      .data.repository.object.associatedPullRequests.nodes[] |
      select(
        (.number | positive_int) and
        .url == (
          "https://github.com/" + $repository + "/pull/" +
          (.number | tostring)
        ) and
        .state == "MERGED" and
        .merged == true and
        (.mergedAt | nonempty_string) and
        .mergeCommit.oid == $commit and
        .author.__typename == "User" and
        (.author.login | nonempty_string) and
        (.author.databaseId | positive_int) and
        .mergedBy.__typename == "User" and
        (.mergedBy.login | nonempty_string) and
        (.mergedBy.databaseId | positive_int) and
        .baseRefName == "main" and
        (.baseRefOid | full_sha) and
        (.headRefName | nonempty_string) and
        (.headRefOid | full_sha)
      )
    ]
  ' <<< "$graphql"
)"

match_count="$(jq 'length' <<< "$matches")"
if [[ "$match_count" != "1" ]]; then
  printf 'Expected exactly one complete merged-main PR association for %s; found %s\n' \
    "$commit" "$match_count" >&2
  exit 1
fi

jq -c --arg commit "$commit" '
  .[0] | {
    number,
    html_url: .url,
    state: "closed",
    merged_at: .mergedAt,
    merge_commit_sha: $commit,
    user: {
      login: .author.login,
      id: .author.databaseId
    },
    merged_by: {
      login: .mergedBy.login,
      id: .mergedBy.databaseId
    },
    base: {
      ref: .baseRefName,
      sha: .baseRefOid
    },
    head: {
      ref: .headRefName,
      sha: .headRefOid
    }
  }
' <<< "$matches"
