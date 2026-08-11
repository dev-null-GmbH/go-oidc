#!/usr/bin/env bash

set -euo pipefail

repository="${GITHUB_REPOSITORY:-dev-null-GmbH/go-oidc}"
commit="${1:?usage: verify-release-checks.sh <commit> [evidence-output]}"
evidence_output="${2:-}"
api_version="2026-03-10"
readonly actions_app_id=15368
readonly actions_app_slug="github-actions"

if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Release commit must be a full SHA: %s\n' "$commit" >&2
  exit 1
fi
if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "GH_TOKEN is required to verify release checks" >&2
  exit 1
fi

api() {
  gh api -H "X-GitHub-Api-Version: $api_version" "$@"
}

api_pages() {
  api --paginate --slurp "$1"
}

check_runs_for_commit() {
  api_pages \
    "repos/$repository/commits/$1/check-runs?filter=latest&per_page=100" |
    jq '[.[]?.check_runs[]?]'
}

trusted_check() {
  local checks_json="$1"
  local expected_name="$2"
  local expected_sha="$3"
  local expected_workflow="$4"
  local expected_event="$5"
  local expected_branch="${6:-}"
  local candidate details_url run_suffix run_id run_json

  while IFS= read -r candidate; do
    details_url="$(jq -r .details_url <<< "$candidate")"
    if [[ "$details_url" != \
      "https://github.com/$repository/actions/runs/"* ]]; then
      continue
    fi
    run_suffix="${details_url#"https://github.com/$repository/actions/runs/"}"
    run_id="${run_suffix%%/*}"
    if [[ ! "$run_id" =~ ^[1-9][0-9]*$ ]]; then
      continue
    fi

    run_json="$(api "repos/$repository/actions/runs/$run_id")"
    if ! jq -e \
      --arg path "$expected_workflow" \
      --arg event "$expected_event" \
      --arg sha "$expected_sha" \
      --arg branch "$expected_branch" '
        .path == $path and .event == $event and .head_sha == $sha and
        .status == "completed" and .conclusion == "success" and
        ($branch == "" or .head_branch == $branch)
      ' <<< "$run_json" >/dev/null; then
      continue
    fi

    jq -n \
      --argjson check "$candidate" \
      --argjson workflow "$run_json" '
      {
        id: $check.id,
        name: $check.name,
        headSha: $check.head_sha,
        status: $check.status,
        conclusion: $check.conclusion,
        detailsUrl: $check.details_url,
        app: {
          id: $check.app.id,
          slug: $check.app.slug
        },
        workflow: {
          id: $workflow.id,
          path: $workflow.path,
          event: $workflow.event,
          headBranch: $workflow.head_branch,
          headSha: $workflow.head_sha,
          runAttempt: $workflow.run_attempt,
          status: $workflow.status,
          conclusion: $workflow.conclusion,
          htmlUrl: $workflow.html_url,
          createdAt: $workflow.created_at,
          updatedAt: $workflow.updated_at
        }
      }'
    return 0
  done < <(
    jq -c \
      --arg name "$expected_name" \
      --arg sha "$expected_sha" \
      --argjson app_id "$actions_app_id" \
      --arg app_slug "$actions_app_slug" '
      map(select(
        .name == $name and .head_sha == $sha and
        .status == "completed" and .conclusion == "success" and
        .app.id == $app_id and .app.slug == $app_slug
      )) | sort_by(.id) | reverse[]
    ' <<< "$checks_json"
  )

  printf 'No trusted successful check found: %s (%s)\n' \
    "$expected_name" "$expected_workflow" >&2
  return 1
}

release_commit_json="$(api "repos/$repository/commits/$commit")"
if ! jq -e --arg commit "$commit" '
  .sha == $commit and .commit.verification.verified == true and
  .commit.verification.reason == "valid"
' <<< "$release_commit_json" >/dev/null; then
  echo "Release commit is not GitHub-verified with a valid signature" >&2
  exit 1
fi
commit_verification="$(
  jq '{
    sha,
    htmlUrl: .html_url,
    author: {login: .author.login, id: .author.id},
    committer: {login: .committer.login, id: .committer.id},
    verification: {
      verified: .commit.verification.verified,
      reason: .commit.verification.reason,
      verifiedAt: .commit.verification.verified_at
    }
  }' <<< "$release_commit_json"
)"

release_checks="$(check_runs_for_commit "$commit")"
check_specs=(
  $'Go quality gates\t.github/workflows/ci.yml'
  $'Nested VCI module\t.github/workflows/ci.yml'
  $'All conformance profiles passed\t.github/workflows/conformance.yml'
  $'Go vulnerability analysis\t.github/workflows/security.yml'
  $'Nested VCI vulnerability analysis\t.github/workflows/security.yml'
  $'Analyze Go\t.github/workflows/codeql.yml'
)
required_checks=()
for specification in "${check_specs[@]}"; do
  IFS=$'\t' read -r check_name workflow_path <<< "$specification"
  required_checks+=("$(
    trusted_check "$release_checks" "$check_name" "$commit" \
      "$workflow_path" push main
  )")
done
required_checks_json="$(printf '%s\n' "${required_checks[@]}" | jq -s 'sort_by(.name)')"

pull_request="$(
  "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/select-release-pull-request.sh" \
    "$repository" "$commit"
)"

pull_head_sha="$(jq -r .head.sha <<< "$pull_request")"
pull_head_commit_json="$(api "repos/$repository/commits/$pull_head_sha")"
if ! jq -e --arg head "$pull_head_sha" '
  .sha == $head and .commit.verification.verified == true and
  .commit.verification.reason == "valid"
' <<< "$pull_head_commit_json" >/dev/null; then
  echo "Release pull-request head is not GitHub-verified and signed" >&2
  exit 1
fi
pull_head_verification="$(
  jq '{
    sha,
    htmlUrl: .html_url,
    author: {login: .author.login, id: .author.id},
    verification: {
      verified: .commit.verification.verified,
      reason: .commit.verification.reason,
      verifiedAt: .commit.verification.verified_at
    }
  }' <<< "$pull_head_commit_json"
)"
pull_checks="$(check_runs_for_commit "$pull_head_sha")"
dependency_review="$(
  trusted_check "$pull_checks" "Dependency review" "$pull_head_sha" \
    ".github/workflows/security.yml" pull_request
)"

pull_request_evidence="$(
  jq -n \
    --argjson pull "$pull_request" \
    --argjson head_verification "$pull_head_verification" \
    --argjson dependency "$dependency_review" '
    {
      number: $pull.number,
      htmlUrl: $pull.html_url,
      state: $pull.state,
      mergedAt: $pull.merged_at,
      mergeCommitSha: $pull.merge_commit_sha,
      author: {login: $pull.user.login, id: $pull.user.id},
      mergedBy: {login: $pull.merged_by.login, id: $pull.merged_by.id},
      base: {ref: $pull.base.ref, sha: $pull.base.sha},
      head: {ref: $pull.head.ref, sha: $pull.head.sha},
      headVerification: $head_verification,
      reviewPolicy: {
        mode: "solo-maintainer-signed-head-and-required-checks",
        requiredApprovalCount: 0
      },
      dependencyReview: $dependency
    }'
)"

conformance_check="$(
  jq '.[] | select(.name == "All conformance profiles passed")' \
    <<< "$required_checks_json"
)"
conformance_run_id="$(jq -r .workflow.id <<< "$conformance_check")"
conformance_jobs="$(
  api_pages "repos/$repository/actions/runs/$conformance_run_id/jobs?filter=latest&per_page=100" |
    jq '[.[]?.jobs[]?]'
)"
conformance_artifacts="$(
  api_pages "repos/$repository/actions/runs/$conformance_run_id/artifacts?per_page=100" |
    jq '[.[]?.artifacts[]?]'
)"

profiles=(
  oidc
  fapi2-sp-op-mtls-mtls
  fapi2-sp-op-mtls-dpop
  fapi2-sp-op-private-key-mtls
  fapi2-ms-op-jar
  fapi2-ms-op-jarm
  fapi2-sp-op-private-key-dpop
  fapi1-op-mtls
  fapi1-op-mtls-jarm
  fapi1-op-mtls-par
  fapi1-op-mtls-par-jarm
  fapi1-op-private-key
  fapi1-op-private-key-jarm
  fapi1-op-private-key-par
  fapi1-op-private-key-par-jarm
  fapiciba
  federation
)
profile_evidence=()
for profile in "${profiles[@]}"; do
  job="$(
    jq -c --arg profile "$profile" '
      map(select(
        .name == $profile and .status == "completed" and
        .conclusion == "success"
      )) | sort_by(.id) | last // empty
    ' <<< "$conformance_jobs"
  )"
  artifact_name="conformance-$profile-$conformance_run_id"
  artifact="$(
    jq -c \
      --arg name "$artifact_name" \
      --arg commit "$commit" '
      map(select(
        .name == $name and .expired == false and
        .workflow_run.head_sha == $commit and
        ((.digest // "") | test("^sha256:[0-9a-f]{64}$"))
      )) | sort_by(.id) | last // empty
    ' <<< "$conformance_artifacts"
  )"
  if [[ -z "$job" || -z "$artifact" ]]; then
    printf 'Conformance evidence is incomplete for profile %s\n' \
      "$profile" >&2
    exit 1
  fi

  profile_evidence+=("$(
    jq -n \
      --arg profile "$profile" \
      --argjson job "$job" \
      --argjson artifact "$artifact" '
      {
        profile: $profile,
        job: {
          id: $job.id,
          name: $job.name,
          status: $job.status,
          conclusion: $job.conclusion,
          htmlUrl: $job.html_url,
          startedAt: $job.started_at,
          completedAt: $job.completed_at
        },
        artifact: {
          id: $artifact.id,
          name: $artifact.name,
          sizeInBytes: $artifact.size_in_bytes,
          digest: $artifact.digest,
          expired: $artifact.expired,
          createdAt: $artifact.created_at,
          expiresAt: $artifact.expires_at,
          archiveDownloadUrl: $artifact.archive_download_url,
          headSha: $artifact.workflow_run.head_sha
        }
      }'
  )")
done
profile_evidence_json="$(
  printf '%s\n' "${profile_evidence[@]}" | jq -s 'sort_by(.profile)'
)"

evidence="$(
  jq -n \
    --arg repository "$repository" \
    --arg commit "$commit" \
    --argjson verification "$commit_verification" \
    --argjson checks "$required_checks_json" \
    --argjson pull "$pull_request_evidence" \
    --argjson conformance_check "$conformance_check" \
    --argjson profiles "$profile_evidence_json" '
    {
      schemaVersion: 2,
      repository: $repository,
      releaseCommit: $commit,
      commitVerification: $verification,
      requiredChecks: $checks,
      pullRequestEvidence: $pull,
      conformance: {
        aggregateCheck: $conformance_check,
        profiles: $profiles
      }
    }'
)"

if [[ -n "$evidence_output" ]]; then
  mkdir -p "$(dirname "$evidence_output")"
  jq --sort-keys . <<< "$evidence" > "$evidence_output"
  "$(
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
  )/verify-release-evidence.sh" "$evidence_output" "$commit"
fi

printf 'All trusted checks, reviewed PR evidence, and conformance artifacts verified for %s\n' \
  "$commit"
