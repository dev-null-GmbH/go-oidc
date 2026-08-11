#!/usr/bin/env bash

set -euo pipefail

evidence_file="${1:?usage: verify-release-evidence.sh <evidence-json> <commit>}"
expected_commit="${2:?usage: verify-release-evidence.sh <evidence-json> <commit>}"

if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ || ! -s "$evidence_file" ]]; then
  echo "Invalid release evidence input" >&2
  exit 1
fi

jq -e --arg commit "$expected_commit" '
  def successful_actions_check($sha; $path; $event):
    .headSha == $sha and .status == "completed" and
    .conclusion == "success" and .app.id == 15368 and
    .app.slug == "github-actions" and
    .workflow.path == $path and .workflow.event == $event and
    .workflow.headSha == $sha and .workflow.status == "completed" and
    .workflow.conclusion == "success";

  . as $root |
  .schemaVersion == 2 and
  .repository == "dev-null-GmbH/go-oidc" and
  .releaseCommit == $commit and
  .commitVerification.sha == $commit and
  .commitVerification.verification.verified == true and
  .commitVerification.verification.reason == "valid" and

  (.requiredChecks | length) == 6 and
  ([.requiredChecks[].name] | unique | sort) == ([
    "Go quality gates",
    "Nested VCI module",
    "All conformance profiles passed",
    "Go vulnerability analysis",
    "Nested VCI vulnerability analysis",
    "Analyze Go"
  ] | sort) and
  (all(.requiredChecks[];
    .name as $name |
    ({
      "Go quality gates": ".github/workflows/ci.yml",
      "Nested VCI module": ".github/workflows/ci.yml",
      "All conformance profiles passed": ".github/workflows/conformance.yml",
      "Go vulnerability analysis": ".github/workflows/security.yml",
      "Nested VCI vulnerability analysis": ".github/workflows/security.yml",
      "Analyze Go": ".github/workflows/codeql.yml"
    }[$name]) as $path |
    successful_actions_check($commit; $path; "push") and
    .workflow.headBranch == "main"
  )) and

  .pullRequestEvidence.mergeCommitSha == $commit and
  .pullRequestEvidence.base.ref == "main" and
  .pullRequestEvidence.headVerification.sha ==
    .pullRequestEvidence.head.sha and
  .pullRequestEvidence.headVerification.verification.verified == true and
  .pullRequestEvidence.headVerification.verification.reason == "valid" and
  .pullRequestEvidence.reviewPolicy == {
    mode: "solo-maintainer-signed-head-and-required-checks",
    requiredApprovalCount: 0
  } and
  (.pullRequestEvidence | has("approvals") | not) and
  (.pullRequestEvidence.dependencyReview |
    successful_actions_check(
      $root.pullRequestEvidence.head.sha;
      ".github/workflows/security.yml";
      "pull_request"
    )
  ) and

  (.conformance.aggregateCheck |
    .name == "All conformance profiles passed" and
    successful_actions_check(
      $commit; ".github/workflows/conformance.yml"; "push"
    )
  ) and
  (.conformance.profiles | length) == 17 and
  ([.conformance.profiles[].profile] | unique | sort) == ([
    "oidc",
    "fapi2-sp-op-mtls-mtls",
    "fapi2-sp-op-mtls-dpop",
    "fapi2-sp-op-private-key-mtls",
    "fapi2-ms-op-jar",
    "fapi2-ms-op-jarm",
    "fapi2-sp-op-private-key-dpop",
    "fapi1-op-mtls",
    "fapi1-op-mtls-jarm",
    "fapi1-op-mtls-par",
    "fapi1-op-mtls-par-jarm",
    "fapi1-op-private-key",
    "fapi1-op-private-key-jarm",
    "fapi1-op-private-key-par",
    "fapi1-op-private-key-par-jarm",
    "fapiciba",
    "federation"
  ] | sort) and
  (all(.conformance.profiles[];
    .job.name == .profile and .job.status == "completed" and
    .job.conclusion == "success" and
    .artifact.name == (
      "conformance-" + .profile + "-" +
      ($root.conformance.aggregateCheck.workflow.id | tostring)
    ) and
    .artifact.expired == false and .artifact.headSha == $commit and
    (.artifact.digest | test("^sha256:[0-9a-f]{64}$"))
  ))
' "$evidence_file" >/dev/null

printf 'Verified retained release evidence for %s\n' "$expected_commit"
