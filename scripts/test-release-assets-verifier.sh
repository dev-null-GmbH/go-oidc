#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

"$tool_root/scripts/test-conformance-evidence-bundle.sh"

asset_dir="$temporary_root/assets"
source_dir="$temporary_root/source"
conformance_archives_dir="$temporary_root/conformance-archives"
conformance_fixture_dir="$temporary_root/conformance-fixture"
mkdir -p \
  "$asset_dir" "$source_dir" \
  "$conformance_archives_dir" "$conformance_fixture_dir"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

printf '{"result":"PASSED"}\n' > "$conformance_fixture_dir/result.json"
printf 'test signature\n' > "$conformance_fixture_dir/result.sig"
(
  cd "$conformance_fixture_dir"
  zip -q export.zip result.json result.sig
)
printf 'ephemeral authorization-server log\n' \
  > "$conformance_fixture_dir/auth-server.log"

release_tag='v0.25.1-d0.1'
release_version="${release_tag#v}"
release_commit='0123456789abcdef0123456789abcdef01234567'
pull_head='89abcdef0123456789abcdef0123456789abcdef'
conformance_run_id=103
digest="sha256:$(printf '0%.0s' {1..64})"

make_check() {
  local name="$1"
  local sha="$2"
  local path="$3"
  local event="$4"
  local branch="$5"
  local run_id="$6"

  jq -n \
    --arg name "$name" \
    --arg sha "$sha" \
    --arg path "$path" \
    --arg event "$event" \
    --arg branch "$branch" \
    --argjson run_id "$run_id" '
    {
      id: $run_id,
      name: $name,
      headSha: $sha,
      status: "completed",
      conclusion: "success",
      detailsUrl: ("https://example.invalid/actions/runs/" + ($run_id | tostring)),
      app: {id: 15368, slug: "github-actions"},
      workflow: {
        id: $run_id,
        path: $path,
        event: $event,
        headBranch: $branch,
        headSha: $sha,
        runAttempt: 1,
        status: "completed",
        conclusion: "success",
        htmlUrl: "https://example.invalid/run"
      }
    }'
}

check_specs=(
  $'Go quality gates\t.github/workflows/ci.yml\t101'
  $'Nested VCI module\t.github/workflows/ci.yml\t102'
  $'All conformance profiles passed\t.github/workflows/conformance.yml\t103'
  $'Go vulnerability analysis\t.github/workflows/security.yml\t104'
  $'Nested VCI vulnerability analysis\t.github/workflows/security.yml\t105'
  $'Analyze Go\t.github/workflows/codeql.yml\t106'
)
checks=()
for specification in "${check_specs[@]}"; do
  IFS=$'\t' read -r name path run_id <<< "$specification"
  checks+=("$(make_check "$name" "$release_commit" "$path" push main "$run_id")")
done
checks_json="$(printf '%s\n' "${checks[@]}" | jq -s 'sort_by(.name)')"
aggregate_check="$(
  jq '.[] | select(.name == "All conformance profiles passed")' \
    <<< "$checks_json"
)"
dependency_review="$(
  make_check "Dependency review" "$pull_head" \
    .github/workflows/security.yml pull_request feature 107
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
profile_records=()
profile_id=1000
for profile in "${profiles[@]}"; do
  artifact_archive="$conformance_archives_dir/$profile_id.zip"
  (
    cd "$conformance_fixture_dir"
    zip -q -j "$artifact_archive" export.zip auth-server.log
  )
  artifact_size="$(wc -c < "$artifact_archive")"
  artifact_size="${artifact_size//[[:space:]]/}"
  artifact_digest="sha256:$(sha256_file "$artifact_archive")"
  profile_records+=("$(
    jq -n \
      --arg profile "$profile" \
      --arg commit "$release_commit" \
      --arg digest "$artifact_digest" \
      --argjson id "$profile_id" \
      --argjson run_id "$conformance_run_id" \
      --argjson size "$artifact_size" '
      {
        profile: $profile,
        job: {
          id: $id,
          name: $profile,
          status: "completed",
          conclusion: "success",
          htmlUrl: "https://example.invalid/job"
        },
        artifact: {
          id: $id,
          name: ("conformance-" + $profile + "-" + ($run_id | tostring)),
          sizeInBytes: $size,
          digest: $digest,
          expired: false,
          archiveDownloadUrl: "https://example.invalid/artifact",
          headSha: $commit
        }
      }'
  )")
  profile_id=$((profile_id + 1))
done
profiles_json="$(printf '%s\n' "${profile_records[@]}" | jq -s 'sort_by(.profile)')"

jq -n \
  --arg commit "$release_commit" \
  --arg head "$pull_head" \
  --argjson checks "$checks_json" \
  --argjson dependency "$dependency_review" \
  --argjson aggregate "$aggregate_check" \
  --argjson profiles "$profiles_json" '
  {
    schemaVersion: 2,
    repository: "dev-null-GmbH/go-oidc",
    releaseCommit: $commit,
    commitVerification: {
      sha: $commit,
      verification: {verified: true, reason: "valid"}
    },
    requiredChecks: $checks,
    pullRequestEvidence: {
      mergeCommitSha: $commit,
      author: {login: "greg6775", id: 33130539},
      base: {ref: "main", sha: $commit},
      head: {ref: "feature", sha: $head},
      headVerification: {
        sha: $head,
        verification: {verified: true, reason: "valid"}
      },
      reviewPolicy: {
        mode: "solo-maintainer-signed-head-and-required-checks",
        requiredApprovalCount: 0
      },
      dependencyReview: $dependency
    },
    conformance: {
      aggregateCheck: $aggregate,
      profiles: $profiles
    }
  }' > "$asset_dir/RELEASE-EVIDENCE.json"

go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$asset_dir/RELEASE-EVIDENCE.json" \
  -archives-dir "$conformance_archives_dir" \
  -bundle "$asset_dir/CONFORMANCE-EVIDENCE.tar" >/dev/null

jq -n \
  --arg tag "$release_tag" \
  --arg commit "$release_commit" \
  --arg digest "$digest" '
  {
    schemaVersion: 1,
    releaseTag: $tag,
    releaseCommit: $commit,
    module: {path: "github.com/dev-null-GmbH/go-oidc"},
    provenanceBinding: {
      workflow: ".github/workflows/release.yml",
      sourceRef: "refs/heads/main",
      sourceDigest: $commit
    },
    conformance: {
      evidence: "CONFORMANCE-EVIDENCE.tar",
      images: {
        maven: ("maven@" + $digest),
        mongodb: ("mongo@" + $digest),
        nginx: ("nginx@" + $digest),
        temurin: ("temurin@" + $digest)
      }
    },
    releaseEvidence: "RELEASE-EVIDENCE.json"
  }' > "$asset_dir/RELEASE-MANIFEST.json"

jq -n \
  --arg tag "$release_tag" \
  --arg commit "$release_commit" '
  {
    spdxVersion: "SPDX-2.3",
    documentNamespace: ("https://example.invalid/" + $commit),
    documentComment: (
      "Approved local replacement: examples/vci maps " +
      "github.com/dev-null-GmbH/go-oidc@" + $tag +
      " to the release source root"
    ),
    packages: [
      {
        name: "github.com/dev-null-GmbH/go-oidc",
        versionInfo: $tag,
        primaryPackagePurpose: "SOURCE"
      },
      {
        name: "github.com/dev-null-GmbH/go-oidc/examples/vci",
        versionInfo: $tag,
        primaryPackagePurpose: "SOURCE"
      },
      {name: "github.com/luikyv/go-sdjwt", versionInfo: "v0.1.0"},
      {name: "golang.org/x/crypto", versionInfo: "v0.39.0"}
    ]
  }' > "$asset_dir/go-oidc-$release_version.spdx.json"

archive_root="$source_dir/go-oidc-$release_version"
mkdir -p "$archive_root"
printf 'release source\n' > "$archive_root/source.txt"
tar -C "$source_dir" -cf \
  "$asset_dir/go-oidc-$release_version.src.tar" \
  "go-oidc-$release_version"
printf 'release %s\n' "$release_commit" > "$asset_dir/PATCHES.txt"
printf 'release notes\n' > "$asset_dir/RELEASE-NOTES.md"
printf '{}\n' > "$asset_dir/provenance.sigstore.json"
printf '{}\n' > "$asset_dir/sbom-attestation.sigstore.json"

"$tool_root/scripts/write-release-checksums.sh" "$asset_dir" >/dev/null
"$tool_root/scripts/verify-release-assets.sh" \
  "$release_tag" "$asset_dir" "$release_commit" >/dev/null

cp "$asset_dir/CONFORMANCE-EVIDENCE.tar" \
  "$temporary_root/valid-conformance-evidence.tar"
printf 'X' | dd of="$asset_dir/CONFORMANCE-EVIDENCE.tar" \
  bs=1 seek=512 conv=notrunc 2>/dev/null
"$tool_root/scripts/write-release-checksums.sh" "$asset_dir" >/dev/null
if "$tool_root/scripts/verify-release-assets.sh" \
  "$release_tag" "$asset_dir" "$release_commit" >/dev/null 2>&1; then
  echo "Release verifier accepted altered conformance evidence" >&2
  exit 1
fi
mv "$temporary_root/valid-conformance-evidence.tar" \
  "$asset_dir/CONFORMANCE-EVIDENCE.tar"
"$tool_root/scripts/write-release-checksums.sh" "$asset_dir" >/dev/null

cp "$asset_dir/RELEASE-EVIDENCE.json" "$temporary_root/valid-release-evidence.json"
jq '.schemaVersion = 1' "$temporary_root/valid-release-evidence.json" \
  > "$asset_dir/RELEASE-EVIDENCE.json"
if "$tool_root/scripts/verify-release-evidence.sh" \
  "$asset_dir/RELEASE-EVIDENCE.json" "$release_commit" >/dev/null 2>&1; then
  echo "Verifier accepted obsolete two-person evidence schema" >&2
  exit 1
fi
jq '.pullRequestEvidence.approvals = []' \
  "$temporary_root/valid-release-evidence.json" \
  > "$asset_dir/RELEASE-EVIDENCE.json"
if "$tool_root/scripts/verify-release-evidence.sh" \
  "$asset_dir/RELEASE-EVIDENCE.json" "$release_commit" >/dev/null 2>&1; then
  echo "Verifier accepted ambiguous approval evidence in the solo model" >&2
  exit 1
fi
cp "$temporary_root/valid-release-evidence.json" "$asset_dir/RELEASE-EVIDENCE.json"

cp "$asset_dir/SHA256SUMS" "$temporary_root/valid-checksums"
awk '$2 != "RELEASE-NOTES.md"' "$temporary_root/valid-checksums" \
  > "$asset_dir/SHA256SUMS"
if "$tool_root/scripts/verify-release-assets.sh" \
  "$release_tag" "$asset_dir" "$release_commit" >/dev/null 2>&1; then
  echo "Verifier accepted a checksum manifest that omitted an asset" >&2
  exit 1
fi

cp "$temporary_root/valid-checksums" "$asset_dir/SHA256SUMS"
head -n 1 "$temporary_root/valid-checksums" >> "$asset_dir/SHA256SUMS"
if "$tool_root/scripts/verify-release-assets.sh" \
  "$release_tag" "$asset_dir" "$release_commit" >/dev/null 2>&1; then
  echo "Verifier accepted a duplicate checksum entry" >&2
  exit 1
fi

echo "Release asset verifier rejects stale review evidence and incomplete checksums"
