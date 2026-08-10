#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${RELEASE_SOURCE_ROOT:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"
cd "$source_root"
export LC_ALL=C

tag="${1:?usage: build-release-assets.sh <tag> <output-directory> <evidence-json>}"
output_dir="${2:?usage: build-release-assets.sh <tag> <output-directory> <evidence-json>}"
evidence_file="${3:?usage: build-release-assets.sh <tag> <output-directory> <evidence-json>}"
evidence_file="$(cd "$(dirname "$evidence_file")" && pwd)/$(basename "$evidence_file")"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-d0\.[1-9][0-9]*$ ]]; then
  printf 'Invalid governed fork release tag: %s\n' "$tag" >&2
  exit 1
fi
if ! git show-ref --verify --quiet "refs/tags/$tag"; then
  printf 'Release tag does not exist locally: %s\n' "$tag" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Release assets must be built from a clean checkout" >&2
  exit 1
fi
if [[ ! -s "$evidence_file" ]]; then
  printf 'Release evidence is missing or empty: %s\n' "$evidence_file" >&2
  exit 1
fi
if [[ -e "$output_dir" ]] && \
   find "$output_dir" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
  printf 'Release output directory is not empty: %s\n' "$output_dir" >&2
  exit 1
fi
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

release_commit="$(git rev-parse "$tag^{commit}")"
release_version="${tag#v}"
source_date_epoch="$(git show -s --format=%ct "$release_commit")"
created_at="$(git show -s --format=%cI "$release_commit")"
upstream_tag="$(awk '$1 == "Base" && $2 == "tag:" {print $3; exit}' NOTICE)"
upstream_commit="$(awk '$1 == "Base" && $2 == "SHA:" {print $3; exit}' NOTICE)"

if [[ ! "$upstream_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || \
      ! "$upstream_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "NOTICE does not contain an exact upstream tag and commit" >&2
  exit 1
fi
if [[ "$(git rev-parse "$upstream_tag^{commit}")" != "$upstream_commit" ]]; then
  echo "NOTICE upstream tag and commit do not identify the same revision" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$upstream_commit" "$release_commit"; then
  echo "Recorded upstream commit is not an ancestor of the release" >&2
  exit 1
fi

go mod download
go mod verify
while IFS= read -r nested_go_mod; do
  nested_module_dir="$(dirname "$nested_go_mod")"
  (
    cd "$nested_module_dir"
    go mod download
    go mod verify
  )
done < <(
  find . -type f -name go.mod \
    ! -path './go.mod' \
    ! -path './.git/*' \
    ! -path './conformance-suite/*' \
    ! -path '*/vendor/*' |
    sort
)
module_path="$(go list -mod=readonly -m -f '{{.Path}}')"
go_directive="$(awk '$1 == "go" {print $2; exit}' go.mod)"
toolchain_directive="$(awk '$1 == "toolchain" {print $2; exit}' go.mod)"
actual_go_version="$(go env GOVERSION)"
conformance_version="$(awk '$1 == "CS_VERSION" && $2 == "=" {print $3; exit}' Makefile)"
conformance_commit="$(awk '$1 == "CS_COMMIT" && $2 == "=" {print $3; exit}' Makefile)"
maven_image="$(awk '$1 == "CS_MAVEN_IMAGE" && $2 == "=" {print $3; exit}' Makefile)"
python_version="$(awk '$1 == "PYTHON_VERSION:" {gsub(/"/, "", $2); print $2; exit}' .github/workflows/conformance.yml)"
mongo_image="$(awk '$1 == "image:" && $2 ~ /^mongo:/ {print $2; exit}' docker-compose.yml)"
nginx_image="$(awk -F '"' '/^readonly nginx_image=/ {print $2; exit}' scripts/prepare-conformance-suite.sh)"
temurin_image="$(awk -F '"' '/^readonly temurin_image=/ {print $2; exit}' scripts/prepare-conformance-suite.sh)"

if [[ ! "$module_path" =~ ^[A-Za-z0-9._/-]+$ || \
      ! "$go_directive" =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ || \
      ! "$actual_go_version" =~ ^go[0-9]+\.[0-9]+([.][0-9]+)?$ || \
      ! "$conformance_version" =~ ^release-v[0-9]+\.[0-9]+\.[0-9]+$ || \
      ! "$conformance_commit" =~ ^[0-9a-f]{40}$ || \
      ! "$maven_image" =~ @sha256:[0-9a-f]{64}$ || \
      ! "$mongo_image" =~ @sha256:[0-9a-f]{64}$ || \
      ! "$nginx_image" =~ @sha256:[0-9a-f]{64}$ || \
      ! "$temurin_image" =~ @sha256:[0-9a-f]{64}$ ]]; then
  echo "Release metadata contains an invalid value" >&2
  exit 1
fi

archive_name="go-oidc-${release_version}.src.tar"
sbom_name="go-oidc-${release_version}.spdx.json"

git archive \
  --format=tar \
  --prefix="go-oidc-${release_version}/" \
  "$tag" > "$output_dir/$archive_name"

{
  printf 'Fork patch inventory for %s\n' "$tag"
  printf 'Upstream: %s (%s)\n' "$upstream_tag" "$upstream_commit"
  printf 'Release:  %s\n\n' "$release_commit"
  git log --reverse --format='%H%x09%aI%x09%s' \
    "$upstream_commit..$release_commit"
} > "$output_dir/PATCHES.txt"

"$tool_root/scripts/verify-release-evidence.sh" \
  "$evidence_file" "$release_commit"
cp "$evidence_file" "$output_dir/RELEASE-EVIDENCE.json"

lock_sha256="$(sha256sum scripts/conformance-requirements.lock | awk '{print $1}')"
cat > "$output_dir/RELEASE-MANIFEST.json" <<EOF
{
  "schemaVersion": 1,
  "repository": "https://github.com/dev-null-GmbH/go-oidc",
  "releaseTag": "$tag",
  "releaseCommit": "$release_commit",
  "sourceDateEpoch": $source_date_epoch,
  "upstream": {
    "tag": "$upstream_tag",
    "commit": "$upstream_commit"
  },
  "provenanceBinding": {
    "workflow": ".github/workflows/release.yml",
    "sourceRef": "refs/heads/main",
    "sourceDigest": "$release_commit"
  },
  "module": {
    "path": "$module_path",
    "goDirective": "$go_directive",
    "toolchainDirective": "$toolchain_directive",
    "actualGoVersion": "$actual_go_version"
  },
  "nestedModules": [
    {
      "path": "github.com/dev-null-GmbH/go-oidc/examples/vci",
      "requiredForkVersion": "$tag",
      "releaseSourceReplacement": "../.."
    }
  ],
  "conformance": {
    "tag": "$conformance_version",
    "commit": "$conformance_commit",
    "python": "$python_version",
    "requirementsLockSHA256": "$lock_sha256",
    "images": {
      "maven": "$maven_image",
      "mongodb": "$mongo_image",
      "nginx": "$nginx_image",
      "temurin": "$temurin_image"
    }
  },
  "patchInventory": "PATCHES.txt",
  "releaseEvidence": "RELEASE-EVIDENCE.json",
  "sbom": "$sbom_name"
}
EOF

go run "$tool_root/scripts/generate-release-sbom.go" \
  -tag "$tag" \
  -commit "$release_commit" \
  -created "$created_at" \
  -output "$output_dir/$sbom_name"

cat > "$output_dir/RELEASE-NOTES.md" <<EOF
# go-oidc $tag

Governed d0 fork release based on upstream $upstream_tag
($upstream_commit), built from GitHub-verified squash commit $release_commit.

The staged release contains a deterministic source archive, the complete
fork-only patch inventory, a machine-readable release manifest, retained check
and conformance evidence, an SPDX 2.3 SBOM, SHA-256 checksums, and GitHub
Sigstore attestation bundles. OpenID
certification statements for upstream versions do not automatically apply to
this fork release.

Verify after downloading all assets:

\`sha256sum --check SHA256SUMS\`

\`for subject in $archive_name $sbom_name PATCHES.txt RELEASE-EVIDENCE.json RELEASE-MANIFEST.json RELEASE-NOTES.md; do gh attestation verify "\$subject" --bundle provenance.sigstore.json --deny-self-hosted-runners --repo dev-null-GmbH/go-oidc --signer-workflow github.com/dev-null-GmbH/go-oidc/.github/workflows/release.yml --source-ref refs/heads/main --source-digest $release_commit; done\`

\`gh attestation verify $archive_name --bundle sbom-attestation.sigstore.json --deny-self-hosted-runners --predicate-type https://spdx.dev/Document/v2.3 --repo dev-null-GmbH/go-oidc --signer-workflow github.com/dev-null-GmbH/go-oidc/.github/workflows/release.yml --source-ref refs/heads/main --source-digest $release_commit\`
EOF

printf 'Built deterministic release payload for %s at %s\n' \
  "$tag" "$output_dir"
