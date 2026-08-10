#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tag="${1:?usage: verify-release-assets.sh <tag> <asset-directory> <commit>}"
asset_dir="${2:?usage: verify-release-assets.sh <tag> <asset-directory> <commit>}"
expected_commit="${3:?usage: verify-release-assets.sh <tag> <asset-directory> <commit>}"
release_version="${tag#v}"
archive_name="go-oidc-${release_version}.src.tar"
sbom_name="go-oidc-${release_version}.spdx.json"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-d0\.[1-9][0-9]*$ || \
      ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid release identity" >&2
  exit 1
fi

required_assets=(
  "$archive_name"
  "$sbom_name"
  "PATCHES.txt"
  "RELEASE-MANIFEST.json"
  "RELEASE-NOTES.md"
  "RELEASE-EVIDENCE.json"
  "provenance.sigstore.json"
  "sbom-attestation.sigstore.json"
  "SHA256SUMS"
)
for asset in "${required_assets[@]}"; do
  if [[ ! -f "$asset_dir/$asset" || -L "$asset_dir/$asset" ||
        ! -s "$asset_dir/$asset" ]]; then
    printf 'Missing or empty release asset: %s\n' "$asset" >&2
    exit 1
  fi
done

actual_asset_count="$(find "$asset_dir" -maxdepth 1 -type f | wc -l | tr -d ' ')"
unexpected_nodes="$(
  find "$asset_dir" -mindepth 1 -maxdepth 1 ! -type f -print
)"
if [[ "$actual_asset_count" != "${#required_assets[@]}" ||
      -n "$unexpected_nodes" ]]; then
  printf 'Expected %d release assets, found %s\n' \
    "${#required_assets[@]}" "$actual_asset_count" >&2
  find "$asset_dir" -maxdepth 1 -type f -print >&2
  exit 1
fi

expected_checksum_names=()
for asset in "${required_assets[@]}"; do
  if [[ "$asset" != "SHA256SUMS" ]]; then
    expected_checksum_names+=("$asset")
  fi
done
manifest_checksum_names=()
while IFS= read -r checksum_line; do
  if [[ ! "$checksum_line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9][A-Za-z0-9._-]*)$ ]]; then
    printf 'Malformed SHA256SUMS line: %s\n' "$checksum_line" >&2
    exit 1
  fi
  expected_hash="${BASH_REMATCH[1]}"
  filename="${BASH_REMATCH[2]}"
  manifest_checksum_names+=("$filename")
  if [[ ! -f "$asset_dir/$filename" || -L "$asset_dir/$filename" ]]; then
    printf 'Checksum names an unsafe or missing asset: %s\n' "$filename" >&2
    exit 1
  fi
  actual_hash="$(sha256sum "$asset_dir/$filename" | awk '{print $1}')"
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    printf 'Checksum mismatch for %s\n' "$filename" >&2
    exit 1
  fi
done < "$asset_dir/SHA256SUMS"

if ! diff -u \
  <(printf '%s\n' "${expected_checksum_names[@]}" | sort) \
  <(printf '%s\n' "${manifest_checksum_names[@]}" | sort) >/dev/null; then
  echo "SHA256SUMS must name every non-manifest asset exactly once" >&2
  exit 1
fi

jq -e \
  --arg tag "$tag" \
  --arg commit "$expected_commit" \
  '.schemaVersion == 1 and .releaseTag == $tag and .releaseCommit == $commit and
   .module.path == "github.com/dev-null-GmbH/go-oidc" and
   .provenanceBinding.workflow == ".github/workflows/release.yml" and
   .provenanceBinding.sourceRef == "refs/heads/main" and
   .provenanceBinding.sourceDigest == $commit and
   .releaseEvidence == "RELEASE-EVIDENCE.json" and
   (.conformance.images | all(.[]; test("@sha256:[0-9a-f]{64}$")))' \
  "$asset_dir/RELEASE-MANIFEST.json" >/dev/null
"$tool_root/scripts/verify-release-evidence.sh" \
  "$asset_dir/RELEASE-EVIDENCE.json" "$expected_commit"
jq -e \
  --arg version "$tag" \
  --arg commit "$expected_commit" \
  '.spdxVersion == "SPDX-2.3" and
   (.documentNamespace | endswith("/" + $commit)) and
   ([.packages[] | select(
      .versionInfo == $version and .primaryPackagePurpose == "SOURCE"
    ) | .name] | sort) == [
      "github.com/dev-null-GmbH/go-oidc",
      "github.com/dev-null-GmbH/go-oidc/examples/vci"
    ] and
   any(.packages[];
     .name == "github.com/luikyv/go-sdjwt" and .versionInfo == "v0.1.0") and
   any(.packages[];
     .name == "golang.org/x/crypto" and .versionInfo == "v0.39.0") and
   (.documentComment | contains(
     "Approved local replacement: examples/vci maps github.com/dev-null-GmbH/go-oidc@" +
     $version + " to the release source root"
   ))' \
  "$asset_dir/$sbom_name" >/dev/null
jq -e . "$asset_dir/provenance.sigstore.json" >/dev/null
jq -e . "$asset_dir/sbom-attestation.sigstore.json" >/dev/null

if ! grep -Fq "$expected_commit" "$asset_dir/PATCHES.txt"; then
  echo "Patch inventory does not identify the release commit" >&2
  exit 1
fi

prefix="go-oidc-${release_version}/"
if tar -tf "$asset_dir/$archive_name" | \
   awk -v prefix="$prefix" \
     'index($0, prefix) != 1 || $0 ~ /(^|\/)\.\.($|\/)/ { bad = 1 }
      END { exit bad }'; then
  :
else
  echo "Source archive contains an unexpected path" >&2
  exit 1
fi

printf 'Verified staged assets for %s (%s)\n' "$tag" "$expected_commit"
