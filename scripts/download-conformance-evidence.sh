#!/usr/bin/env bash

set -euo pipefail
umask 077

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_file="${1:?usage: download-conformance-evidence.sh <evidence-json> <bundle-output>}"
bundle_output="${2:?usage: download-conformance-evidence.sh <evidence-json> <bundle-output>}"
api_version="2026-03-10"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "GH_TOKEN is required to download conformance evidence" >&2
  exit 1
fi
if [[ ! -s "$evidence_file" ]]; then
  echo "Release evidence is missing or empty" >&2
  exit 1
fi

repository="$(jq -r .repository "$evidence_file")"
if [[ "$repository" != "dev-null-GmbH/go-oidc" ]]; then
  echo "Release evidence identifies an unexpected repository" >&2
  exit 1
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT
archives_dir="$temporary_root/archives"
mkdir -p "$archives_dir"

artifact_count=0
while IFS=$'\t' read -r artifact_id artifact_name artifact_size artifact_digest; do
  if [[ ! "$artifact_id" =~ ^[1-9][0-9]*$ ||
        ! "$artifact_name" =~ ^conformance-[a-z0-9-]+-[1-9][0-9]*$ ||
        ! "$artifact_size" =~ ^[1-9][0-9]*$ ||
        ! "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Release evidence contains invalid conformance artifact metadata" >&2
    exit 1
  fi

  archive="$archives_dir/$artifact_id.zip"
  gh api \
    -H "X-GitHub-Api-Version: $api_version" \
    -H "Accept: application/vnd.github+json" \
    "repos/$repository/actions/artifacts/$artifact_id/zip" \
    > "$archive"

  actual_size="$(wc -c < "$archive")"
  actual_size="${actual_size//[[:space:]]/}"
  actual_digest="sha256:$(sha256_file "$archive")"
  if [[ "$actual_size" != "$artifact_size" ||
        "$actual_digest" != "$artifact_digest" ]]; then
    printf 'Downloaded conformance artifact bytes do not match evidence: %s\n' \
      "$artifact_name" >&2
    exit 1
  fi
  artifact_count=$((artifact_count + 1))
done < <(
  jq -r \
    '.conformance.profiles | sort_by(.profile)[] |
     [.artifact.id, .artifact.name, .artifact.sizeInBytes, .artifact.digest] |
     @tsv' \
    "$evidence_file"
)

if [[ "$artifact_count" != "17" ]]; then
  printf 'Expected 17 conformance artifact downloads, got %s\n' \
    "$artifact_count" >&2
  exit 1
fi

go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$evidence_file" \
  -archives-dir "$archives_dir" \
  -bundle "$bundle_output"
