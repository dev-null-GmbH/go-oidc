#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${RELEASE_SOURCE_ROOT:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"

tag="${1:?usage: verify-release-tag.sh <tag> [expected-commit]}"
expected_commit="${2:-}"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-d0\.[1-9][0-9]*$ ]]; then
  printf 'Invalid governed fork release tag: %s\n' "$tag" >&2
  exit 1
fi
if ! git -C "$source_root" show-ref --verify --quiet "refs/tags/$tag"; then
  printf 'Release tag does not exist locally: %s\n' "$tag" >&2
  exit 1
fi
if [[ "$(git -C "$source_root" cat-file -t "refs/tags/$tag")" != "tag" ]]; then
  printf 'Release tag must be annotated: %s\n' "$tag" >&2
  exit 1
fi

tag_headers="$(
  git -C "$source_root" cat-file tag "refs/tags/$tag" |
    awk 'NF == 0 { exit } { print }'
)"
tag_object="$(awk '$1 == "object" && NF == 2 {print $2}' <<< "$tag_headers")"
tag_type="$(awk '$1 == "type" && NF == 2 {print $2}' <<< "$tag_headers")"
embedded_tag="$(awk '$1 == "tag" && NF == 2 {print $2}' <<< "$tag_headers")"
if [[ "$(grep -c '^object ' <<< "$tag_headers")" != "1" ||
      "$(grep -c '^type ' <<< "$tag_headers")" != "1" ||
      "$(grep -c '^tag ' <<< "$tag_headers")" != "1" ||
      ! "$tag_object" =~ ^[0-9a-f]{40}$ ||
      "$tag_type" != "commit" || "$embedded_tag" != "$tag" ]]; then
  printf 'Tag object identity is invalid for requested ref %s\n' "$tag" >&2
  exit 1
fi

release_commit="$tag_object"
if [[ -n "$expected_commit" && "$release_commit" != "$expected_commit" ]]; then
  printf 'Tag %s resolves to %s, expected %s\n' \
    "$tag" "$release_commit" "$expected_commit" >&2
  exit 1
fi

git -C "$source_root" config --local gpg.format ssh
git -C "$source_root" config --local gpg.ssh.allowedSignersFile \
  "$tool_root/.github/release-signers"
git -C "$source_root" config --local gpg.minTrustLevel fully

git -C "$source_root" verify-tag "$tag"

printf 'Verified signed annotated tag %s directly identifies commit %s\n' \
  "$tag" "$release_commit"
