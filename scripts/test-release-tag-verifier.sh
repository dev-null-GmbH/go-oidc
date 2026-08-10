#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

mkdir -p "$temporary_root/tool/scripts" "$temporary_root/tool/.github"
cp "$tool_root/scripts/verify-release-tag.sh" "$temporary_root/tool/scripts/"

ssh-keygen -q -t ed25519 -N '' -C release-test \
  -f "$temporary_root/signing-key"
printf 'release-test@example.invalid namespaces="git" %s\n' \
  "$(< "$temporary_root/signing-key.pub")" \
  > "$temporary_root/tool/.github/release-signers"

git init --quiet "$temporary_root/repository"
git -C "$temporary_root/repository" config user.name 'Release test'
git -C "$temporary_root/repository" config user.email \
  release-test@example.invalid
git -C "$temporary_root/repository" config user.signingkey \
  "$temporary_root/signing-key"
git -C "$temporary_root/repository" config gpg.format ssh
git -C "$temporary_root/repository" config commit.gpgsign true
git -C "$temporary_root/repository" config tag.gpgsign true

touch "$temporary_root/repository/release-source"
git -C "$temporary_root/repository" add release-source
git -C "$temporary_root/repository" commit --quiet -m 'release source'
release_commit="$(git -C "$temporary_root/repository" rev-parse HEAD)"
valid_tag='v1.2.3-d0.1'
git -C "$temporary_root/repository" tag --annotate "$valid_tag" \
  --message "$valid_tag"

RELEASE_SOURCE_ROOT="$temporary_root/repository" \
  "$temporary_root/tool/scripts/verify-release-tag.sh" \
  "$valid_tag" "$release_commit" >/dev/null

tag_object="$(
  git -C "$temporary_root/repository" rev-parse "refs/tags/$valid_tag"
)"
replayed_tag='v1.2.3-d0.2'
git -C "$temporary_root/repository" update-ref \
  "refs/tags/$replayed_tag" "$tag_object"
if RELEASE_SOURCE_ROOT="$temporary_root/repository" \
  "$temporary_root/tool/scripts/verify-release-tag.sh" \
  "$replayed_tag" "$release_commit" >/dev/null 2>&1; then
  echo "Verifier accepted a signed tag object replayed under another ref" >&2
  exit 1
fi

echo "Release tag verifier rejects signed-object ref replay"
