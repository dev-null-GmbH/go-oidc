#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${RELEASE_SOURCE_ROOT:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"
workflow="$source_root/.github/workflows/release.yml"

if [[ ! -f "$workflow" ]]; then
  echo "Governed release workflow is missing" >&2
  exit 1
fi
if grep -Eq '^  (push|workflow_dispatch):' "$workflow"; then
  echo "Governed releases must load only through default-branch repository dispatch" >&2
  exit 1
fi

qualification_block="$(
  awk '/^  qualify:$/ {inside=1} /^  prepare:$/ {inside=0} inside' \
    "$workflow"
)"
publish_block="$(
  awk '/^  publish:$/ {inside=1} inside' "$workflow"
)"
if grep -Eq '^[[:space:]]+[a-z-]+:[[:space:]]+write$' \
  <<< "$qualification_block"; then
  echo "First release qualification job must be read-only" >&2
  exit 1
fi

required_literals=(
  'repository_dispatch:'
  '- governed-release-prepare'
  '- governed-release-publish'
  'name: Read-only release qualification'
  'environment: governed-release'
  'EVENT_TYPE: ${{ github.event.action }}'
  'RELEASE_COMMIT: ${{ github.event.client_payload.commit }}'
  'RELEASE_TAG: ${{ github.event.client_payload.tag }}'
  'SENDER_ID: ${{ github.event.sender.id }}'
  'SENDER_LOGIN: ${{ github.event.sender.login }}'
  'greg6775:33130539|Schlauer-Hax:32987311'
  'WORKFLOW_REF: ${{ github.ref }}'
  'refs/heads/$DEFAULT_BRANCH'
  'path: trusted'
  'path: release-tree'
  './trusted/scripts/verify-release-tag.sh'
  './trusted/scripts/verify-release-checks.sh'
  '$RUNNER_TEMP/RELEASE-EVIDENCE.json'
  '$RUNNER_TEMP/current-evidence.json'
  './trusted/scripts/build-release-assets.sh'
  'RELEASE-EVIDENCE.json RELEASE-MANIFEST.json'
  '--source-ref "refs/heads/main"'
  '$RUNNER_TEMP/verified-draft-snapshot.json'
  'repos/$GITHUB_REPOSITORY/releases/assets/$asset_id'
  '$RUNNER_TEMP/final-release-assets'
  '$RUNNER_TEMP/prepublish-draft-snapshot.json'
  '--method PATCH'
  '$RUNNER_TEMP/publish-release.json'
  '.immutable == true'
)
for literal in "${required_literals[@]}"; do
  if ! grep -Fq -- "$literal" "$workflow"; then
    printf 'Release workflow trust contract is missing: %s\n' \
      "$literal" >&2
    exit 1
  fi
done

if [[ "$(grep -c '^    needs: qualify$' "$workflow")" != "2" ]]; then
  echo "Both release write jobs must depend on read-only qualification" >&2
  exit 1
fi
if ! grep -Fq 'environment: governed-release' <<< "$publish_block"; then
  echo "The publish job must use the protected release environment" >&2
  exit 1
fi
if grep -Fq './release-tree/scripts/' "$workflow"; then
  echo "Release workflow must never execute verifier code from the tag tree" >&2
  exit 1
fi
if [[ "$(grep -c 'verify-release-checks.sh \\' "$workflow")" -lt 2 ||
      "$(grep -c 'build-release-assets.sh \\' "$workflow")" != "2" ]]; then
  echo "Release evidence generation is not wired into both stages" >&2
  exit 1
fi
if ! awk '
  /cmp "[$]RUNNER_TEMP\/verified-draft-snapshot[.]json"/ {
    getline
    if ($0 ~ /prepublish-draft-snapshot[.]json/) {
      getline
      if ($0 ~ /gh api --method PATCH/) {
        found = 1
      }
    }
  }
  END { exit(found ? 0 : 1) }
' "$workflow"; then
  echo "Final remote snapshot comparison must be immediately followed by publication" >&2
  exit 1
fi

echo "Governed release workflow preserves the trusted-tooling boundary"
