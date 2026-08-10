#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${RELEASE_SOURCE_ROOT:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"
cd "$source_root"

shopt -s nullglob
workflow_files=(.github/workflows/*.yml .github/workflows/*.yaml)
if (( ${#workflow_files[@]} == 0 )); then
  echo "No workflow files found" >&2
  exit 1
fi

status=0
version_comment_pattern='#[[:space:]]*v[0-9]+([.][0-9]+){1,2}'
while IFS=: read -r file line content; do
  if [[ ! "$content" =~ uses:[[:space:]]*([^[:space:]#]+) ]]; then
    continue
  fi

  action_spec="${BASH_REMATCH[1]}"
  if [[ "$action_spec" == ./* ]]; then
    continue
  fi

  reference="${action_spec##*@}"
  if [[ ! "$reference" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s:%s: action is not pinned to a full commit SHA: %s\n' \
      "$file" "$line" "$action_spec" >&2
    status=1
  fi

  if [[ ! "$content" =~ $version_comment_pattern ]]; then
    printf '%s:%s: pinned action needs an audited version comment\n' \
      "$file" "$line" >&2
    status=1
  fi
done < <(grep -nHE '^[[:space:]]*(-[[:space:]]+)?uses:' "${workflow_files[@]}")

if (( status != 0 )); then
  exit "$status"
fi

for script in scripts/*.sh; do
  if [[ ! -x "$script" ]]; then
    printf '%s must be executable\n' "$script" >&2
    exit 1
  fi
done

"$tool_root/scripts/verify-release-workflow.sh"
"$tool_root/scripts/test-release-tag-verifier.sh"
"$tool_root/scripts/test-release-assets-verifier.sh"

echo "All external workflow actions use immutable commit SHAs"
