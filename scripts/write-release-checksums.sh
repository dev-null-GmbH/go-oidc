#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

asset_dir="${1:?usage: write-release-checksums.sh <asset-directory>}"
asset_dir="$(cd "$asset_dir" && pwd)"

assets=()
while IFS= read -r -d '' asset; do
  assets+=("$asset")
done < <(
  find "$asset_dir" -maxdepth 1 -type f ! -name SHA256SUMS \
    -print0 | sort -z
)
if (( ${#assets[@]} == 0 )); then
  echo "No release assets found" >&2
  exit 1
fi

temporary="$(mktemp "$asset_dir/SHA256SUMS.XXXXXX")"
for asset in "${assets[@]}"; do
  checksum="$(sha256sum "$asset" | awk '{print $1}')"
  printf '%s  %s\n' "$checksum" "$(basename "$asset")" >> "$temporary"
done
mv "$temporary" "$asset_dir/SHA256SUMS"

printf 'Wrote checksums for %d release assets\n' "${#assets[@]}"
