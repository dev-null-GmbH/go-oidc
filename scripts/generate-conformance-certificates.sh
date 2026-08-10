#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="${1:-$tool_root}"
repo_root="$(cd "$repo_root" && pwd)"
cert_dir="$repo_root/examples/keys"

for command in go jq openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required conformance certificate tool is unavailable: %s\n' \
      "$command" >&2
    exit 1
  fi
done
if [[ ! -d "$cert_dir" || -L "$cert_dir" ]]; then
  printf 'Conformance key directory is missing or unsafe: %s\n' "$cert_dir" >&2
  exit 1
fi

generation_dir="$(mktemp -d "$cert_dir/.conformance-certificates.XXXXXX")"
cleanup() {
  case "$generation_dir" in
    "$cert_dir"/.conformance-certificates.*)
      rm -rf -- "$generation_dir"
      ;;
    *)
      echo "Refusing to clean an unexpected certificate path" >&2
      ;;
  esac
}
trap cleanup EXIT

generate_certificate() {
  local name="$1"
  local common_name="$2"
  local extended_key_usage="$3"
  local subject_alt_name="${4:-}"
  local arguments=(
    req -new -newkey rsa:2048 -nodes -x509 -sha256 -days 2
    -subj "/CN=$common_name"
    -keyout "$generation_dir/$name.key"
    -out "$generation_dir/$name.crt"
    -addext "basicConstraints=critical,CA:FALSE"
    -addext "keyUsage=critical,digitalSignature,keyEncipherment"
    -addext "extendedKeyUsage=$extended_key_usage"
  )
  if [[ -n "$subject_alt_name" ]]; then
    arguments+=(-addext "subjectAltName=$subject_alt_name")
  fi
  openssl "${arguments[@]}" >/dev/null 2>&1
  chmod 0600 "$generation_dir/$name.key"
  chmod 0644 "$generation_dir/$name.crt"
}

generate_certificate server auth.localhost serverAuth \
  "DNS:auth.localhost,DNS:matls-auth.localhost,DNS:fed-trust-anchor.localhost,DNS:localhost"
generate_certificate client_one client_one clientAuth
generate_certificate client_two client_two clientAuth

for name in server client_one client_two; do
  mv -f "$generation_dir/$name.crt" "$cert_dir/$name.crt"
  mv -f "$generation_dir/$name.key" "$cert_dir/$name.key"
done

patched_configs=0
while IFS= read -r -d '' config; do
  if ! jq -e '(.mtls? != null) or (.mtls2? != null)' "$config" >/dev/null; then
    continue
  fi
  temporary="$(mktemp "${config}.XXXXXX")"
  if ! jq \
    --rawfile client_one_cert "$cert_dir/client_one.crt" \
    --rawfile client_one_key "$cert_dir/client_one.key" \
    --rawfile client_two_cert "$cert_dir/client_two.crt" \
    --rawfile client_two_key "$cert_dir/client_two.key" '
      if .mtls? != null then
        .mtls.cert = $client_one_cert |
        .mtls.key = $client_one_key
      else . end |
      if .mtls2? != null then
        .mtls2.cert = $client_two_cert |
        .mtls2.key = $client_two_key
      else . end
    ' "$config" > "$temporary"; then
    rm -f -- "$temporary"
    printf 'Failed to inject ephemeral credentials into %s\n' "$config" >&2
    exit 1
  fi
  chmod 0644 "$temporary"
  mv -f "$temporary" "$config"
  patched_configs=$((patched_configs + 1))
done < <(find "$repo_root/examples" -type f -name '*.json' -print0 | sort -z)

if (( patched_configs == 0 )); then
  echo "No conformance configurations accepted ephemeral credentials" >&2
  exit 1
fi

"$tool_root/scripts/verify-conformance-certificates.sh" "$repo_root" 43200
printf 'Generated ephemeral conformance TLS credentials for %d configs\n' \
  "$patched_configs"
