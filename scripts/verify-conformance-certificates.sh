#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="${1:-$tool_root}"
minimum_validity_seconds="${2:-43200}"
repo_root="$(cd "$repo_root" && pwd)"
cert_dir="$repo_root/examples/keys"
readonly maximum_lifetime_seconds=172800

if [[ ! "$minimum_validity_seconds" =~ ^[1-9][0-9]*$ ||
      "$minimum_validity_seconds" -gt 172800 ]]; then
  echo "Minimum certificate validity must be 1..172800 seconds" >&2
  exit 1
fi

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

key_permissions() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

certificate_epoch() {
  local cert="$1"
  local field="$2"
  local value epoch

  value="$(
    openssl x509 -in "$cert" -noout -dates -dateopt iso_8601 |
      awk -F= -v field="$field" '$1 == field {print $2}'
  )"
  if epoch="$(date -u -d "$value" +%s 2>/dev/null)"; then
    printf '%s\n' "$epoch"
    return
  fi
  if epoch="$(date -j -u -f '%Y-%m-%d %H:%M:%SZ' "$value" +%s 2>/dev/null)"; then
    printf '%s\n' "$epoch"
    return
  fi
  printf 'Unable to parse certificate time %s from %s\n' "$value" "$cert" >&2
  exit 1
}

verify_pair() {
  local name="$1"
  local common_name="$2"
  local purpose="$3"
  local cert="$cert_dir/$name.crt"
  local key="$cert_dir/$name.key"
  local cert_public_key key_public_key cert_text subject not_before not_after

  for file in "$cert" "$key"; do
    if [[ ! -f "$file" || -L "$file" || ! -s "$file" ]]; then
      printf 'Missing, empty, or unsafe conformance credential: %s\n' "$file" >&2
      exit 1
    fi
  done

  if ! openssl x509 -in "$cert" -noout -checkend \
    "$minimum_validity_seconds" >/dev/null; then
    printf 'Conformance certificate expires within %s seconds: %s\n' \
      "$minimum_validity_seconds" "$cert" >&2
    exit 1
  fi
  openssl x509 -in "$cert" -noout >/dev/null
  openssl pkey -in "$key" -check -noout >/dev/null 2>&1

  not_before="$(certificate_epoch "$cert" notBefore)"
  not_after="$(certificate_epoch "$cert" notAfter)"
  if (( not_after <= not_before ||
        not_after - not_before > maximum_lifetime_seconds )); then
    printf 'Conformance certificate lifetime exceeds 48 hours: %s\n' "$cert" >&2
    exit 1
  fi

  cert_public_key="$({
    openssl x509 -in "$cert" -pubkey -noout |
      openssl pkey -pubin -outform DER 2>/dev/null
  } | sha256_stream)"
  key_public_key="$({
    openssl pkey -in "$key" -pubout -outform DER 2>/dev/null
  } | sha256_stream)"
  if [[ "$cert_public_key" != "$key_public_key" ]]; then
    printf 'Certificate and private key do not match: %s\n' "$name" >&2
    exit 1
  fi
  if [[ "$(key_permissions "$key")" != "600" ]]; then
    printf 'Ephemeral conformance private key must have mode 600: %s\n' "$key" >&2
    exit 1
  fi

  cert_text="$(openssl x509 -in "$cert" -noout -text)"
  if ! grep -Fq 'CA:FALSE' <<< "$cert_text" ||
     ! grep -Fq 'Digital Signature' <<< "$cert_text" ||
     ! grep -Eq 'Public-Key: \(2048 bit\)' <<< "$cert_text"; then
    printf 'Conformance certificate constraints are invalid: %s\n' "$cert" >&2
    exit 1
  fi

  subject="$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253)"
  if [[ "$subject" != "subject=CN=$common_name" ]]; then
    printf 'Unexpected conformance certificate subject: %s\n' "$subject" >&2
    exit 1
  fi

  case "$purpose" in
    server)
      if ! grep -Fq 'TLS Web Server Authentication' <<< "$cert_text"; then
        printf 'Server certificate lacks serverAuth EKU: %s\n' "$cert" >&2
        exit 1
      fi
      for hostname in auth.localhost matls-auth.localhost \
        fed-trust-anchor.localhost; do
        openssl verify -purpose sslserver -verify_hostname "$hostname" \
          -CAfile "$cert" "$cert" >/dev/null
      done
      ;;
    client)
      if ! grep -Fq 'TLS Web Client Authentication' <<< "$cert_text"; then
        printf 'Client certificate lacks clientAuth EKU: %s\n' "$cert" >&2
        exit 1
      fi
      openssl verify -purpose sslclient -CAfile "$cert" "$cert" >/dev/null
      ;;
    *)
      printf 'Unknown certificate purpose: %s\n' "$purpose" >&2
      exit 1
      ;;
  esac
}

verify_pair server auth.localhost server
verify_pair client_one client_one client
verify_pair client_two client_two client
go run "$tool_root/scripts/verify-conformance-client-tls.go" "$cert_dir"

client_one_cert="$(< "$cert_dir/client_one.crt")"$'\n'
client_one_key="$(< "$cert_dir/client_one.key")"$'\n'
client_two_cert="$(< "$cert_dir/client_two.crt")"$'\n'
client_two_key="$(< "$cert_dir/client_two.key")"$'\n'
config_count=0
mtls_count=0
mtls2_count=0
while IFS= read -r -d '' config; do
  if ! jq -e '(.mtls? != null) or (.mtls2? != null)' "$config" >/dev/null; then
    continue
  fi
  config_count=$((config_count + 1))
  if jq -e '.mtls? != null' "$config" >/dev/null; then
    mtls_count=$((mtls_count + 1))
  fi
  if jq -e '.mtls2? != null' "$config" >/dev/null; then
    mtls2_count=$((mtls2_count + 1))
  fi
  if ! jq -e \
    --arg client_one_cert "$client_one_cert" \
    --arg client_one_key "$client_one_key" \
    --arg client_two_cert "$client_two_cert" \
    --arg client_two_key "$client_two_key" '
      ((.mtls? == null) or
        (.mtls.cert == $client_one_cert and .mtls.key == $client_one_key)) and
      ((.mtls2? == null) or
        (.mtls2.cert == $client_two_cert and .mtls2.key == $client_two_key))
    ' "$config" >/dev/null; then
    printf 'Conformance config contains stale or mismatched TLS credentials: %s\n' \
      "$config" >&2
    exit 1
  fi
done < <(find "$repo_root/examples" -type f -name '*.json' -print0 | sort -z)

if (( config_count == 0 || mtls_count == 0 || mtls2_count == 0 )); then
  echo "No complete conformance mTLS configuration set was found" >&2
  exit 1
fi

printf 'Verified ephemeral conformance TLS credentials across %d configs\n' \
  "$config_count"
