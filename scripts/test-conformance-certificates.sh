#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${1:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"
temporary_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
temporary_root="$(mktemp -d "$temporary_parent/go-oidc-conformance-certs.XXXXXX")"
cleanup() {
  case "$temporary_root" in
    "$temporary_parent"/go-oidc-conformance-certs.*)
      rm -rf -- "$temporary_root"
      ;;
    *)
      echo "Refusing to clean an unexpected certificate test path" >&2
      ;;
  esac
}
trap cleanup EXIT

if ! grep -Fxq 'readonly maximum_lifetime_seconds=172800' \
  "$tool_root/scripts/verify-conformance-certificates.sh"; then
  echo "Certificate verifier must enforce the exact 48-hour lifetime ceiling" >&2
  exit 1
fi

cp -R "$source_root/examples" "$temporary_root/examples"
committed_server_fingerprint="$({
  openssl x509 -in "$temporary_root/examples/keys/server.crt" \
    -noout -fingerprint -sha256
})"

"$tool_root/scripts/generate-conformance-certificates.sh" "$temporary_root"
"$tool_root/scripts/verify-conformance-certificates.sh" \
  "$temporary_root" 43200

generated_server_fingerprint="$({
  openssl x509 -in "$temporary_root/examples/keys/server.crt" \
    -noout -fingerprint -sha256
})"
if [[ "$generated_server_fingerprint" == "$committed_server_fingerprint" ]]; then
  echo "Conformance TLS generation reused the committed server credential" >&2
  exit 1
fi

if "$tool_root/scripts/verify-conformance-certificates.sh" \
  "$temporary_root" 172800 >/dev/null 2>&1; then
  echo "Ephemeral conformance certificates must not remain valid beyond 48 hours" >&2
  exit 1
fi

overlong_output="$temporary_root/overlong-verifier.log"
openssl req -new -newkey rsa:2048 -nodes -x509 -sha256 -days 3 \
  -subj '/CN=auth.localhost' \
  -keyout "$temporary_root/examples/keys/server.key" \
  -out "$temporary_root/examples/keys/server.crt" \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -addext 'subjectAltName=DNS:auth.localhost,DNS:matls-auth.localhost,DNS:fed-trust-anchor.localhost,DNS:localhost' \
  >/dev/null 2>&1
chmod 0600 "$temporary_root/examples/keys/server.key"
chmod 0644 "$temporary_root/examples/keys/server.crt"
if "$tool_root/scripts/verify-conformance-certificates.sh" \
  "$temporary_root" 1 >"$overlong_output" 2>&1; then
  echo "Certificate verifier accepted a lifetime longer than 48 hours" >&2
  exit 1
fi
if ! grep -Fq 'lifetime exceeds 48 hours' "$overlong_output"; then
  echo "Certificate verifier rejected the overlong fixture for the wrong reason" >&2
  sed -n '1,80p' "$overlong_output" >&2
  exit 1
fi

"$tool_root/scripts/generate-conformance-certificates.sh" \
  "$temporary_root" >/dev/null

stale_config="$temporary_root/examples/fapi1_op_private_key_jarm/config.json"
temporary_config="$(mktemp "${stale_config}.XXXXXX")"
jq '.mtls.cert = "stale-certificate"' "$stale_config" > "$temporary_config"
mv -f "$temporary_config" "$stale_config"
if "$tool_root/scripts/verify-conformance-certificates.sh" \
  "$temporary_root" 1 >/dev/null 2>&1; then
  echo "Certificate verifier accepted a stale embedded conformance credential" >&2
  exit 1
fi

echo "Ephemeral conformance certificate generation rejects expiry and config drift"
