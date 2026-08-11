#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

archives_dir="$temporary_root/archives"
fixture_dir="$temporary_root/fixture"
evidence_file="$temporary_root/RELEASE-EVIDENCE.json"
mkdir -p "$archives_dir" "$fixture_dir"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

printf '{"result":"PASSED"}\n' > "$fixture_dir/result.json"
printf 'test signature\n' > "$fixture_dir/result.sig"
(
  cd "$fixture_dir"
  zip -q export.zip result.json result.sig
)
printf 'ephemeral authorization-server log\n' > "$fixture_dir/auth-server.log"

profiles=(
  oidc
  fapi2-sp-op-mtls-mtls
  fapi2-sp-op-mtls-dpop
  fapi2-sp-op-private-key-mtls
  fapi2-ms-op-jar
  fapi2-ms-op-jarm
  fapi2-sp-op-private-key-dpop
  fapi1-op-mtls
  fapi1-op-mtls-jarm
  fapi1-op-mtls-par
  fapi1-op-mtls-par-jarm
  fapi1-op-private-key
  fapi1-op-private-key-jarm
  fapi1-op-private-key-par
  fapi1-op-private-key-par-jarm
  fapiciba
  federation
)

release_commit='0123456789abcdef0123456789abcdef01234567'
conformance_run_id=103
profile_records=()
artifact_id=1000
for profile in "${profiles[@]}"; do
  archive="$archives_dir/$artifact_id.zip"
  (
    cd "$fixture_dir"
    zip -q -j "$archive" export.zip auth-server.log
  )
  archive_size="$(wc -c < "$archive")"
  archive_size="${archive_size//[[:space:]]/}"
  archive_digest="sha256:$(sha256_file "$archive")"
  profile_records+=("$(
    jq -n \
      --arg profile "$profile" \
      --arg commit "$release_commit" \
      --arg digest "$archive_digest" \
      --argjson id "$artifact_id" \
      --argjson run_id "$conformance_run_id" \
      --argjson size "$archive_size" '
      {
        profile: $profile,
        artifact: {
          id: $id,
          name: ("conformance-" + $profile + "-" + ($run_id | tostring)),
          sizeInBytes: $size,
          digest: $digest,
          expired: false,
          headSha: $commit
        }
      }'
  )")
  artifact_id=$((artifact_id + 1))
done
profiles_json="$(printf '%s\n' "${profile_records[@]}" | jq -s 'sort_by(.profile)')"

jq -n \
  --arg commit "$release_commit" \
  --argjson run_id "$conformance_run_id" \
  --argjson profiles "$profiles_json" '
  {
    schemaVersion: 2,
    repository: "dev-null-GmbH/go-oidc",
    releaseCommit: $commit,
    conformance: {
      aggregateCheck: {workflow: {id: $run_id}},
      profiles: $profiles
    }
  }' > "$evidence_file"

bundle_one="$temporary_root/CONFORMANCE-EVIDENCE-one.tar"
bundle_two="$temporary_root/CONFORMANCE-EVIDENCE-two.tar"
go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$evidence_file" \
  -archives-dir "$archives_dir" \
  -bundle "$bundle_one"
go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$evidence_file" \
  -archives-dir "$archives_dir" \
  -bundle "$bundle_two"
cmp "$bundle_one" "$bundle_two"
go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode verify \
  -evidence "$evidence_file" \
  -bundle "$bundle_one"

fake_bin="$temporary_root/fake-bin"
mkdir -p "$fake_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ " $* " != *" Accept: application/vnd.github+json "* ]]; then' \
  '  echo "artifact download did not use the supported JSON media type" >&2' \
  '  exit 1' \
  'fi' \
  'endpoint="${!#}"' \
  'artifact_id="${endpoint%/zip}"' \
  'artifact_id="${artifact_id##*/}"' \
  'if [[ ! "$artifact_id" =~ ^[1-9][0-9]*$ ]]; then' \
  '  echo "invalid artifact endpoint" >&2' \
  '  exit 1' \
  'fi' \
  'command cat "$FAKE_ARCHIVES_DIR/$artifact_id.zip"' \
  > "$fake_bin/gh"
chmod 0755 "$fake_bin/gh"
downloaded_bundle="$temporary_root/CONFORMANCE-EVIDENCE-downloaded.tar"
GH_TOKEN=fake \
FAKE_ARCHIVES_DIR="$archives_dir" \
PATH="$fake_bin:$PATH" \
  "$tool_root/scripts/download-conformance-evidence.sh" \
    "$evidence_file" "$downloaded_bundle"
cmp "$bundle_one" "$downloaded_bundle"

ln -s "$evidence_file" "$temporary_root/evidence-link.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/evidence-link.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/symlink-evidence.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted a symlinked release-evidence file" >&2
  exit 1
fi

oversized_evidence="$temporary_root/oversized-evidence.json"
cp "$evidence_file" "$oversized_evidence"
dd if=/dev/zero bs=1048576 count=17 2>/dev/null | \
  tr '\000' ' ' >> "$oversized_evidence"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$oversized_evidence" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/oversized-evidence.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted release evidence larger than 16 MiB" >&2
  exit 1
fi

jq '(.conformance.profiles[0].artifact.sizeInBytes) = 134217729' \
  "$evidence_file" > "$temporary_root/oversized-artifact.json"
if oversized_error="$(
  go run "$tool_root/scripts/conformance-evidence-bundle.go" \
    -mode pack \
    -evidence "$temporary_root/oversized-artifact.json" \
    -archives-dir "$archives_dir" \
    -bundle "$temporary_root/oversized-artifact.tar" 2>&1
)"; then
  echo "Conformance bundle accepted an oversized compressed artifact" >&2
  exit 1
fi
if [[ "$oversized_error" != *"128 MiB"* ]]; then
  echo "Conformance bundle did not enforce the per-artifact compressed limit" >&2
  exit 1
fi

empty_log_archive="$temporary_root/empty-log.zip"
: > "$fixture_dir/auth-server.log"
(
  cd "$fixture_dir"
  zip -q -j "$empty_log_archive" export.zip auth-server.log
)
printf 'ephemeral authorization-server log\n' > "$fixture_dir/auth-server.log"
empty_log_size="$(wc -c < "$empty_log_archive")"
empty_log_size="${empty_log_size//[[:space:]]/}"
empty_log_digest="sha256:$(sha256_file "$empty_log_archive")"
cp "$archives_dir/1000.zip" "$temporary_root/valid-1000.zip"
cp "$empty_log_archive" "$archives_dir/1000.zip"
jq \
  --arg digest "$empty_log_digest" \
  --argjson size "$empty_log_size" \
  '(.conformance.profiles[] | select(.artifact.id == 1000).artifact) |=
    (.digest = $digest | .sizeInBytes = $size)' \
  "$evidence_file" > "$temporary_root/empty-log-evidence.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/empty-log-evidence.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/empty-log.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted an empty authorization-server log" >&2
  exit 1
fi
mv "$temporary_root/valid-1000.zip" "$archives_dir/1000.zip"

ln -s result.json "$fixture_dir/result-link"
unsafe_archive="$temporary_root/unsafe-outer.zip"
(
  cd "$fixture_dir"
  zip -q -y -j "$unsafe_archive" export.zip auth-server.log result-link
)
unsafe_size="$(wc -c < "$unsafe_archive")"
unsafe_size="${unsafe_size//[[:space:]]/}"
unsafe_digest="sha256:$(sha256_file "$unsafe_archive")"
cp "$archives_dir/1000.zip" "$temporary_root/valid-1000.zip"
cp "$unsafe_archive" "$archives_dir/1000.zip"
jq \
  --arg digest "$unsafe_digest" \
  --argjson size "$unsafe_size" \
  '(.conformance.profiles[] | select(.artifact.id == 1000).artifact) |=
    (.digest = $digest | .sizeInBytes = $size)' \
  "$evidence_file" > "$temporary_root/unsafe-outer-evidence.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/unsafe-outer-evidence.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/unsafe-outer.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted a symlink in an Actions artifact ZIP" >&2
  exit 1
fi

unsafe_export="$fixture_dir/unsafe-export.zip"
unsafe_inner_archive="$temporary_root/unsafe-inner.zip"
(
  cd "$fixture_dir"
  zip -q -y "$unsafe_export" result.json result.sig result-link
  zip -q -j "$unsafe_inner_archive" unsafe-export.zip auth-server.log
)
unsafe_size="$(wc -c < "$unsafe_inner_archive")"
unsafe_size="${unsafe_size//[[:space:]]/}"
unsafe_digest="sha256:$(sha256_file "$unsafe_inner_archive")"
cp "$unsafe_inner_archive" "$archives_dir/1000.zip"
jq \
  --arg digest "$unsafe_digest" \
  --argjson size "$unsafe_size" \
  '(.conformance.profiles[] | select(.artifact.id == 1000).artifact) |=
    (.digest = $digest | .sizeInBytes = $size)' \
  "$evidence_file" > "$temporary_root/unsafe-inner-evidence.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/unsafe-inner-evidence.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/unsafe-inner.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted a symlink in an exported evidence ZIP" >&2
  exit 1
fi

printf 'mismatched signature\n' > "$fixture_dir/other.sig"
mismatched_export="$fixture_dir/mismatched-export.zip"
mismatched_archive="$temporary_root/mismatched-pair.zip"
(
  cd "$fixture_dir"
  zip -q "$mismatched_export" result.json other.sig
  zip -q -j "$mismatched_archive" mismatched-export.zip auth-server.log
)
unsafe_size="$(wc -c < "$mismatched_archive")"
unsafe_size="${unsafe_size//[[:space:]]/}"
unsafe_digest="sha256:$(sha256_file "$mismatched_archive")"
cp "$mismatched_archive" "$archives_dir/1000.zip"
jq \
  --arg digest "$unsafe_digest" \
  --argjson size "$unsafe_size" \
  '(.conformance.profiles[] | select(.artifact.id == 1000).artifact) |=
    (.digest = $digest | .sizeInBytes = $size)' \
  "$evidence_file" > "$temporary_root/mismatched-pair-evidence.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/mismatched-pair-evidence.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/mismatched-pair.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted mismatched JSON and signature paths" >&2
  exit 1
fi
mv "$temporary_root/valid-1000.zip" "$archives_dir/1000.zip"

missing_archive="$archives_dir/1000.zip"
mv "$missing_archive" "$temporary_root/missing.zip"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$evidence_file" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/missing.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted a missing artifact archive" >&2
  exit 1
fi
mv "$temporary_root/missing.zip" "$missing_archive"

cp "$missing_archive" "$temporary_root/valid.zip"
printf 'tamper\n' >> "$missing_archive"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$evidence_file" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/tampered-input.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted artifact bytes outside the recorded digest" >&2
  exit 1
fi
mv "$temporary_root/valid.zip" "$missing_archive"

jq '.conformance.profiles += [.conformance.profiles[0]]' \
  "$evidence_file" > "$temporary_root/duplicate-evidence.json"
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode pack \
  -evidence "$temporary_root/duplicate-evidence.json" \
  -archives-dir "$archives_dir" \
  -bundle "$temporary_root/duplicate.tar" >/dev/null 2>&1; then
  echo "Conformance bundle accepted duplicate profile evidence" >&2
  exit 1
fi

cp "$bundle_one" "$temporary_root/tampered-bundle.tar"
printf 'X' | dd of="$temporary_root/tampered-bundle.tar" \
  bs=1 seek=512 conv=notrunc 2>/dev/null
if go run "$tool_root/scripts/conformance-evidence-bundle.go" \
  -mode verify \
  -evidence "$evidence_file" \
  -bundle "$temporary_root/tampered-bundle.tar" >/dev/null 2>&1; then
  echo "Conformance bundle verifier accepted a tampered internal manifest" >&2
  exit 1
fi

echo "Conformance evidence bundle is deterministic and rejects incomplete or altered archives"
