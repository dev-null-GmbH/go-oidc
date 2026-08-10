#!/usr/bin/env bash

set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${RELEASE_SOURCE_ROOT:-$tool_root}"
source_root="$(cd "$source_root" && pwd)"
cd "$source_root"

readonly expected_version="release-v5.2.2"
readonly expected_commit="321bc5bc53601b9690b54c023c0cbfac0f0230f2"
readonly expected_python="3.14.6"
readonly expected_maven_image="maven:3.9.16-eclipse-temurin-21@sha256:c07f7ccfb8ca6c9fa29ee523f00afa7d2ca6132c92f8652c4aebb5ee3491f502"
readonly expected_mongo_image="mongo:6.0.13@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070"
readonly expected_nginx_image="nginx:1.27.3@sha256:bc2f6a7c8ddbccf55bdb19659ce3b0a92ca6559e86d42677a5a02ef6bda2fcef"
readonly expected_temurin_image="eclipse-temurin:21@sha256:efd34b940f2d5a621605c8531c2afb7759c936b6c2ef637a69aa3bf3e1e789d1"
readonly expected_cache_schema="v3-dependencies-only"

make_value() {
  awk -v key="$1" '$1 == key && $2 == "=" { print $3; exit }' Makefile
}

workflow_value() {
  awk -v key="$1:" '$1 == key { gsub(/"/, "", $2); print $2; exit }' \
    .github/workflows/conformance.yml
}

require_literal() {
  local file="$1"
  local literal="$2"

  if ! grep -Fq -- "$literal" "$file"; then
    printf '%s does not contain required pinned input: %s\n' \
      "$file" "$literal" >&2
    exit 1
  fi
}

make_version="$(make_value CS_VERSION)"
make_commit="$(make_value CS_COMMIT)"
make_maven_image="$(make_value CS_MAVEN_IMAGE)"
workflow_version="$(workflow_value CS_VERSION)"
workflow_commit="$(workflow_value CS_COMMIT)"
workflow_maven_image="$(workflow_value CS_MAVEN_IMAGE)"
workflow_python="$(workflow_value PYTHON_VERSION)"
workflow_cache_schema="$(workflow_value CS_CACHE_SCHEMA)"

if [[ "$make_version" != "$expected_version" || \
      "$workflow_version" != "$expected_version" ]]; then
  printf 'Conformance version must be %s (Makefile=%s workflow=%s)\n' \
    "$expected_version" "$make_version" "$workflow_version" >&2
  exit 1
fi
if [[ "$make_commit" != "$expected_commit" || \
      "$workflow_commit" != "$expected_commit" ]]; then
  printf 'Conformance commit must be %s (Makefile=%s workflow=%s)\n' \
    "$expected_commit" "$make_commit" "$workflow_commit" >&2
  exit 1
fi
if [[ "$workflow_python" != "$expected_python" ]]; then
  printf 'Conformance Python must be %s, got %s\n' \
    "$expected_python" "$workflow_python" >&2
  exit 1
fi
if [[ "$workflow_cache_schema" != "$expected_cache_schema" ]]; then
  printf 'Conformance cache schema must be %s, got %s\n' \
    "$expected_cache_schema" "$workflow_cache_schema" >&2
  exit 1
fi
if [[ "$make_maven_image" != "$expected_maven_image" || \
      "$workflow_maven_image" != "$expected_maven_image" ]]; then
  printf 'Conformance Maven image drift: expected %s (Makefile=%s workflow=%s)\n' \
    "$expected_maven_image" "$make_maven_image" "$workflow_maven_image" >&2
  exit 1
fi

require_literal .github/workflows/conformance.yml "$expected_maven_image"
require_literal docker-compose.yml "$expected_mongo_image"
require_literal scripts/prepare-conformance-suite.sh "$expected_commit"
require_literal scripts/prepare-conformance-suite.sh "$expected_nginx_image"
require_literal scripts/prepare-conformance-suite.sh "$expected_temurin_image"
require_literal .github/workflows/conformance.yml \
  "hashFiles('scripts/conformance-requirements.lock', 'scripts/prepare-conformance-suite.sh', 'docker-compose.yml', 'Makefile')"
require_literal .github/workflows/conformance.yml \
  "./scripts/prepare-conformance-suite.sh conformance-suite"
require_literal .github/workflows/conformance.yml \
  "./scripts/generate-conformance-certificates.sh"
require_literal .github/workflows/conformance.yml \
  '${{ env.MAVEN_CACHE_DIR }}'
require_literal .github/workflows/conformance.yml \
  '${{ env.PIP_CACHE_DIR }}'
require_literal Makefile "./scripts/prepare-conformance-suite.sh conformance-suite"
require_literal Makefile "./scripts/generate-conformance-certificates.sh"

if grep -Eq '^[[:space:]]+path:[[:space:]]+conformance-suite$' \
  .github/workflows/conformance.yml; then
  echo "Conformance checkout, venv, and JAR must never be restored from cache" >&2
  exit 1
fi
if [[ "$(grep -c 'git init --quiet conformance-suite' \
  .github/workflows/conformance.yml)" -lt 2 ||
      "$(grep -c 'mvn -B clean package -DskipTests=true' \
  .github/workflows/conformance.yml)" -lt 2 ]]; then
  echo "Every conformance phase must use a fresh checkout and rebuilt JAR" >&2
  exit 1
fi

if [[ "$(grep -Fc 'for attempt in 1 2 3 4; do' \
  .github/workflows/conformance.yml)" != "2" ||
      "$(grep -Fc 'timeout --kill-after=10s 120s docker pull "$CS_MAVEN_IMAGE"' \
  .github/workflows/conformance.yml)" != "2" ||
      "$(grep -Fc 'docker run --rm --pull=never \' \
  .github/workflows/conformance.yml)" != "2" ]]; then
  echo "Every conformance phase must use the bounded pinned-image pull contract" >&2
  exit 1
fi

certificate_generation_line="$(
  grep -nF './scripts/generate-conformance-certificates.sh' \
    .github/workflows/conformance.yml | cut -d: -f1
)"
suite_start_line="$(
  grep -nF 'docker compose up --build --detach' \
    .github/workflows/conformance.yml | cut -d: -f1
)"
server_start_line="$(
  grep -nF 'sudo "$go_binary" run' .github/workflows/conformance.yml |
    cut -d: -f1
)"
test_start_line="$(
  grep -nF 'run: make "cs-${{ matrix.profile }}-tests"' \
    .github/workflows/conformance.yml | cut -d: -f1
)"
if [[ ! "$certificate_generation_line" =~ ^[0-9]+$ ||
      ! "$suite_start_line" =~ ^[0-9]+$ ||
      ! "$server_start_line" =~ ^[0-9]+$ ||
      ! "$test_start_line" =~ ^[0-9]+$ ||
      "$certificate_generation_line" -ge "$suite_start_line" ||
      "$suite_start_line" -ge "$server_start_line" ||
      "$server_start_line" -ge "$test_start_line" ]]; then
  echo "Ephemeral TLS generation must precede suite, server, and test execution" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*(version:|links:)' docker-compose.yml; then
  echo "docker-compose.yml contains obsolete version or links configuration" >&2
  exit 1
fi
if grep -E '^[[:space:]]*image:' docker-compose.yml | grep -Ev '@sha256:[0-9a-f]{64}$'; then
  echo "Every Compose image must be pinned to a SHA-256 digest" >&2
  exit 1
fi

if ! grep -Fqx 'httpx==0.28.1 \' scripts/conformance-requirements.lock || \
   ! grep -Fqx 'pyparsing==3.3.2 \' scripts/conformance-requirements.lock; then
  echo "Direct conformance Python dependencies are not pinned as reviewed" >&2
  exit 1
fi

if ! awk '
  /^[[:alnum:]_.-]+==/ {
    if (in_requirement && hash_count == 0) exit 1
    in_requirement = 1
    hash_count = 0
    next
  }
  /--hash=sha256:/ {
    digest = $0
    sub(/^.*--hash=sha256:/, "", digest)
    sub(/[[:space:]\\].*$/, "", digest)
    if (!in_requirement || digest !~ /^[0-9a-f]{64}$/) exit 1
    hash_count++
  }
  END {
    if (!in_requirement || hash_count == 0) exit 1
  }
' scripts/conformance-requirements.lock; then
  echo "Every locked Python dependency must have a valid SHA-256 hash" >&2
  exit 1
fi

printf 'Conformance inputs are immutable and consistent at %s (%s)\n' \
  "$expected_version" "$expected_commit"
