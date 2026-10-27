#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
self_test=false
if [[ "${1:-}" == "--self-test" ]]; then
  self_test=true
  shift
fi
suite_dir="${1:-$repo_root/conformance-suite}"

readonly expected_commit="7d420f716e49d44f8a6b04f0a3e240ad6d68ab55"
readonly expected_requirements_sha256="05176cbcaf1a221a8943f8534d14d70c45237b3f28d055f3a55d0633d63a3085"
readonly expected_nginx_dockerfile_sha256="25c8f9a1cff410eaccfe98c460e96adb5e772d0cf1f20f9d1bb02815e7ed9f20"
readonly expected_server_dockerfile_sha256="bf8149a12accc809d2d55f6faf67859dbb59340076bb5819efd21343d5d53035"
readonly pinned_nginx_dockerfile_sha256="3282bc953da1148d1b8cb9f2bb3f532f8e8e22699a6827c2126aa4843f9393a1"
readonly pinned_server_dockerfile_sha256="c5b560e429286131f89f5c6261b757a71d4cb891e765532f83b1b55fba9c9761"
readonly expected_nginx_config_sha256="a0d5fd58f15fb1cd7bae4103ee9b637e7c64a66fee18f374e6062a75e0b2acdd"
readonly pinned_nginx_config_sha256="6a135eccd81000b2d1fb21d1e6d57688a163624c00e1f71b713835fe7a79e9d6"
readonly nginx_image="nginx:1.31.5@sha256:05b8cb60c354a44ab824ea6e7dc69b46d50762cdbe728a347a5b656e6fb3d7c4"
readonly temurin_image="eclipse-temurin:21@sha256:85f00967bcc624fc19fa9c2cf124ea426a5363898e267141726f31f358c2e14b"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual

  actual="$(sha256_file "$file")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'Unexpected SHA-256 for %s: expected %s, got %s\n' \
      "$file" "$expected" "$actual" >&2
    exit 1
  fi
}

replace_from() {
  local file="$1"
  local original="$2"
  local pinned="$3"
  local temporary

  if [[ "$(grep -Fxc "FROM $original" "$file")" != "1" ]]; then
    printf 'Expected exactly one FROM %s line in %s\n' "$original" "$file" >&2
    exit 1
  fi

  temporary="$(mktemp "${file}.XXXXXX")"
  awk -v original="FROM $original" -v pinned="FROM $pinned" \
    '{ if ($0 == original) print pinned; else print }' \
    "$file" > "$temporary"
  mv "$temporary" "$file"
}

prepare_nginx_config() {
  local file="$1"
  local actual
  local temporary

  actual="$(sha256_file "$file")"
  if [[ "$actual" == "$expected_nginx_config_sha256" ]]; then
    temporary="$(mktemp "${file}.XXXXXX")"
    awk '
      { print }
      /^        listen (8443|8444|8445) ssl;$/ {
        sub(/listen /, "listen [::]:")
        sub(/ ssl;/, " ssl ipv6only=on;")
        print
      }
    ' "$file" > "$temporary"
    verify_sha256 "$temporary" "$pinned_nginx_config_sha256"
    mv "$temporary" "$file"
  else
    verify_sha256 "$file" "$pinned_nginx_config_sha256"
  fi
}

if [[ ! -d "$suite_dir/.git" ]]; then
  printf '%s is not a conformance-suite Git checkout\n' "$suite_dir" >&2
  exit 1
fi

actual_commit="$(git -C "$suite_dir" rev-parse HEAD)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
  printf 'Expected conformance suite %s, got %s\n' \
    "$expected_commit" "$actual_commit" >&2
  exit 1
fi

if "$self_test"; then
  temporary_root="$(mktemp -d)"
  trap 'rm -rf -- "$temporary_root"' EXIT
  test_config="$temporary_root/nginx-static.conf"
  git -C "$suite_dir" show HEAD:nginx/nginx-static.conf > "$test_config"
  verify_sha256 "$test_config" "$expected_nginx_config_sha256"
  prepare_nginx_config "$test_config"
  prepare_nginx_config "$test_config"
  for port in 8443 8444 8445; do
    grep -Fqx "        listen $port ssl;" "$test_config"
    grep -Fqx "        listen [::]:$port ssl ipv6only=on;" "$test_config"
  done
  printf '\n# drift\n' >> "$test_config"
  drift_sha256="$(sha256_file "$test_config")"
  if (prepare_nginx_config "$test_config") >/dev/null 2>&1; then
    echo "Conformance nginx overlay accepted configuration drift" >&2
    exit 1
  fi
  verify_sha256 "$test_config" "$drift_sha256"
  echo "Conformance nginx overlay is dual-stack, idempotent, and rejects drift"
  exit 0
fi

requirements_file="$suite_dir/scripts/requirements.txt"
nginx_dockerfile="$suite_dir/nginx/Dockerfile-static"
server_dockerfile="$suite_dir/server-dev/Dockerfile"
nginx_config="$suite_dir/nginx/nginx-static.conf"

verify_sha256 "$requirements_file" "$expected_requirements_sha256"
prepare_nginx_config "$nginx_config"

nginx_dockerfile_sha256="$(sha256_file "$nginx_dockerfile")"
server_dockerfile_sha256="$(sha256_file "$server_dockerfile")"
if [[ "$nginx_dockerfile_sha256" == "$expected_nginx_dockerfile_sha256" && \
      "$server_dockerfile_sha256" == "$expected_server_dockerfile_sha256" ]]; then
  replace_from "$nginx_dockerfile" "nginx:1.27.3" "$nginx_image"
  replace_from "$server_dockerfile" "eclipse-temurin:21" "$temurin_image"
elif [[ "$nginx_dockerfile_sha256" != "$pinned_nginx_dockerfile_sha256" || \
        "$server_dockerfile_sha256" != "$pinned_server_dockerfile_sha256" ]]; then
  echo "Conformance-suite Dockerfile content is neither pristine nor pinned" >&2
  exit 1
fi

verify_sha256 "$nginx_dockerfile" "$pinned_nginx_dockerfile_sha256"
verify_sha256 "$server_dockerfile" "$pinned_server_dockerfile_sha256"
grep -Fqx "FROM $nginx_image" "$nginx_dockerfile"
grep -Fqx "FROM $temurin_image" "$server_dockerfile"

python3 -m venv --clear "$suite_dir/venv"
"$suite_dir/venv/bin/python3" -m pip install \
  --disable-pip-version-check \
  --only-binary=:all: \
  --quiet \
  --require-hashes \
  --requirement "$repo_root/scripts/conformance-requirements.lock"
"$suite_dir/venv/bin/python3" -m pip check

printf 'Prepared pinned conformance suite %s\n' "$actual_commit"
