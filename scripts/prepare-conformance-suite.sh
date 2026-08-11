#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
suite_dir="${1:-$repo_root/conformance-suite}"

readonly expected_commit="321bc5bc53601b9690b54c023c0cbfac0f0230f2"
readonly expected_requirements_sha256="05176cbcaf1a221a8943f8534d14d70c45237b3f28d055f3a55d0633d63a3085"
readonly expected_nginx_dockerfile_sha256="25c8f9a1cff410eaccfe98c460e96adb5e772d0cf1f20f9d1bb02815e7ed9f20"
readonly expected_server_dockerfile_sha256="bf8149a12accc809d2d55f6faf67859dbb59340076bb5819efd21343d5d53035"
readonly pinned_nginx_dockerfile_sha256="ca80ada40974398576c2f8f0e17466023f368f0eaa3c0d7ef1939002b0e6eb95"
readonly pinned_server_dockerfile_sha256="37969f1def503093970455de848c2b115483149f0ea160f98d614f29eb80d9e3"
readonly nginx_image="nginx:1.27.3@sha256:bc2f6a7c8ddbccf55bdb19659ce3b0a92ca6559e86d42677a5a02ef6bda2fcef"
readonly temurin_image="eclipse-temurin:21@sha256:efd34b940f2d5a621605c8531c2afb7759c936b6c2ef637a69aa3bf3e1e789d1"

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

requirements_file="$suite_dir/scripts/requirements.txt"
nginx_dockerfile="$suite_dir/nginx/Dockerfile-static"
server_dockerfile="$suite_dir/server-dev/Dockerfile"

verify_sha256 "$requirements_file" "$expected_requirements_sha256"

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
