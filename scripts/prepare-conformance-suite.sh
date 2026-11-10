#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
self_test=false
if [[ "${1:-}" == "--self-test" ]]; then
  self_test=true
  shift
fi
suite_dir="${1:-$repo_root/conformance-suite}"

readonly expected_commit="23353b36957d6466010de767c812d2c91ed37638"
readonly expected_runner_sha256="6043f8fb9d64dcd30235540cae1f32eb4e94618d1fc5408f1e8ae626d6553ad2"
readonly pinned_runner_sha256="f71781d4da8961ea2eb1a474aac6709710dd01072df9f362b3531ce38699f1c9"
readonly expected_requirements_sha256="05176cbcaf1a221a8943f8534d14d70c45237b3f28d055f3a55d0633d63a3085"
readonly expected_nginx_dockerfile_sha256="25c8f9a1cff410eaccfe98c460e96adb5e772d0cf1f20f9d1bb02815e7ed9f20"
readonly expected_server_dockerfile_sha256="bf8149a12accc809d2d55f6faf67859dbb59340076bb5819efd21343d5d53035"
readonly pinned_nginx_dockerfile_sha256="740378c6c5e541468a5a522da621ed900f10d2c223245b0a4bf73239d7764528"
readonly pinned_server_dockerfile_sha256="0c17eb4bd480bf785b2228785c36cd6cf900e8b2d602dbd127c0f0c30b98ff06"
readonly expected_nginx_config_sha256="a0d5fd58f15fb1cd7bae4103ee9b637e7c64a66fee18f374e6062a75e0b2acdd"
readonly pinned_nginx_config_sha256="6a135eccd81000b2d1fb21d1e6d57688a163624c00e1f71b713835fe7a79e9d6"
readonly nginx_image="nginx:1.31.8@sha256:165ddde8751e75a1c907d24ef10d9f6deb08b57e0fe56caf67512486aff76d82"
readonly temurin_image="eclipse-temurin:21@sha256:ebfbb18d11ff163ee83b21258acf12248af48d22a0fdfdc68fa1a1516c05976a"

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

prepare_terminal_log_read() {
  local root="$1"
  local runner="$root/scripts/run-test-plan.py"
  if [[ "$(sha256_file "$runner")" == "$expected_runner_sha256" ]]; then
    (cd "$root" && git apply --unidiff-zero --whitespace=error "$repo_root/scripts/conformance-terminal-log.patch")
  fi
  verify_sha256 "$runner" "$pinned_runner_sha256"
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
  mkdir "$temporary_root/scripts"
  test_runner="$temporary_root/scripts/run-test-plan.py"
  git -C "$suite_dir" show HEAD:scripts/run-test-plan.py > "$test_runner"
  prepare_terminal_log_read "$temporary_root"
  prepare_terminal_log_read "$temporary_root"
  python3 -B "$repo_root/scripts/test-conformance-terminal-log.py" "$test_runner" "$repo_root/examples/oidc/failures.json"
  printf '\n# drift\n' >> "$test_runner"
  drift_sha256="$(sha256_file "$test_runner")"
  if (prepare_terminal_log_read "$temporary_root") >/dev/null 2>&1; then
    echo "Conformance terminal log overlay accepted runner drift" >&2
    exit 1
  fi
  verify_sha256 "$test_runner" "$drift_sha256"
  exit 0
fi

requirements_file="$suite_dir/scripts/requirements.txt"
nginx_dockerfile="$suite_dir/nginx/Dockerfile-static"
server_dockerfile="$suite_dir/server-dev/Dockerfile"
nginx_config="$suite_dir/nginx/nginx-static.conf"

verify_sha256 "$requirements_file" "$expected_requirements_sha256"
prepare_nginx_config "$nginx_config"
prepare_terminal_log_read "$suite_dir"

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
