#!/usr/bin/env bash
set -euo pipefail

repository=dev-null-GmbH/go-oidc
tag=v0.25.1-d0.17
commit=c120911f6946028fcc5d1a12147789c2a2377e91
manifest_sha=d53fc4d85debd058788e6aa4671e00250a7c3a759605a87a127fbf302459d554
module_sum='h1:ImJYnAIUzG1DVWPqR4t1gdGrEY2/SPRyoCmiWNqif1w='
go_mod_sum='h1:K2WzoLZ36O8fi4Y8BIR+fcP4xL4PrKcSCQXh/bx4yi0='

root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?pass an evidence directory}
mkdir -p "$output"
output=$(cd "$output" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

test "$(git -C "$root" rev-parse "$tag^{commit}")" = "$commit"
gh release download "$tag" --repo "$repository" --dir "$scratch/assets"
test "$(sha256sum "$scratch/assets/SHA256SUMS" | cut -d' ' -f1)" = "$manifest_sha"
"$root/scripts/verify-release-assets.sh" "$tag" "$scratch/assets" "$commit"

export GOWORK=off GOMODCACHE="$scratch/gomodcache" GOTOOLCHAIN=local
export GOFLAGS='-mod=readonly -modcacherw'
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOPRIVATE= GONOPROXY= GONOSUMDB=
go mod download -json "github.com/$repository@$tag" > "$output/module.json"
jq -e --arg commit "$commit" --arg sum "$module_sum" --arg mod "$go_mod_sum" \
    '.Sum == $sum and .GoModSum == $mod and (.Origin.Hash == null or .Origin.Hash == $commit)' \
    "$output/module.json" >/dev/null

archive="go-oidc-${tag#v}.src.tar"
digests=$(sha256sum "$scratch/assets/$archive" | cut -d' ' -f1)
jq -n --arg tag "$tag" --arg commit "$commit" --arg digest "$digests" \
    --arg manifest "$manifest_sha" --arg queried_at "$(date -u +%FT%TZ)" \
    --arg go_platform "$(go env GOOS)/$(go env GOARCH)" \
    '{role: "supported distribution", tag: $tag, revision: $commit, platform: "portable Go source", scanPlatform: $go_platform,
      sourceSha256: $digest, checksumsSha256: $manifest, queriedAt: $queried_at,
      scanners: ["govulncheck 1.10.0 at vuln.go.dev", "OSV-Scanner 2.7.1 at osv.dev"]}' \
    > "$output/scope.json"

mkdir "$scratch/source"
tar -xf "$scratch/assets/$archive" --strip-components=1 -C "$scratch/source"
cd "$scratch/source"
go list -m -json all > "$output/module-graph.json"
(cd examples/vci && go list -m -json all) > "$output/vci-module-graph.json"
failed=0
govulncheck -json ./... > "$output/govulncheck.json" || failed=1
(cd examples/vci && govulncheck -json ./...) > "$output/vci-govulncheck.json" || failed=1
govulncheck ./... || failed=1
(cd examples/vci && govulncheck ./...) || failed=1
osv-scanner scan source --all-vulns --all-packages --format json --output-file "$output/osv.json" \
    -L go.mod -L examples/vci/go.mod -L requirements.txt:scripts/conformance-requirements.lock || failed=1
exit "$failed"
