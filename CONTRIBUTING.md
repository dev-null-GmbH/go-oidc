# Contributing to the d0 governed fork

Thank you for improving `dev-null-GmbH/go-oidc`. This fork carries targeted
runtime and security patches needed by d0 services while preserving a clear
relationship to [the upstream project](https://github.com/luikyv/go-oidc).
Changes should remain narrowly reviewable, standards-based, and suitable for
upstream contribution where their contracts are generally useful.

## Before starting

- Report security issues through the private process in [SECURITY.md](SECURITY.md).
- Discuss broad public API, storage-contract, cryptographic, or protocol changes
  in an issue before implementation.
- Do not add a runtime dependency without an explicit design and security
  review. Prefer the standard library and existing dependencies.
- Keep fork-only behavior behind explicit, typed APIs. Do not silently change
  upstream defaults for existing consumers.

## Development

Use the Go version declared in `go.mod`; CI reads the same file. Keep changes
formatted with `gofmt`, add tests before or alongside behavior changes, and
exercise error and concurrency paths as carefully as success paths.

At minimum, run:

```sh
go test -race -shuffle=on -count=1 ./...
go vet ./...
golangci-lint run ./pkg/... ./internal/... ./examples/...
(cd examples/vci && go test -race -shuffle=on -count=1 ./...)
(cd examples/vci && go vet ./...)
./scripts/verify-action-pins.sh
./scripts/verify-conformance-pin.sh
```

Protocol or metadata changes also require the applicable OpenID conformance
profiles. Include exact commands and results in the pull request. Tests for
replay stores, client assertions, DPoP, and issuance must verify that failures
cannot persist partial state or trigger signing/side effects out of order.

## Commits and pull requests

- Use small
  [Conventional Commits](https://www.conventionalcommits.org/) with an
  imperative summary.
- Cryptographically sign every commit. Release commits and annotated tags must
  show a verified signature.
- Do not add automated-tool or AI co-author trailers. The person accepting the
  change remains responsible for its contents.
- Explain compatibility, security, storage, and standards impact.
- Link upstream issues or pull requests when a patch is intended for upstream.
- Keep GitHub Actions pinned to audited full commit SHAs with the corresponding
  release version in an inline comment.

Pull requests require `CODEOWNERS` review. Security-critical changes should be
reviewed independently by both named maintainers whenever practical, and all
required checks must pass before merge.

## Upstream and release discipline

Do not rebase or rewrite released fork history. Upstream synchronization uses
a dedicated reviewed branch, an exact upstream commit, an updated patch
inventory, and complete requalification. Follow
[the release policy](.github/RELEASE_POLICY.md) for version selection,
signatures, SBOMs, provenance, immutability, and rollback.

## License

Contributions are accepted under the repository's MIT license. Preserve the
upstream copyright and license notice. By contributing, you represent that you
have the right to submit the work under those terms.
