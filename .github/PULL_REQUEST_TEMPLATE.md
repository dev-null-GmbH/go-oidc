## Summary

Describe the problem, the chosen design, and any compatibility or security
impact.

## Verification

List the exact commands and conformance profiles run, with their results.

## Checklist

- [ ] Commits are cryptographically signed and use Conventional Commits.
- [ ] Tests cover success, failure, replay, and persistence ordering where relevant.
- [ ] `go test -race -shuffle=on -count=1 ./...` passes.
- [ ] `go vet ./...` and the configured linter pass.
- [ ] New GitHub Actions are pinned to full commit SHAs.
- [ ] Conformance-suite and container pins remain exact and synchronized.
- [ ] New dependencies are justified and reviewed for licenses and vulnerabilities.
- [ ] Public API or metadata changes include compatibility and conformance evidence.
- [ ] Fork-only patches and upstream-sync implications are documented.
