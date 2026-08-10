# Governed fork release policy

This policy applies to releases made by `/dev/null GmbH` from
`dev-null-GmbH/go-oidc`. It does not alter the upstream project's release or
certification practices.

## Version identity

Fork releases use `v<upstream-major>.<upstream-minor>.<patch>-d0.<revision>`.
The first release based on upstream `v0.25.0` is `v0.25.1-d0.1`. The fork has
a distinct module path, so it does not collide with upstream under Minimal
Version Selection. However, `v0.25.1-d0.1` is a prerelease, while the copied
upstream `v0.25.0` tag is stable and declares the old upstream module path.
Consumers **must** exact-pin `v0.25.1-d0.1` (or a later governed fork tag) and
must not use `@latest`. A released version is never rebuilt, retagged, or
reused.

Every release records:

- the exact upstream tag and commit in `NOTICE`;
- the fork commit and complete fork-only patch inventory;
- the Go toolchain from `go.mod` and the conformance-suite revision;
- checksums, an SPDX SBOM covering every shipped Go module, and build
  provenance for every primary generated payload asset;
- retained machine-readable CI, review, vulnerability, CodeQL, dependency,
  and OpenID conformance evidence bound to the release commit.

## Release requirements

GitHub release immutability must be enabled **before the first release is
created**. The setting applies only to future releases, so enabling it after a
release is published does not protect that release. Tags and immutable
releases are never deleted or rewritten to conceal a defect.

The protected repository uses squash-only merges. The pull request's current
author head must be signed and GitHub-verified. GitHub must separately report
the exact squash release commit as validly signed and verified; the release
workflow retains both verification records, the merged pull request,
current-head approval, dependency review, and required check evidence. The
annotated release tag is separately signed by a principal in
`.github/release-signers`. This makes the reviewed merge path achievable
without assuming that GitHub's squash commit can be verified by a maintainer's
local SSH key.

Every release follows this order:

1. Before any release tag exists, enable immutable releases and the audited
   branch, tag, Actions, security, and merge controls below. The active
   `Governed tag creation` ruleset targets `refs/tags/v*-d0.*`, contains only
   the creation restriction, and has exactly the named release maintainers
   (`greg6775` user ID `33130539` and `Schlauer-Hax` user ID `32987311`) as
   bypass actors. A separate `Protect governed release tags` ruleset has no
   bypass actors and blocks update and deletion while requiring verified
   commits. Splitting the rulesets lets authorized maintainers create a tag
   without allowing anyone to move or delete it.
2. Squash-merge the approved release pull request to protected `main`. All
   required checks must pass for the exact GitHub-verified squash commit. The
   dependency review must pass on the pull request's current head, and a named
   maintainer other than the author must approve that same head. Security- or
   protocol-relevant changes require the full conformance matrix; waivers must
   be explicit, time-bounded, and approved by both maintainers.
3. An authorized release maintainer creates and pushes a signed annotated tag
   whose embedded name and direct commit object exactly match the requested
   release identity. The tag is never updated, replayed under another name, or
   deleted.
4. Send the `governed-release-prepare` repository dispatch with the exact tag,
   40-character commit, and confirmation `prepare <tag>@<commit>` using the
   command below. Unlike `workflow_dispatch`, `repository_dispatch` always
   loads the workflow from the default branch; the release workflow has no
   branch- or tag-loaded trigger. The webhook sender login and numeric user ID
   must be exactly one of the two named release maintainers, and it must match
   `github.actor`; an app or any other Actions-capable actor cannot initiate a
   release. Preparation must run while that commit is default-branch HEAD. The
   first job is read-only and checks the trusted default-branch
   workflow/tooling revision, tag-object identity and allowlisted tag
   signature, GitHub-verified commit, ancestry, reviewed pull request, the
   exact configured GitHub-Actions-sourced required-check set, and conformance
   artifacts. Only dependent write-capable jobs may proceed.

   ```sh
   gh api --method POST repos/dev-null-GmbH/go-oidc/dispatches \
     -f event_type=governed-release-prepare \
     -F "client_payload[tag]=$tag" \
     -F "client_payload[commit]=$commit" \
     -F "client_payload[confirm]=prepare $tag@$commit"
   ```
5. The preparation job keeps trusted scripts/signers and the release tree in
   separate checkouts, revalidates the qualification, and generates a
   deterministic source archive, complete patch inventory, release manifest,
   retained release evidence, strict SHA-256 manifest, multi-module SPDX SBOM,
   and GitHub provenance/SBOM bundles. It uploads all nine assets to an
   unpublished **draft prerelease** and never publishes it.
6. Independently inspect the draft. Then send the trusted default-branch
   `governed-release-publish` repository dispatch with confirmation
   `publish <tag>@<commit>`. It repeats qualification, downloads and strictly
   verifies the exact draft asset set by asset ID, size, server SHA-256 digest,
   and downloaded bytes; regenerates and compares current release evidence and
   all deterministic primary payloads; verifies both attestation bundles; and
   re-audits governance immediately before publication. After environment
   approval, one final shell step re-fetches the complete release body/state
   and asset inventory, compares it with the verified snapshot, re-downloads
   and re-hashes every asset by immutable asset ID, runs the strict asset
   verifier, and re-fetches the body/state plus complete paginated inventory
   one last time. The final snapshot comparison is immediately followed by the
   publication request, which also rewrites the verified title, body, tag, and
   prerelease state. It then requires the now-immutable release and frozen
   asset inventory to equal the verified snapshot. Corrections require a new
   signed tag and release.

   GitHub does not document conditional `If-Match` support for the release
   `PATCH`; its REST guidance says conditional unsafe methods are unsupported
   unless an endpoint explicitly opts in. GitHub also provides no transactional
   compare-and-publish operation for drafts. Therefore an administrator race in
   the final network interval cannot be excluded atomically. The post-publish
   immutable-inventory comparison detects such a race in the workflow, while
   the retained provenance/SBOM bundles and strict checksum verification let
   consumers reject unauthorized or incomplete bytes. This is a detectable
   residual platform risk, not an atomicity guarantee.

   The publish job targets the protected `governed-release` environment. Its
   required reviewers are exactly `greg6775` and `Schlauer-Hax`; GitHub needs
   one approval, prevents the dispatching actor from self-approving, disallows
   administrator bypass, and permits only `main`. Therefore one maintainer
   sends the publish dispatch and the other approves the waiting environment
   deployment before any publish step or job token becomes available.

   ```sh
   gh api --method POST repos/dev-null-GmbH/go-oidc/dispatches \
     -f event_type=governed-release-publish \
     -F "client_payload[tag]=$tag" \
     -F "client_payload[commit]=$commit" \
     -F "client_payload[confirm]=publish $tag@$commit"
   ```

Build inputs must be immutable: exact module versions, action SHAs, container
digests, hashed Python dependencies, and external-suite commits. Release jobs
receive only the minimum write permissions needed for their operation. The
prepare run is dispatched from `refs/heads/main` at the exact release commit,
so GitHub artifact attestations bind each primary generated payload (including
`RELEASE-EVIDENCE.json`) to the trusted workflow, repository, and release
commit. `SHA256SUMS` inventories and integrity-checks the exact payload and both
Sigstore bundle files without making the bundles self-attest; Sigstore
verification plus the immutable GitHub release supplies authenticity.
Publication separately verifies the checksum manifest, provenance bundle, and
SPDX SBOM bundle.

The workflow's repository-settings audit uses the
`RELEASE_GOVERNANCE_TOKEN` Actions secret. It must be a fine-grained,
read-only credential scoped only to this repository with `Metadata: read`,
`Administration: read`, and `Actions: read`; release creation continues to use
the ephemeral `GITHUB_TOKEN`. The audit requires squash-only merges; active,
no-bypass main protection with the exact seven strict
GitHub-Actions-sourced checks retained by release evidence; the exact named tag
creation actors plus a no-bypass immutable-tag ruleset; GitHub Actions SHA
enforcement and an action allowlist; the no-admin-bypass, self-review-blocked
`governed-release` environment with exactly both maintainers; private
vulnerability reporting; Dependabot alerts and security updates; secret
scanning with push protection; and immutable releases.

## Upstream synchronization

Upstream updates are performed on a dedicated branch from a recorded upstream
tag and commit. A maintainer must:

1. review the complete upstream delta, release notes, dependency changes, and
   security advisories;
2. classify each fork patch as retained, upstreamed, superseded, or removed;
3. resolve conflicts without weakening fork security contracts;
4. update `NOTICE` and the patch inventory;
5. rerun unit, race, static, vulnerability, and conformance qualification; and
6. obtain a `CODEOWNERS` review before merging.

Released history is never rebased during an upstream sync. Upstream signature
verification is required when upstream publishes signed objects; otherwise,
the retrieved commit SHA and its provenance are recorded and independently
reviewed.

## Rollback and incident releases

Consumers roll back by pinning the last known-good immutable fork tag and its
checksum. A bad release remains available for audit but is marked as affected
in its release notes and security advisory. Corrections use a new signed
version and fresh provenance. If immediate containment is required, maintainers
may withdraw distribution links or recommend a prior version, but they do not
move or reuse the affected tag.

OpenID certification statements made by upstream do not automatically apply
to modified fork releases. Certification or conformance claims for a fork tag
must be backed by evidence generated for that exact tag.
