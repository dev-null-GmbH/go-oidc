# Security policy

`dev-null-GmbH/go-oidc` is a security-sensitive, governed fork of
`luikyv/go-oidc`. Please report suspected vulnerabilities privately so that
users can be protected before technical details become public.

## Supported versions

Until the first signed d0 fork release, security fixes are made on the active
integration branch and are not covered by a stable-version support promise.
After release, the newest `-d0.N` release line receives security fixes. Older
fork releases may receive fixes when operationally necessary, but users should
plan to upgrade to the latest qualified release.

Upstream-only versions are governed by the
[upstream project](https://github.com/luikyv/go-oidc). A vulnerability that
also affects upstream may be coordinated with its maintainers without sharing
reporter details beyond the agreed disclosure scope.

## Reporting a vulnerability

Use
[GitHub private vulnerability reporting](https://github.com/dev-null-GmbH/go-oidc/security/advisories/new).
Do not include vulnerability details, proof-of-concept exploits, credentials,
tokens, or production data in a public issue or pull request.

Include, when available:

- the affected fork version or commit;
- the relevant protocol flow and deployment configuration;
- reproducible steps or a minimal proof of concept;
- the security impact and any known exploitation;
- suggested mitigations; and
- your preferred contact and disclosure timeline.

If private reporting is temporarily unavailable, email the public organization
contact, `support@d0.eu`, with only a request for a private security channel.
Do not include vulnerability details or sensitive material in that first
message. A public issue may likewise request private contact after repository
issues are enabled, but must contain no technical details.

## Response and disclosure

Maintainers aim to acknowledge a complete report within two business days and
provide an initial severity assessment within five business days. Timelines
for remediation and disclosure depend on impact, exploitability, affected
downstream services, and any required upstream coordination.

During an embargo, reporters and maintainers should limit information to the
people needed to reproduce, fix, review, and deploy the correction. A fix must
include regression tests and must not weaken replay protection, proof-of-
possession, client authentication, persistence ordering, or protocol error
boundaries. Release artifacts follow
[the governed release policy](.github/RELEASE_POLICY.md).

Security releases use new, signed, immutable versions. Maintainers do not move
or reuse a published tag. Advisories credit reporters who request recognition;
anonymous reporting is respected.

## Operational secrets

This repository must never receive production secrets, signing keys, private
certificates, client assertions, or access tokens. If a secret is disclosed,
rotate or revoke it immediately; deleting it from Git history is not sufficient
containment.
