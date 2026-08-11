module github.com/dev-null-GmbH/go-oidc

go 1.26.5

retract (
	v0.25.1-d0.2 // Draft creation failed; use v0.25.1-d0.3.
	v0.25.1-d0.1 // Governance audit failed; use v0.25.1-d0.3.
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
)
