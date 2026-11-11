module github.com/dev-null-GmbH/go-oidc/examples/vci

go 1.27.3

toolchain go1.27.4

require (
	github.com/dev-null-GmbH/go-oidc v0.25.1-d0.16
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/google/uuid v1.6.0
	github.com/luikyv/go-sdjwt v0.1.0
)

replace github.com/dev-null-GmbH/go-oidc => ../..
