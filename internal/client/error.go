package client

import "github.com/dev-null-GmbH/go-oidc/pkg/goidc"

var ErrClientNotIdentified = goidc.NewError(goidc.ErrorCodeInvalidClient, "could not identify the client")
