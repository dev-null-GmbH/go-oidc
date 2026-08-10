package token

import (
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func tokenEndpointResultFromError(err error) goidc.TokenEndpointResult {
	if err == nil {
		return goidc.TokenEndpointResultIssued
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		return goidc.TokenEndpointResultServerError
	}
	switch oidcErr.Code {
	case goidc.ErrorCodeInvalidRequest:
		return goidc.TokenEndpointResultInvalidRequest
	case goidc.ErrorCodeInvalidClient:
		return goidc.TokenEndpointResultInvalidClient
	case goidc.ErrorCodeUnauthorizedClient:
		return goidc.TokenEndpointResultUnauthorizedClient
	case goidc.ErrorCodeInvalidScope:
		return goidc.TokenEndpointResultInvalidScope
	case goidc.ErrorCodeInvalidTarget:
		return goidc.TokenEndpointResultInvalidTarget
	case goidc.ErrorCodeInvalidDPoPProof:
		return goidc.TokenEndpointResultInvalidDPoPProof
	case goidc.ErrorCodeUseDPoPNonce:
		return goidc.TokenEndpointResultUseDPoPNonce
	case goidc.ErrorCodeServerError, goidc.ErrorCodeInternalError:
		return goidc.TokenEndpointResultServerError
	default:
		return goidc.TokenEndpointResultProtocolDenied
	}
}
