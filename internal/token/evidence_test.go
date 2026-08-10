package token

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenEndpointResultFromErrorIsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want goidc.TokenEndpointResult
	}{
		{name: "success", want: goidc.TokenEndpointResultIssued},
		{name: "invalid request", err: goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request"), want: goidc.TokenEndpointResultInvalidRequest},
		{name: "invalid client", err: goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client"), want: goidc.TokenEndpointResultInvalidClient},
		{name: "unauthorized client", err: goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client"), want: goidc.TokenEndpointResultUnauthorizedClient},
		{name: "invalid scope", err: goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope"), want: goidc.TokenEndpointResultInvalidScope},
		{name: "invalid target", err: goidc.NewError(goidc.ErrorCodeInvalidTarget, "invalid target"), want: goidc.TokenEndpointResultInvalidTarget},
		{name: "invalid dpop proof", err: goidc.NewError(goidc.ErrorCodeInvalidDPoPProof, "invalid proof"), want: goidc.TokenEndpointResultInvalidDPoPProof},
		{name: "use dpop nonce", err: goidc.NewError(goidc.ErrorCodeUseDPoPNonce, "nonce required"), want: goidc.TokenEndpointResultUseDPoPNonce},
		{name: "server error", err: goidc.NewError(goidc.ErrorCodeServerError, "server error"), want: goidc.TokenEndpointResultServerError},
		{name: "legacy internal error", err: goidc.NewError(goidc.ErrorCodeInternalError, "internal error"), want: goidc.TokenEndpointResultServerError},
		{name: "plain error", err: errors.New("storage unavailable"), want: goidc.TokenEndpointResultServerError},
		{name: "other protocol denial", err: goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant"), want: goidc.TokenEndpointResultProtocolDenied},
		{name: "unknown protocol denial", err: goidc.NewError(goidc.ErrorCode("future_error"), "future error"), want: goidc.TokenEndpointResultProtocolDenied},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenEndpointResultFromError(test.err); got != test.want {
				t.Fatalf("tokenEndpointResultFromError() = %d, want %d", got, test.want)
			}
		})
	}
}
