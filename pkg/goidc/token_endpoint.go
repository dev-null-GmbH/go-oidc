package goidc

import "context"

// TokenEndpointResult is the closed set of protocol outcomes exposed after a
// token endpoint response is selected. Its numeric representation prevents
// request-derived OAuth error strings from crossing the callback boundary.
type TokenEndpointResult uint8

const (
	// TokenEndpointResultIssued reports successful token issuance.
	TokenEndpointResultIssued TokenEndpointResult = iota + 1
	// TokenEndpointResultInvalidRequest reports an invalid_request denial.
	TokenEndpointResultInvalidRequest
	// TokenEndpointResultInvalidClient reports an invalid_client denial.
	TokenEndpointResultInvalidClient
	// TokenEndpointResultUnauthorizedClient reports an unauthorized_client denial.
	TokenEndpointResultUnauthorizedClient
	// TokenEndpointResultInvalidScope reports an invalid_scope denial.
	TokenEndpointResultInvalidScope
	// TokenEndpointResultInvalidTarget reports an invalid_target denial.
	TokenEndpointResultInvalidTarget
	// TokenEndpointResultInvalidDPoPProof reports an invalid_dpop_proof denial.
	TokenEndpointResultInvalidDPoPProof
	// TokenEndpointResultUseDPoPNonce reports a use_dpop_nonce challenge.
	TokenEndpointResultUseDPoPNonce
	// TokenEndpointResultServerError reports an operational failure.
	TokenEndpointResultServerError
	// TokenEndpointResultProtocolDenied reports a protocol denial without a more
	// specific result in this contract.
	TokenEndpointResultProtocolDenied
)

// TokenEndpointEvidence is the complete bounded value exposed after a token
// endpoint response is selected. AuthenticatedClientID is empty until client
// authentication has passed its signature, claims, and configured assertion
// policy. It is snapshotted before replay reservation so a later assertion
// replay can be attributed without attributing an invalid assertion.
type TokenEndpointEvidence struct {
	Result                TokenEndpointResult
	AuthenticatedClientID string
}

// TokenEndpointEvidenceFunc observes one bounded result for a token endpoint
// request. Callback panics are contained and cannot change protocol behavior.
// The callback receives no request, response, token, grant, client, or error.
type TokenEndpointEvidenceFunc func(context.Context, TokenEndpointEvidence)
