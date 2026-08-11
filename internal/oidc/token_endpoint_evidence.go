package oidc

import (
	"context"
	"strings"
	"sync"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

type tokenEndpointEvidenceState struct {
	mu                    sync.Mutex
	authenticatedClientID string
	attributionInvalid    bool
	emitted               bool
}

// BeginTokenEndpointEvidence creates private request-local evidence state. The
// pointer is deliberately carried by Context copies and is never stored in the
// provider configuration or the request's context values.
func (ctx Context) BeginTokenEndpointEvidence() Context {
	if ctx.TokenEndpointEvidenceFunc != nil {
		ctx.tokenEndpointEvidence = &tokenEndpointEvidenceState{}
	}
	return ctx
}

// MarkTokenEndpointClientAuthenticated snapshots a server-resolved client ID
// after authentication policy succeeds. Conflicting identities fail closed by
// permanently removing attribution from this request.
func (ctx Context) MarkTokenEndpointClientAuthenticated(id string) {
	state := ctx.tokenEndpointEvidence
	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.emitted || state.attributionInvalid {
		return
	}
	if id == "" {
		state.authenticatedClientID = ""
		state.attributionInvalid = true
		return
	}
	if state.authenticatedClientID == "" {
		state.authenticatedClientID = strings.Clone(id)
		return
	}
	if state.authenticatedClientID != id {
		state.authenticatedClientID = ""
		state.attributionInvalid = true
	}
}

// EmitTokenEndpointEvidence invokes the configured callback at most once. An
// invalid internal result is reduced to ServerError; callback panics are
// contained without recovering any panic already unwinding through the token
// endpoint handler.
func (ctx Context) EmitTokenEndpointEvidence(result goidc.TokenEndpointResult) {
	state := ctx.tokenEndpointEvidence
	callback := ctx.TokenEndpointEvidenceFunc
	if state == nil || callback == nil {
		return
	}
	if !validTokenEndpointResult(result) {
		result = goidc.TokenEndpointResultServerError
	}

	state.mu.Lock()
	if state.emitted {
		state.mu.Unlock()
		return
	}
	state.emitted = true
	authenticatedClientID := state.authenticatedClientID
	if state.attributionInvalid {
		authenticatedClientID = ""
	}
	state.mu.Unlock()

	safeTokenEndpointEvidenceCallback(callback, ctx.Context(), goidc.TokenEndpointEvidence{
		Result:                result,
		AuthenticatedClientID: authenticatedClientID,
	})
}

func safeTokenEndpointEvidenceCallback(
	callback goidc.TokenEndpointEvidenceFunc,
	ctxContext context.Context,
	evidence goidc.TokenEndpointEvidence,
) {
	defer func() {
		_ = recover()
	}()
	callback(ctxContext, evidence)
}

func validTokenEndpointResult(result goidc.TokenEndpointResult) bool {
	switch result {
	case goidc.TokenEndpointResultIssued,
		goidc.TokenEndpointResultInvalidRequest,
		goidc.TokenEndpointResultInvalidClient,
		goidc.TokenEndpointResultUnauthorizedClient,
		goidc.TokenEndpointResultInvalidScope,
		goidc.TokenEndpointResultInvalidTarget,
		goidc.TokenEndpointResultInvalidDPoPProof,
		goidc.TokenEndpointResultUseDPoPNonce,
		goidc.TokenEndpointResultServerError,
		goidc.TokenEndpointResultProtocolDenied:
		return true
	default:
		return false
	}
}
