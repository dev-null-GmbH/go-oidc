package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestTokenEndpointEvidenceStateSnapshotsIdentityAndEmitsOnce(t *testing.T) {
	t.Parallel()

	var got []goidc.TokenEndpointEvidence
	config := &Configuration{
		TokenEndpointEvidenceFunc: func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
			got = append(got, evidence)
		},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", nil)
	ctx := NewHTTPContext(httptest.NewRecorder(), request, config).BeginTokenEndpointEvidence()
	copyOfContext := ctx
	copyOfContext.MarkTokenEndpointClientAuthenticated("verified-client")
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultIssued)
	copyOfContext.EmitTokenEndpointEvidence(goidc.TokenEndpointResultInvalidClient)

	if len(got) != 1 {
		t.Fatalf("callback calls = %d, want 1", len(got))
	}
	want := goidc.TokenEndpointEvidence{
		Result:                goidc.TokenEndpointResultIssued,
		AuthenticatedClientID: "verified-client",
	}
	if got[0] != want {
		t.Fatalf("evidence = %#v, want %#v", got[0], want)
	}
}

func TestTokenEndpointEvidenceStateFailsClosedOnConflictingIdentity(t *testing.T) {
	t.Parallel()

	var got goidc.TokenEndpointEvidence
	config := &Configuration{
		TokenEndpointEvidenceFunc: func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
			got = evidence
		},
	}
	ctx := NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/token", nil),
		config,
	).BeginTokenEndpointEvidence()
	ctx.MarkTokenEndpointClientAuthenticated("first-client")
	ctx.MarkTokenEndpointClientAuthenticated("second-client")
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultInvalidClient)

	if got.Result != goidc.TokenEndpointResultInvalidClient || got.AuthenticatedClientID != "" {
		t.Fatalf("evidence = %#v, want unattributed invalid_client", got)
	}
}

func TestTokenEndpointEvidenceContainsCallbackPanicAndNormalizesInvalidResult(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	var got goidc.TokenEndpointEvidence
	config := &Configuration{
		TokenEndpointEvidenceFunc: func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
			calls.Add(1)
			got = evidence
			panic("evidence panic canary")
		},
	}
	ctx := NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/token", nil),
		config,
	).BeginTokenEndpointEvidence()
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResult(255))
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultIssued)

	if calls.Load() != 1 {
		t.Fatalf("callback calls = %d, want 1", calls.Load())
	}
	if got != (goidc.TokenEndpointEvidence{Result: goidc.TokenEndpointResultServerError}) {
		t.Fatalf("evidence = %#v, want normalized server error", got)
	}
}

func TestTokenEndpointEvidenceConcurrentEmissionIsExactlyOnce(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	config := &Configuration{
		TokenEndpointEvidenceFunc: func(context.Context, goidc.TokenEndpointEvidence) {
			calls.Add(1)
		},
	}
	ctx := NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/token", nil),
		config,
	).BeginTokenEndpointEvidence()
	ctx.MarkTokenEndpointClientAuthenticated("verified-client")

	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultIssued)
		}()
	}
	wait.Wait()
	if calls.Load() != 1 {
		t.Fatalf("callback calls = %d, want 1", calls.Load())
	}
}

func TestTokenEndpointEvidenceIsInactiveWithoutCallback(t *testing.T) {
	t.Parallel()

	ctx := NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/token", nil),
		&Configuration{},
	).BeginTokenEndpointEvidence()
	ctx.MarkTokenEndpointClientAuthenticated("client")
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultIssued)
}
