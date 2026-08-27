package authorize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestPushAuthTransportsVerifiedClientAssertionAuthorityToHandleAndSave(t *testing.T) {
	ctx := oidctest.NewContext(t)
	manager := oidctest.Manager(t, ctx)
	ctx.PARManager = manager
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgRS256}
	ctx.JWTLifetimeSecs = 60
	ctx.PARLifetimeSecs = 60
	ctx.AuthSessionIDFunc = func(context.Context) string { return "authority-session" }
	ctx.AuthSessionPersistenceIDFunc = func(context.Context) string { return "authority-persistence" }
	ctx.PARIDFunc = func(context.Context) string { return "authority-par" }

	decoyKey := oidctest.PrivateRS256JWK(t, "decoy-key", goidc.KeyUsageSignature)
	signingKey := oidctest.PrivateRS256JWK(t, "matched-key", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID: "authority-client",
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 81,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{
				{Key: decoyKey.Public(), KeyAuthorityID: "019c8a06-6aa2-73d0-b23f-c7a32c27f30e"},
				{Key: signingKey.Public(), KeyAuthorityID: "019c8a06-8d95-7fc8-b51a-d30682d47c30"},
			},
		},
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
			RedirectURIs:     []string{"https://client.example/callback"},
			ScopeIDs:         goidc.ScopeOpenID.ID,
			GrantTypes:       []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:    []goidc.ResponseType{goidc.ResponseTypeCode},
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, client)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   client.ID,
			goidc.ClaimSubject:  client.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + 50,
			goidc.ClaimTokenID:  "authority-par-assertion",
		}, signingKey)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	var policyCalls, consumeCalls, handleCalls, saveCalls int
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, assertion goidc.VerifiedClientAssertion) error {
		policyCalls++
		assertVerifiedAuthority(t, assertion.Authority, 81, "019c8a06-8d95-7fc8-b51a-d30682d47c30")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		consumeCalls++
		if use.ID != "authority-par-assertion" {
			t.Fatalf("consumed JTI = %q, want authority-par-assertion", use.ID)
		}
		return nil
	}
	ctx.PARHandleSessionFunc = func(_ context.Context, session *goidc.AuthnSession, gotClient *goidc.Client) error {
		handleCalls++
		if gotClient != client {
			t.Fatal("PAR handler received a different client")
		}
		assertVerifiedAuthority(t, session.ClientAssertionAuthority, 81, "019c8a06-8d95-7fc8-b51a-d30682d47c30")

		// The session evidence must not alias the resolver-owned authority.
		client.PrivateKeyJWTAuthority.SnapshotRevision = 999
		client.PrivateKeyJWTAuthority.Keys[1].KeyAuthorityID = "mutated-resolver-key"
		assertVerifiedAuthority(t, session.ClientAssertionAuthority, 81, "019c8a06-8d95-7fc8-b51a-d30682d47c30")
		return nil
	}
	ctx.AuthManager = &parAuthorityObservingManager{
		AuthManager: manager,
		onSave: func(session *goidc.AuthnSession) {
			saveCalls++
			if handleCalls != 1 {
				t.Fatalf("SaveSession called before PAR handler: handle calls = %d", handleCalls)
			}
			assertVerifiedAuthority(t, session.ClientAssertionAuthority, 81, "019c8a06-8d95-7fc8-b51a-d30682d47c30")
		},
	}

	response, err := pushAuth(ctx, request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
	})
	if err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if policyCalls != 1 || consumeCalls != 1 || handleCalls != 1 || saveCalls != 1 {
		t.Fatalf("calls policy/consume/handle/save = %d/%d/%d/%d, want 1/1/1/1",
			policyCalls, consumeCalls, handleCalls, saveCalls)
	}

	encodedResponse, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal(PAR response) error = %v", err)
	}
	if bytes.Contains(encodedResponse, []byte("client_assertion_authority")) ||
		bytes.Contains(encodedResponse, []byte("019c8a06-8d95-7fc8-b51a-d30682d47c30")) {
		t.Fatalf("PAR protocol response exposes authority evidence: %s", encodedResponse)
	}
}

func TestPushAuthRejectsPARHandlerAuthorityMutationBeforePersistence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*goidc.AuthnSession)
	}{
		{
			name: "clear",
			mutate: func(session *goidc.AuthnSession) {
				session.ClientAssertionAuthority = nil
			},
		},
		{
			name: "replace revision",
			mutate: func(session *goidc.AuthnSession) {
				session.ClientAssertionAuthority.SnapshotRevision++
			},
		},
		{
			name: "replace authority key id",
			mutate: func(session *goidc.AuthnSession) {
				session.ClientAssertionAuthority.KeyAuthorityID = "substituted-key"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, _, manager := newAuthorityPARTestContext(t)
			var saveCalls int
			ctx.PARHandleSessionFunc = func(_ context.Context, session *goidc.AuthnSession, _ *goidc.Client) error {
				test.mutate(session)
				return nil
			}
			ctx.AuthManager = &parAuthorityObservingManager{
				AuthManager: manager,
				onSave: func(*goidc.AuthnSession) {
					saveCalls++
				},
			}

			_, err := pushAuth(ctx, req)
			assertPARAuthorityErrorCode(t, err, goidc.ErrorCodeServerError)
			if saveCalls != 0 {
				t.Fatalf("SaveSession calls = %d, want 0", saveCalls)
			}
		})
	}
}

func TestPushAuthIsolatesHandlerRetainedSessionBeforePersistence(t *testing.T) {
	ctx, req, _, manager := newAuthorityPARTestContext(t)
	var retainedSession *goidc.AuthnSession
	var retained *goidc.VerifiedClientAssertionAuthority
	ctx.PARHandleSessionFunc = func(_ context.Context, session *goidc.AuthnSession, _ *goidc.Client) error {
		retainedSession = session
		retained = session.ClientAssertionAuthority
		return nil
	}
	ctx.AuthManager = &parAuthorityObservingManager{
		AuthManager: manager,
		onSave: func(session *goidc.AuthnSession) {
			retained.SnapshotRevision = 999
			retained.KeyAuthorityID = "mutated-retained-pointer"
			retainedSession.ClientAssertionAuthority = &goidc.VerifiedClientAssertionAuthority{
				SnapshotRevision: 998,
				KeyAuthorityID:   "mutated-retained-session",
			}
			assertVerifiedAuthority(t, session.ClientAssertionAuthority, 111, "authority-matched-key")
		},
	}

	if _, err := pushAuth(ctx, req); err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
}

func TestPushAuthCancellationAfterAuthenticationSkipsHandleAndSave(t *testing.T) {
	ctx, req, _, manager := newAuthorityPARTestContext(t)
	requestContext, cancel := context.WithCancel(ctx.Request.Context())
	ctx.Request = ctx.Request.WithContext(requestContext)
	ctx.AuthSessionIDFunc = func(context.Context) string {
		cancel()
		return "canceled-session"
	}
	var handleCalls, saveCalls int
	ctx.PARHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
		handleCalls++
		return nil
	}
	ctx.AuthManager = &parAuthorityObservingManager{
		AuthManager: manager,
		onSave: func(*goidc.AuthnSession) {
			saveCalls++
		},
	}

	_, err := pushAuth(ctx, req)
	assertPARAuthorityErrorCode(t, err, goidc.ErrorCodeServerError)
	if handleCalls != 0 || saveCalls != 0 {
		t.Fatalf("handle/save calls = %d/%d, want 0/0", handleCalls, saveCalls)
	}
}

func TestPushAuthConflictingRecordedAuthoritySkipsHandleAndSave(t *testing.T) {
	ctx, req, client, manager := newAuthorityPARTestContext(t)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(callbackContext context.Context, _ goidc.VerifiedClientAssertion) error {
		requestContext, ok := callbackContext.(oidc.Context)
		if !ok {
			t.Fatalf("policy context type = %T, want oidc.Context", callbackContext)
		}
		requestContext.RecordClientAssertionAuthority(client.ID, &goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 999,
			KeyAuthorityID:   "conflicting-policy-record",
		})
		return nil
	}
	var handleCalls, saveCalls int
	ctx.PARHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
		handleCalls++
		return nil
	}
	ctx.AuthManager = &parAuthorityObservingManager{
		AuthManager: manager,
		onSave: func(*goidc.AuthnSession) {
			saveCalls++
		},
	}

	_, err := pushAuth(ctx, req)
	assertPARAuthorityErrorCode(t, err, goidc.ErrorCodeServerError)
	if handleCalls != 0 || saveCalls != 0 {
		t.Fatalf("handle/save calls = %d/%d, want 0/0", handleCalls, saveCalls)
	}
}

type parAuthorityObservingManager struct {
	goidc.AuthManager
	onSave func(*goidc.AuthnSession)
}

func (manager *parAuthorityObservingManager) SaveSession(ctx context.Context, session *goidc.AuthnSession) error {
	manager.onSave(session)
	return manager.AuthManager.SaveSession(ctx, session)
}

func newAuthorityPARTestContext(
	t *testing.T,
) (oidc.Context, request, *goidc.Client, goidc.AuthManager) {
	t.Helper()
	ctx := oidctest.NewContext(t)
	manager := oidctest.Manager(t, ctx)
	ctx.PARManager = manager
	ctx.AuthManager = manager
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgRS256}
	ctx.JWTLifetimeSecs = 60
	ctx.PARLifetimeSecs = 60
	ctx.AuthSessionIDFunc = func(context.Context) string { return "authority-session" }
	ctx.AuthSessionPersistenceIDFunc = func(context.Context) string { return "authority-persistence" }
	ctx.PARIDFunc = func(context.Context) string { return "authority-par" }

	decoyKey := oidctest.PrivateRS256JWK(t, "authority-decoy", goidc.KeyUsageSignature)
	signingKey := oidctest.PrivateRS256JWK(t, "authority-matched", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID: "authority-client",
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 111,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{
				{Key: decoyKey.Public(), KeyAuthorityID: "authority-decoy-key"},
				{Key: signingKey.Public(), KeyAuthorityID: "authority-matched-key"},
			},
		},
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
			RedirectURIs:     []string{"https://client.example/callback"},
			ScopeIDs:         goidc.ScopeOpenID.ID,
			GrantTypes:       []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:    []goidc.ResponseType{goidc.ResponseTypeCode},
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, client)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_id": {client.ID},
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   client.ID,
			goidc.ClaimSubject:  client.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + 50,
			goidc.ClaimTokenID:  "authority-par-assertion",
		}, signingKey)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	return ctx, request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			Scopes:       client.ScopeIDs,
			ResponseType: goidc.ResponseTypeCode,
		},
	}, client, manager
}

func assertPARAuthorityErrorCode(t *testing.T, err error, want goidc.ErrorCode) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error", err)
	}
	if oidcErr.Code != want {
		t.Fatalf("error code = %q, want %q", oidcErr.Code, want)
	}
}

func assertVerifiedAuthority(
	t *testing.T,
	authority *goidc.VerifiedClientAssertionAuthority,
	wantRevision int64,
	wantKeyID string,
) {
	t.Helper()
	if authority == nil {
		t.Fatal("verified client assertion authority is nil")
	}
	if authority.SnapshotRevision != wantRevision || authority.KeyAuthorityID != wantKeyID {
		t.Fatalf("verified authority = %#v, want revision %d key %q", authority, wantRevision, wantKeyID)
	}
}
