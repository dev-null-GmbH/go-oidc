package oidc_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestPARClientAssertionAuthorityStateIsRequestLocalAndDefensive(t *testing.T) {
	config := &oidc.Configuration{}
	ctxA := oidc.NewHTTPContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/par", nil), config).
		BeginPARClientAuthentication()
	ctxB := oidc.NewHTTPContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/par", nil), config).
		BeginPARClientAuthentication()

	authorityA := &goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 101, KeyAuthorityID: "authority-key-a"}
	authorityB := &goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 202, KeyAuthorityID: "authority-key-b"}
	clientA := authorityModeClient("client-a")
	clientB := authorityModeClient("client-b")
	ctxA.RecordClientAssertionAuthority(clientA.ID, authorityA)
	ctxB.RecordClientAssertionAuthority(clientB.ID, authorityB)

	// Mutating caller-owned inputs after capture must not alter request state.
	authorityA.SnapshotRevision = 999
	authorityA.KeyAuthorityID = "mutated-input"
	gotA, err := ctxA.PARClientAssertionAuthority(clientA)
	if err != nil {
		t.Fatalf("request A authority error = %v", err)
	}
	assertRequestAuthority(t, gotA, 101, "authority-key-a")
	gotB, err := ctxB.PARClientAssertionAuthority(clientB)
	if err != nil {
		t.Fatalf("request B authority error = %v", err)
	}
	assertRequestAuthority(t, gotB, 202, "authority-key-b")

	// Mutating a returned copy must not alter a later read.
	gotA.SnapshotRevision = 998
	gotA.KeyAuthorityID = "mutated-output"
	gotAAgain, err := ctxA.PARClientAssertionAuthority(clientA)
	if err != nil {
		t.Fatalf("second request A authority error = %v", err)
	}
	assertRequestAuthority(t, gotAAgain, 101, "authority-key-a")

	errCh := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, test := range []struct {
		ctx       oidc.Context
		client    *goidc.Client
		authority goidc.VerifiedClientAssertionAuthority
	}{
		{ctx: ctxA, client: clientA, authority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 101, KeyAuthorityID: "authority-key-a"}},
		{ctx: ctxB, client: clientB, authority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 202, KeyAuthorityID: "authority-key-b"}},
	} {
		waitGroup.Go(func() {
			for range 100 {
				test.ctx.RecordClientAssertionAuthority(test.client.ID, &test.authority)
				got, getErr := test.ctx.PARClientAssertionAuthority(test.client)
				if getErr != nil {
					errCh <- getErr
					return
				}
				if got.SnapshotRevision != test.authority.SnapshotRevision ||
					got.KeyAuthorityID != test.authority.KeyAuthorityID {
					errCh <- fmt.Errorf("request %s observed foreign authority %#v", test.client.ID, got)
					return
				}
			}
		})
	}
	waitGroup.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestPARClientAssertionAuthorityFailsClosedOnMissingOrConflictingState(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(oidc.Context)
		client    *goidc.Client
	}{
		{
			name:   "missing authority evidence",
			client: authorityModeClient("client"),
		},
		{
			name: "different authenticated client",
			configure: func(ctx oidc.Context) {
				ctx.RecordClientAssertionAuthority("other-client", &goidc.VerifiedClientAssertionAuthority{
					SnapshotRevision: 1, KeyAuthorityID: "authority-key",
				})
			},
			client: authorityModeClient("client"),
		},
		{
			name: "evidence with another authentication method",
			configure: func(ctx oidc.Context) {
				ctx.RecordClientAssertionAuthority("client", &goidc.VerifiedClientAssertionAuthority{
					SnapshotRevision: 1, KeyAuthorityID: "authority-key",
				})
			},
			client: &goidc.Client{ID: "client", ClientMeta: goidc.ClientMeta{
				TokenAuthnMethod: goidc.AuthnMethodSecretPost,
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidc.NewHTTPContext(
				httptest.NewRecorder(),
				httptest.NewRequest(http.MethodPost, "/par", nil),
				&oidc.Configuration{},
			).BeginPARClientAuthentication()
			if test.configure != nil {
				test.configure(ctx)
			}
			authority, err := ctx.PARClientAssertionAuthority(test.client)
			if err == nil || authority != nil {
				t.Fatalf("PARClientAssertionAuthority() = %#v, %v; want nil, error", authority, err)
			}
		})
	}

	ctx := oidc.NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/par", nil),
		&oidc.Configuration{},
	).BeginPARClientAuthentication()
	client := authorityModeClient("client")
	original := &goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 1, KeyAuthorityID: "original-key"}
	conflicting := &goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 2, KeyAuthorityID: "conflicting-key"}
	ctx.RecordClientAssertionAuthority(client.ID, original)
	ctx.RecordClientAssertionAuthority(client.ID, conflicting)
	ctx.RecordClientAssertionAuthority(client.ID, original)
	authority, err := ctx.PARClientAssertionAuthority(client)
	if err == nil || authority != nil {
		t.Fatalf("authority after conflicting then original records = %#v, %v; want permanently invalid", authority, err)
	}
}

func TestClientAssertionAuthorityGeneralizedAPIAndPARAliasesAgree(t *testing.T) {
	client := authorityModeClient("client")
	ctx := oidc.NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/token", nil),
		&oidc.Configuration{},
	).BeginClientAssertionAuthentication()
	ctx.RecordClientAssertionAuthority(client.ID, &goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 9,
		KeyAuthorityID:   "authority-key",
	})

	general, err := ctx.ClientAssertionAuthority(client)
	if err != nil {
		t.Fatalf("ClientAssertionAuthority() error = %v", err)
	}
	legacy, err := ctx.PARClientAssertionAuthority(client)
	if err != nil {
		t.Fatalf("PARClientAssertionAuthority() error = %v", err)
	}
	if general == legacy || *general != *legacy {
		t.Fatalf("general=%p %#v legacy=%p %#v, want equal defensive copies", general, general, legacy, legacy)
	}

	legacyBegin := oidc.NewHTTPContext(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/par", nil),
		&oidc.Configuration{},
	).BeginPARClientAuthentication()
	legacyBegin.RecordClientAssertionAuthority(client.ID, general)
	got, err := legacyBegin.ClientAssertionAuthority(client)
	if err != nil || got == nil || *got != *general {
		t.Fatalf("legacy BeginPAR alias general read = %#v, %v", got, err)
	}
}

func authorityModeClient(id string) *goidc.Client {
	return &goidc.Client{
		ID:                     id,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{},
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
		},
	}
}

func assertRequestAuthority(
	t *testing.T,
	authority *goidc.VerifiedClientAssertionAuthority,
	wantRevision int64,
	wantKeyID string,
) {
	t.Helper()
	if authority == nil || authority.SnapshotRevision != wantRevision || authority.KeyAuthorityID != wantKeyID {
		t.Fatalf("authority = %#v, want revision %d key %q", authority, wantRevision, wantKeyID)
	}
}
