package authorize

import (
	"errors"
	"net/http"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanConfidentialBFFRejectedCallbackTerminalizesWithoutGrantOutputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		authenticate func(*goidc.AuthnSession) (goidc.Status, error)
	}{
		{
			name: "callback error overrides claimed success",
			authenticate: func(session *goidc.AuthnSession) (goidc.Status, error) {
				session.Subject = "untrusted-subject"
				session.Username = "untrusted-username"
				session.GrantedScopes = goidc.ScopeOpenID.ID
				session.Store["untrusted"] = "state"
				return goidc.StatusSuccess, errors.New("authentication evidence unavailable")
			},
		},
		{
			name: "invalid success output",
			authenticate: func(session *goidc.AuthnSession) (goidc.Status, error) {
				session.Subject = "untrusted-subject"
				session.GrantedScopes = "admin openid"
				return goidc.StatusSuccess, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, _ := newStrictOuterAuthorizationContext(t)
			policy := goidc.NewPolicy(
				"strict-terminal-policy",
				func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
				func(
					_ http.ResponseWriter,
					_ *http.Request,
					session *goidc.AuthnSession,
					_ *goidc.Client,
				) (goidc.Status, error) {
					return test.authenticate(session)
				},
			)
			ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
			session := oidctest.AuthnSessions(t, ctx)[0]
			session.PolicyID = policy.ID
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			_ = continueAuth(ctx, session.ID)
			persisted, err := ctx.AuthSession(session.ID)
			if err != nil {
				t.Fatalf("AuthSession() error = %v", err)
			}
			if persisted.Status != goidc.StatusFailure || persisted.Subject != "" ||
				persisted.Username != "" || persisted.GrantedScopes != "" ||
				persisted.GrantedAuthDetails != nil || persisted.GrantedResources != nil ||
				len(persisted.Store) != 0 {
				t.Fatalf("rejected callback persisted retryable or grant-bearing state: %#v", persisted)
			}
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("rejected callback issued %d grants", len(grants))
			}
		})
	}
}
