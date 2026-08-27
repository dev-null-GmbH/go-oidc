package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanRefreshRevocationUsesExactAuthenticatedAuthorityAndNoStoreResponse(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.ctx.TokenRevocationEnabled = true
	fixture.ctx.TokenRevocationIsClientAllowedFunc = func(context.Context, *goidc.Client) bool {
		panic("legacy revocation policy called")
	}
	fixture.installRevocationRequest(t, "human-revocation-assertion-1", testHumanRefreshToken)
	fixture.authority.revoke = func(_ context.Context, input goidc.HumanRefreshRevocationInput) error {
		presented, err := input.RefreshToken().Render()
		if err != nil || presented != testHumanRefreshToken || input.ClientID() != fixture.client.ID ||
			input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatalf("RevokeRefreshToken() input = %#v, rendered=%q, err=%v", input, presented, err)
		}
		return nil
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleRevocation(fixture.ctx)

	if fixture.authority.revokeCalls != 1 || recorder.Code != http.StatusOK || recorder.Body.Len() != 0 ||
		recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("revocation response = status %d headers %#v body %q; calls=%d",
			recorder.Code, recorder.Header(), recorder.Body.String(), fixture.authority.revokeCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshRevocationRequiresExactFiveFieldForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*humanTokenFixture)
	}{
		{name: "duplicate token", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["token"] = append(
				fixture.ctx.Request.PostForm["token"], testHumanRefreshToken,
			)
		}},
		{name: "missing type hint", mutate: func(fixture *humanTokenFixture) {
			delete(fixture.ctx.Request.PostForm, "token_type_hint")
		}},
		{name: "wrong type hint", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["token_type_hint"] = []string{"access_token"}
		}},
		{name: "extra field", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["scope"] = []string{"openid"}
		}},
		{name: "duplicate assertion", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["client_assertion"] = append(
				fixture.ctx.Request.PostForm["client_assertion"], "duplicate",
			)
		}},
		{name: "query", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.URL.RawQuery = "trace=1"
		}},
		{name: "dpop", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.Header.Set(goidc.HeaderDPoP, "proof")
		}},
		{name: "authorization header", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
		}},
		{name: "wrong content type", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		}},
		{name: "wrong method", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.Method = http.MethodGet
		}},
		{name: "mutual tls", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.ctx.TokenRevocationEnabled = true
			fixture.installRevocationRequest(
				t,
				"human-revocation-form-"+strings.ReplaceAll(test.name, " ", "-"),
				testHumanRefreshToken,
			)
			test.mutate(fixture)
			err := revoke(fixture.ctx, newQueryRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeInvalidRequest)
			if fixture.authority.revokeCalls != 0 {
				t.Fatalf("invalid form reached authority %d times", fixture.authority.revokeCalls)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanRefreshRevocationCapsEncodedBodyBeforeFormParsing(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.ctx.TokenRevocationEnabled = true
	fixture.installRevocationRequest(t, "human-revocation-oversized", testHumanRefreshToken)
	values := url.Values{}
	for name, entries := range fixture.ctx.Request.PostForm {
		values[name] = append([]string(nil), entries...)
	}
	values.Set("padding", strings.Repeat("x", 56*1024))
	request := httptest.NewRequest(
		http.MethodPost,
		fixture.ctx.Issuer()+fixture.ctx.TokenRevocationEndpoint,
		strings.NewReader(values.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fixture.ctx.Request = request
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleRevocation(fixture.ctx)

	if recorder.Code != http.StatusBadRequest || fixture.authority.revokeCalls != 0 ||
		strings.Contains(recorder.Body.String(), testHumanRefreshToken) || recorder.Body.Len() > 1024 {
		t.Fatalf("oversized revocation response = status %d body %q calls=%d",
			recorder.Code, recorder.Body.String(), fixture.authority.revokeCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshRevocationHidesUnknownAndMalformedCapabilities(t *testing.T) {
	t.Parallel()

	for _, token := range []string{
		"unknown-token",
		"d0_hrt_1_not-a-valid-capability",
		testHumanRefreshToken[:len(testHumanRefreshToken)-1] + "F",
	} {
		fixture := newHumanTokenFixture(t)
		fixture.ctx.TokenRevocationEnabled = true
		fixture.installRevocationRequest(t, "human-revocation-unknown-"+url.QueryEscape(token), token)
		if err := revoke(fixture.ctx, newQueryRequest(fixture.ctx.Request)); err != nil {
			t.Fatalf("revoke(%q) error = %v, want indistinguishable success", token, err)
		}
		if fixture.authority.revokeCalls != 0 {
			t.Fatalf("unknown token reached authority %d times", fixture.authority.revokeCalls)
		}
		fixture.assertNoLegacyIssuance(t)
	}
}

func TestHumanRefreshRevocationAuthorityFailureIsServerErrorAndPanicSafe(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		revoke func(context.Context, goidc.HumanRefreshRevocationInput) error
	}{
		{name: "storage error", revoke: func(context.Context, goidc.HumanRefreshRevocationInput) error {
			return errors.New("sensitive storage failure")
		}},
		{name: "panic", revoke: func(context.Context, goidc.HumanRefreshRevocationInput) error {
			panic("sensitive panic")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.ctx.TokenRevocationEnabled = true
			fixture.installRevocationRequest(
				t,
				"human-revocation-failure-"+strings.ReplaceAll(test.name, " ", "-"),
				testHumanRefreshToken,
			)
			fixture.authority.revoke = test.revoke
			err := revoke(fixture.ctx, newQueryRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeServerError)
			if strings.Contains(err.Error(), testHumanRefreshToken) ||
				strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("revocation failure leaked authority details: %q", err)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanRefreshNamespaceNeverFallsThroughToLegacyRevocation(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.ctx.TokenRevocationEnabled = true
	fixture.installRevocationRequest(t, "human-revocation-profile-downgrade", testHumanRefreshToken)
	fixture.client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	if err := revoke(fixture.ctx, newQueryRequest(fixture.ctx.Request)); err != nil {
		t.Fatalf("downgraded profile revocation error = %v, want indistinguishable success", err)
	}
	if fixture.authority.revokeCalls != 0 {
		t.Fatalf("downgraded profile reached authority %d times", fixture.authority.revokeCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func (fixture *humanTokenFixture) installRevocationRequest(
	t *testing.T,
	assertionID string,
	refreshToken string,
) {
	t.Helper()
	now := timeutil.TimestampNow()
	assertion := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   fixture.client.ID,
		goidc.ClaimSubject:  fixture.client.ID,
		goidc.ClaimAudience: fixture.ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 50,
		goidc.ClaimTokenID:  assertionID,
	}, fixture.assertionKey)
	values := url.Values{
		"token":                 {refreshToken},
		"token_type_hint":       {string(goidc.TokenHintRefresh)},
		"client_id":             {fixture.client.ID},
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		fixture.ctx.Issuer()+fixture.ctx.TokenRevocationEndpoint,
		strings.NewReader(values.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error = %v", err)
	}
	fixture.ctx.Request = request
}
