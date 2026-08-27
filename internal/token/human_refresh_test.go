package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	testHumanRefreshToken          = "d0_hrt_1_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	testHumanSuccessorRefreshToken = "d0_hrt_1_CwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
)

func TestHumanAuthorizationCodeIssuesRefreshOnlyForOfflineAccess(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	decision := fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
		config.Scopes = []string{"offline_access", "openid", "profile"}
		config.RefreshToken = mustHumanRefreshToken(t, testHumanRefreshToken)
		config.RefreshTokenExpiresAt = config.CreatedAt + 86_400
	})
	fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		return decision, nil
	}

	resp, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateAuthCodeToken() error = %v", err)
	}
	if resp.RefreshToken != testHumanRefreshToken || resp.RefreshTokenExpiresIn < 86_398 ||
		resp.RefreshTokenExpiresIn > 86_400 || resp.Scopes != "offline_access openid profile" {
		t.Fatalf("offline token response = %#v", resp)
	}
	fixture.assertNoLegacyIssuance(t)

	online := newHumanTokenFixture(t)
	online.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		return online.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {}), nil
	}
	resp, err = generateAuthCodeToken(online.ctx, newRequest(online.ctx.Request))
	if err != nil {
		t.Fatalf("online generateAuthCodeToken() error = %v", err)
	}
	if resp.RefreshToken != "" || resp.RefreshTokenExpiresIn != 0 {
		t.Fatalf("online token response exposed refresh fields: %#v", resp)
	}
	online.assertNoLegacyIssuance(t)
}

func TestHumanRefreshTokenResponseClampsAuthorityClockSkew(t *testing.T) {
	t.Parallel()

	const now int64 = 1_800_000_000
	capability := mustHumanRefreshToken(t, testHumanRefreshToken)
	for _, test := range []struct {
		name      string
		expiresAt int64
		skew      int64
		want      int
		wantError bool
	}{
		{name: "database clock ahead", expiresAt: now + humanTokenMaximumRefreshLife + 30, skew: 30, want: humanTokenMaximumRefreshLife},
		{name: "application clock ahead at skew boundary", expiresAt: now - 30, skew: 30, want: 1},
		{name: "application clock ahead past skew", expiresAt: now - 31, skew: 30, wantError: true},
		{name: "negative skew", expiresAt: now + humanTokenMaximumRefreshLife, skew: -1, wantError: true},
		{name: "unbounded skew", expiresAt: now + humanTokenMaximumRefreshLife, skew: 61, wantError: true},
		{name: "overflowing skew", expiresAt: now + humanTokenMaximumRefreshLife, skew: int64(^uint64(0) >> 1), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value, expiresIn, err := humanRefreshTokenResponse(
				capability,
				true,
				test.expiresAt,
				now,
				test.skew,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("humanRefreshTokenResponse() error = %v, wantError %t", err, test.wantError)
			}
			if test.wantError {
				if value != "" || expiresIn != 0 {
					t.Fatalf("humanRefreshTokenResponse() failure = (%q, %d), want zero values", value, expiresIn)
				}
				return
			}
			if value != testHumanRefreshToken || expiresIn != test.want {
				t.Fatalf("humanRefreshTokenResponse() = (%q, %d), want (%q, %d)",
					value, expiresIn, testHumanRefreshToken, test.want,
				)
			}
		})
	}
}

func TestHumanAuthorizationCodeAcceptsDatabaseClockAheadAfterAtomicRedemption(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.ctx.JWTLeewayTimeSecs = 30
	fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		databaseNow := int64(timeutil.TimestampNow() + 30)
		return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			config.Scopes = []string{"offline_access", "openid", "profile"}
			config.RefreshToken = mustHumanRefreshToken(t, testHumanRefreshToken)
			config.AuthenticationTime = databaseNow - 5
			config.CreatedAt = databaseNow
			config.ExpiresAt = databaseNow + 60
			config.RefreshTokenExpiresAt = databaseNow + humanTokenMaximumRefreshLife
		}), nil
	}

	resp, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateAuthCodeToken() error = %v", err)
	}
	if resp.RefreshToken != testHumanRefreshToken ||
		resp.RefreshTokenExpiresIn != humanTokenMaximumRefreshLife {
		t.Fatalf("database-ahead token response = %#v", resp)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshAcceptsDatabaseClockAheadAfterAtomicRotation(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.ctx.JWTLeewayTimeSecs = 30
	fixture.installRefreshRequest(t, "human-refresh-database-clock-ahead", testHumanRefreshToken)
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	fixture.authority.rotate = func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
		databaseNow := int64(timeutil.TimestampNow() + 30)
		return fixture.rotatedDecision(t, func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.AuthenticationTime = databaseNow - 5
			config.CreatedAt = databaseNow
			config.ExpiresAt = databaseNow + 60
			config.RefreshTokenExpiresAt = databaseNow + humanTokenMaximumRefreshLife
		}), nil
	}

	resp, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateRefreshToken() error = %v", err)
	}
	if resp.RefreshToken != testHumanSuccessorRefreshToken ||
		resp.RefreshTokenExpiresIn != humanTokenMaximumRefreshLife {
		t.Fatalf("database-ahead refresh response = %#v", resp)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshRotationIssuesImmutablePS256BearerWithoutIDToken(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installRefreshRequest(t, "human-refresh-assertion-1", testHumanRefreshToken)
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	fixture.authority.rotate = func(_ context.Context, input goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
		presented, err := input.RefreshToken().Render()
		if err != nil || presented != testHumanRefreshToken || input.ClientID() != fixture.client.ID ||
			input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatalf("RotateRefreshToken() input = %#v, rendered=%q, err=%v", input, presented, err)
		}
		return fixture.rotatedDecision(t, func(*goidc.HumanRefreshRotationDecisionConfig) {}), nil
	}

	resp, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateRefreshToken() error = %v", err)
	}
	if fixture.authority.rotateCalls != 1 || resp.IDToken != "" || resp.AccessToken == "" ||
		resp.RefreshToken != testHumanSuccessorRefreshToken || resp.ExpiresIn != 300 ||
		resp.RefreshTokenExpiresIn < 86_398 || resp.RefreshTokenExpiresIn > 86_400 ||
		resp.TokenType != goidc.TokenTypeBearer || resp.Scopes != "offline_access openid profile" ||
		!slices.Equal(resp.Resources, goidc.Resources{"https://api.example.invalid/accounting"}) || !resp.noStore {
		t.Fatalf("strict refresh response = %#v; rotate calls=%d", resp, fixture.authority.rotateCalls)
	}

	claims := parseHumanPS256Token(t, fixture.ctx, resp.AccessToken, "at+jwt")
	assertHumanTokenClaim(t, claims, goidc.ClaimIssuer, fixture.ctx.Issuer())
	assertHumanTokenClaim(t, claims, goidc.ClaimSubject, testHumanSubject)
	assertHumanTokenClaim(t, claims, goidc.ClaimClientID, testHumanClientID)
	assertHumanTokenClaim(t, claims, goidc.ClaimGrantID, "human-grant-0001")
	assertHumanTokenClaim(t, claims, goidc.ClaimScope, "offline_access openid profile")
	assertHumanTokenClaim(t, claims, humanOrganizationIDClaim, testHumanOrganizationID)
	assertHumanTokenClaim(t, claims, humanMembershipIDClaim, testHumanMembershipID)
	assertHumanTokenClaim(t, claims, humanMembershipRevisionClaim, float64(7))
	if _, ok := claims[goidc.ClaimNonce]; ok {
		t.Fatal("refresh access token replayed nonce")
	}
	if got := integerClaim(t, claims, goidc.ClaimExpiry) - integerClaim(t, claims, goidc.ClaimIssuedAt); got != 300 {
		t.Fatalf("access token lifetime = %d, want 300", got)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshTokenEndpointDispatchesStrictResponseAndCachePolicy(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installRefreshRequest(t, "human-refresh-http-dispatch", testHumanRefreshToken)
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	fixture.authority.rotate = func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
		return fixture.rotatedDecision(t, func(*goidc.HumanRefreshRotationDecisionConfig) {}), nil
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleCreate(fixture.ctx)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token endpoint response = status %d headers %#v body %q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, accessTokenOK := payload["access_token"].(string)
	refreshExpiresIn, refreshExpiryOK := payload["refresh_token_expires_in"].(float64)
	resources, resourcesOK := payload["resources"].([]any)
	if len(payload) != 7 || !accessTokenOK || accessToken == "" ||
		payload["refresh_token"] != testHumanSuccessorRefreshToken || payload["token_type"] != "Bearer" ||
		payload["expires_in"] != float64(300) || !refreshExpiryOK || refreshExpiresIn < 86_398 ||
		refreshExpiresIn > 86_400 || payload["scope"] != "offline_access openid profile" ||
		!resourcesOK || len(resources) != 1 || resources[0] != "https://api.example.invalid/accounting" {
		t.Fatalf("token endpoint payload = %#v", payload)
	}
	if _, present := payload["id_token"]; present {
		t.Fatalf("refresh response contained ID token: %#v", payload)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshRequiresExactFiveFieldForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*humanTokenFixture)
	}{
		{name: "duplicate token", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["refresh_token"] = append(fixture.ctx.Request.PostForm["refresh_token"], testHumanRefreshToken)
		}},
		{name: "duplicate assertion", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["client_assertion"] = append(fixture.ctx.Request.PostForm["client_assertion"], "duplicate")
		}},
		{name: "missing assertion", mutate: func(fixture *humanTokenFixture) {
			delete(fixture.ctx.Request.PostForm, "client_assertion")
		}},
		{name: "scope narrowing", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["scope"] = []string{"openid"}
		}},
		{name: "resource narrowing", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["resource"] = []string{"https://api.example.invalid/accounting"}
		}},
		{name: "authorization code field", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["code"] = []string{testHumanAuthorizationCode}
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
			fixture.enableOfflineAccess()
			fixture.installRefreshRequest(t, "human-refresh-form-"+strings.ReplaceAll(test.name, " ", "-"), testHumanRefreshToken)
			fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
			test.mutate(fixture)
			_, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeInvalidRequest)
			if fixture.authority.rotateCalls != 0 {
				t.Fatalf("invalid form reached authority %d times", fixture.authority.rotateCalls)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanRefreshRejectionsAreIndistinguishableAndNeverFallThrough(t *testing.T) {
	t.Parallel()

	var baseline string
	for _, reason := range []string{"replayed", "expired", "revoked", "client authority mismatch"} {
		t.Run(reason, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.enableOfflineAccess()
			fixture.installRefreshRequest(t, "human-refresh-reject-"+strings.ReplaceAll(reason, " ", "-"), testHumanRefreshToken)
			fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
			fixture.authority.rotate = func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
				return mustHumanRefreshRotationDecision(t, goidc.HumanRefreshRotationDecisionConfig{
					Outcome: goidc.HumanRefreshRotationOutcomeRejected,
				}), nil
			}
			_, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
			if baseline == "" {
				baseline = err.Error()
			} else if err.Error() != baseline {
				t.Fatalf("rejection error = %q, want %q", err, baseline)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installRefreshRequest(t, "human-refresh-invalid-namespace", "legacy-refresh-token")
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	_, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.rotateCalls != 0 {
		t.Fatalf("invalid namespace reached authority %d times", fixture.authority.rotateCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshAuthorityAndSigningFailuresAreServerErrorsAndBurnPredecessor(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		rotate func(*humanTokenFixture, *testing.T) func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error)
	}{
		{name: "storage error", rotate: func(*humanTokenFixture, *testing.T) func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
			return func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
				return goidc.HumanRefreshRotationDecision{}, errors.New("sensitive storage failure")
			}
		}},
		{name: "panic", rotate: func(*humanTokenFixture, *testing.T) func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
			return func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
				panic("sensitive panic")
			}
		}},
		{name: "invalid output", rotate: func(*humanTokenFixture, *testing.T) func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
			return func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
				return goidc.HumanRefreshRotationDecision{}, nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.enableOfflineAccess()
			fixture.installRefreshRequest(t, "human-refresh-failure-"+strings.ReplaceAll(test.name, " ", "-"), testHumanRefreshToken)
			fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
			fixture.authority.rotate = test.rotate(fixture, t)
			resp, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeServerError)
			if resp.AccessToken != "" || resp.IDToken != "" || resp.RefreshToken != "" ||
				resp.RefreshTokenExpiresIn != 0 || resp.ExpiresIn != 0 ||
				resp.TokenType != "" || resp.Scopes != "" ||
				resp.AuthorizationDetails != nil || resp.Resources != nil ||
				resp.IssuedTokenType != "" || resp.noStore {
				t.Fatalf("failure leaked partial response: %#v", resp)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installRefreshRequest(t, "human-refresh-signing-failure", testHumanRefreshToken)
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	rotated := fixture.rotatedDecision(t, func(*goidc.HumanRefreshRotationDecisionConfig) {})
	rejected := mustHumanRefreshRotationDecision(t, goidc.HumanRefreshRotationDecisionConfig{
		Outcome: goidc.HumanRefreshRotationOutcomeRejected,
	})
	fixture.authority.rotate = func(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
		if fixture.authority.rotateCalls == 1 {
			return rotated, nil
		}
		return rejected, nil
	}
	fixture.ctx.SignerFunc = nil
	fixture.ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, errors.New("signing authority unavailable")
	}
	_, firstErr := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, firstErr, goidc.ErrorCodeServerError)
	fixture.installRefreshRequest(t, "human-refresh-signing-replay", testHumanRefreshToken)
	_, replayErr := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, replayErr, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.rotateCalls != 2 {
		t.Fatalf("RotateRefreshToken() calls = %d, want 2", fixture.authority.rotateCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshNamespaceCannotFallThroughAfterProfileDowngrade(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installRefreshRequest(t, "human-refresh-profile-downgrade", testHumanRefreshToken)
	fixture.client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	_, err := generateRefreshToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.rotateCalls != 0 {
		t.Fatalf("downgraded profile reached authority %d times", fixture.authority.rotateCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func (fixture *humanTokenFixture) enableOfflineAccess() {
	fixture.ctx.Scopes = append(fixture.ctx.Scopes, goidc.ScopeOfflineAccess)
	fixture.client.ScopeIDs = "offline_access openid profile"
}

func (fixture *humanTokenFixture) installRefreshRequest(t *testing.T, assertionID, refreshToken string) {
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
		"grant_type":            {string(goidc.GrantRefreshToken)},
		"refresh_token":         {refreshToken},
		"client_id":             {fixture.client.ID},
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	request, err := http.NewRequest(
		http.MethodPost,
		fixture.ctx.Issuer()+fixture.ctx.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error = %v", err)
	}
	fixture.ctx.Request = request
}

func (fixture *humanTokenFixture) rotatedDecision(
	t *testing.T,
	mutate func(*goidc.HumanRefreshRotationDecisionConfig),
) goidc.HumanRefreshRotationDecision {
	t.Helper()
	now := int64(timeutil.TimestampNow())
	config := goidc.HumanRefreshRotationDecisionConfig{
		Outcome:                  goidc.HumanRefreshRotationOutcomeRotated,
		RefreshToken:             mustHumanRefreshToken(t, testHumanSuccessorRefreshToken),
		RefreshTokenExpiresAt:    now + 86_400,
		GrantID:                  "human-grant-0001",
		Subject:                  testHumanSubject,
		OrganizationID:           testHumanOrganizationID,
		MembershipID:             testHumanMembershipID,
		MembershipRevision:       7,
		ClientID:                 testHumanClientID,
		ClientAssertionAuthority: fixture.verifiedAuthority,
		Scopes:                   []string{"offline_access", "openid", "profile"},
		Resources:                []string{"https://api.example.invalid/accounting"},
		AuthenticationTime:       now - 5,
		AuthenticationContext:    "urn:d0:acr:passkey",
		AuthenticationMethods:    []string{"passkey"},
		CreatedAt:                now,
		ExpiresAt:                now + 60,
	}
	mutate(&config)
	return mustHumanRefreshRotationDecision(t, config)
}

func mustHumanRefreshToken(t *testing.T, value string) goidc.HumanRefreshToken {
	t.Helper()
	token, err := goidc.NewHumanRefreshToken(value)
	if err != nil {
		t.Fatalf("NewHumanRefreshToken() error = %v", err)
	}
	return token
}

func mustHumanRefreshRotationDecision(
	t *testing.T,
	config goidc.HumanRefreshRotationDecisionConfig,
) goidc.HumanRefreshRotationDecision {
	t.Helper()
	decision, err := goidc.NewHumanRefreshRotationDecision(config)
	if err != nil {
		t.Fatalf("NewHumanRefreshRotationDecision() error = %v", err)
	}
	return decision
}

type humanRefreshTokenPanicManager struct{}

func (humanRefreshTokenPanicManager) GrantByRefreshToken(context.Context, string) (*goidc.Grant, error) {
	panic("legacy RefreshTokenManager called")
}
