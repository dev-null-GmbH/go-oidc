package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testHumanAuthorizationCode = "d0_hac_1_BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"
	testHumanCodeVerifier      = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
	testHumanRedirectURI       = "https://dashboard.example.invalid/callback"
	testHumanClientID          = "human-confidential-bff"
	testHumanOrganizationID    = "organization-0001"
	testHumanMembershipID      = "membership-000001"
	testHumanSubject           = "pairwise-subject-0001"

	testHumanOrganizationClaim       = "https://d0.eu/claims/organization_id"
	testHumanMembershipClaim         = "https://d0.eu/claims/membership_id"
	testHumanMembershipRevisionClaim = "https://d0.eu/claims/membership_revision"
)

func TestHumanAuthorizationCodeRedemptionIssuesImmutablePS256Tokens(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	// A token request must never reuse authority evidence captured by an earlier
	// authentication attempt on the same outer context value.
	fixture.ctx = fixture.ctx.BeginClientAssertionAuthentication()
	fixture.ctx.RecordClientAssertionAuthority(testHumanClientID, &goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 17,
		KeyAuthorityID:   "human-key-authority-a",
	})
	decision := fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {})
	fixture.authority.redeem = func(_ context.Context, input goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		if !input.Valid() {
			t.Fatal("redemption input is invalid")
		}
		code, err := input.AuthorizationCode().Render()
		if err != nil {
			t.Fatalf("render redemption authorization code: %v", err)
		}
		if code != testHumanAuthorizationCode || input.CodeVerifier() != testHumanCodeVerifier ||
			input.RedirectURI() != testHumanRedirectURI || input.ClientID() != testHumanClientID ||
			input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatalf("redemption input = %#v", input)
		}
		return decision, nil
	}

	resp, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateAuthCodeToken() error = %v", err)
	}
	if fixture.authority.redeemCalls != 1 {
		t.Fatalf("RedeemAuthorizationCode() calls = %d, want 1", fixture.authority.redeemCalls)
	}
	fixture.assertNoLegacyIssuance(t)
	if resp.AccessToken == "" || resp.IDToken == "" || resp.RefreshToken != "" ||
		resp.RefreshTokenExpiresIn != 0 ||
		resp.ExpiresIn != fixture.ctx.HumanAccessTokenLifetimeSecs ||
		resp.TokenType != goidc.TokenTypeBearer || resp.Scopes != "openid profile" ||
		!slices.Equal(resp.Resources, goidc.Resources{"https://api.example.invalid/accounting"}) ||
		resp.AuthorizationDetails != nil || !resp.noStore {
		t.Fatalf("strict token response = %#v", resp)
	}

	accessClaims := parseHumanPS256Token(t, fixture.ctx, resp.AccessToken, "at+jwt")
	issuedAt := integerClaim(t, accessClaims, goidc.ClaimIssuedAt)
	if integerClaim(t, accessClaims, goidc.ClaimExpiry)-issuedAt != int64(fixture.ctx.HumanAccessTokenLifetimeSecs) {
		t.Fatalf("access-token lifetime = %d, want %d",
			integerClaim(t, accessClaims, goidc.ClaimExpiry)-issuedAt,
			fixture.ctx.HumanAccessTokenLifetimeSecs,
		)
	}
	assertHumanTokenClaim(t, accessClaims, goidc.ClaimIssuer, fixture.ctx.Issuer())
	assertHumanTokenClaim(t, accessClaims, goidc.ClaimSubject, testHumanSubject)
	assertHumanTokenClaim(t, accessClaims, goidc.ClaimClientID, testHumanClientID)
	assertHumanTokenClaim(t, accessClaims, goidc.ClaimScope, "openid profile")
	assertHumanTokenClaim(t, accessClaims, goidc.ClaimGrantID, "human-grant-0001")
	assertHumanTokenClaim(t, accessClaims, testHumanOrganizationClaim, testHumanOrganizationID)
	assertHumanTokenClaim(t, accessClaims, testHumanMembershipClaim, testHumanMembershipID)
	if integerClaim(t, accessClaims, testHumanMembershipRevisionClaim) != 7 {
		t.Fatalf("access-token membership revision = %#v, want 7", accessClaims[testHumanMembershipRevisionClaim])
	}
	if audience := stringSliceClaim(t, accessClaims, goidc.ClaimAudience); !slices.Equal(audience, []string{"https://api.example.invalid/accounting"}) {
		t.Fatalf("access-token audience = %#v", audience)
	}
	if _, exists := accessClaims["cnf"]; exists {
		t.Fatal("strict access token contains sender-constraining cnf")
	}
	if _, exists := accessClaims["attacker_claim"]; exists {
		t.Fatal("strict access token contains callback claim")
	}

	idClaims := parseHumanPS256Token(t, fixture.ctx, resp.IDToken, "JWT")
	assertHumanTokenClaim(t, idClaims, goidc.ClaimIssuer, fixture.ctx.Issuer())
	assertHumanTokenClaim(t, idClaims, goidc.ClaimSubject, testHumanSubject)
	assertHumanTokenClaim(t, idClaims, goidc.ClaimAudience, testHumanClientID)
	assertHumanTokenClaim(t, idClaims, goidc.ClaimNonce, "human-nonce-0001")
	if integerClaim(t, idClaims, goidc.ClaimAuthTime) != decision.AuthenticationTime() {
		t.Fatalf("ID-token auth_time = %#v, want %d", idClaims[goidc.ClaimAuthTime], decision.AuthenticationTime())
	}
	assertHumanTokenClaim(t, idClaims, goidc.ClaimACR, "urn:d0:acr:passkey")
	assertHumanTokenClaim(t, idClaims, testHumanOrganizationClaim, testHumanOrganizationID)
	assertHumanTokenClaim(t, idClaims, testHumanMembershipClaim, testHumanMembershipID)
	if integerClaim(t, idClaims, testHumanMembershipRevisionClaim) != 7 {
		t.Fatalf("ID-token membership revision = %#v, want 7", idClaims[testHumanMembershipRevisionClaim])
	}
	if methods := stringSliceClaim(t, idClaims, goidc.ClaimAMR); !slices.Equal(methods, []string{"passkey"}) {
		t.Fatalf("ID-token amr = %#v", methods)
	}
	if integerClaim(t, idClaims, goidc.ClaimExpiry)-integerClaim(t, idClaims, goidc.ClaimIssuedAt) !=
		int64(fixture.ctx.IDTokenLifetimeSecs) {
		t.Fatal("ID-token lifetime did not use the fixed provider configuration")
	}
}

func TestHumanAuthorizationCodeRedemptionRequiresExactFormSurface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*oidc.Context)
	}{
		{name: "unknown parameter", mutate: func(ctx *oidc.Context) { ctx.Request.PostForm["scope"] = []string{"openid"} }},
		{name: "duplicate code", mutate: func(ctx *oidc.Context) {
			ctx.Request.PostForm["code"] = append(ctx.Request.PostForm["code"], testHumanAuthorizationCode)
		}},
		{name: "duplicate assertion", mutate: func(ctx *oidc.Context) {
			ctx.Request.PostForm["client_assertion"] = append(ctx.Request.PostForm["client_assertion"], ctx.Request.PostFormValue("client_assertion"))
		}},
		{name: "missing verifier", mutate: func(ctx *oidc.Context) { delete(ctx.Request.PostForm, "code_verifier") }},
		{name: "client secret", mutate: func(ctx *oidc.Context) { ctx.Request.PostForm["client_secret"] = []string{"not-admitted"} }},
		{name: "query parameter", mutate: func(ctx *oidc.Context) { ctx.Request.URL.RawQuery = "scope=openid" }},
		{name: "authorization header", mutate: func(ctx *oidc.Context) { ctx.Request.SetBasicAuth(testHumanClientID, "not-admitted") }},
		{name: "empty authorization header", mutate: func(ctx *oidc.Context) { ctx.Request.Header.Set("Authorization", "") }},
		{name: "DPoP header", mutate: func(ctx *oidc.Context) { ctx.Request.Header.Set(goidc.HeaderDPoP, "not-admitted") }},
		{name: "empty DPoP header", mutate: func(ctx *oidc.Context) { ctx.Request.Header.Set(goidc.HeaderDPoP, "") }},
		{name: "mutual TLS certificate", mutate: func(ctx *oidc.Context) {
			ctx.Request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
		}},
		{name: "content type parameters", mutate: func(ctx *oidc.Context) {
			ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		}},
		{name: "wrong method", mutate: func(ctx *oidc.Context) { ctx.Request.Method = http.MethodPut }},
		{name: "duplicate content type", mutate: func(ctx *oidc.Context) { ctx.Request.Header.Add("Content-Type", "application/x-www-form-urlencoded") }},
		{name: "malformed dropped form component", mutate: func(ctx *oidc.Context) {
			request := httptest.NewRequest(
				http.MethodPost,
				ctx.Request.URL.String(),
				strings.NewReader(ctx.Request.PostForm.Encode()+"&dropped=%ZZ"),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ctx.Request = request
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHumanTokenFixture(t)
			fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {}), nil
			}
			test.mutate(&fixture.ctx)

			_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeInvalidRequest)
			if fixture.authority.redeemCalls != 0 {
				t.Fatalf("malformed strict form reached redemption authority %d times", fixture.authority.redeemCalls)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanAuthorizationCodeRejectionsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*humanTokenFixture)
	}{
		{name: "malformed code", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["code"] = []string{"not-a-human-code"}
		}},
		{name: "malformed verifier", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["code_verifier"] = []string{"too-short"}
		}},
		{name: "malformed redirect", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.Request.PostForm["redirect_uri"] = []string{"https://dashboard.example.invalid/callback?next=x"}
		}},
		{name: "redirect no longer registered", mutate: func(fixture *humanTokenFixture) {
			fixture.client.RedirectURIs = []string{"https://dashboard.example.invalid/replacement"}
			fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {}), nil
			}
		}},
		{name: "authority rejection", mutate: func(fixture *humanTokenFixture) {
			fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return mustHumanRedemptionDecision(t, goidc.HumanCodeRedemptionDecisionConfig{
					Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
				}), nil
			}
		}},
	}

	var baseline string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return mustHumanRedemptionDecision(t, goidc.HumanCodeRedemptionDecisionConfig{
					Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
				}), nil
			}
			test.mutate(fixture)

			_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
			if baseline == "" {
				baseline = err.Error()
			} else if err.Error() != baseline {
				t.Fatalf("observable rejection = %q, want %q", err, baseline)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanAuthorizationCodeAuthorityFailuresFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		redeem func(*testing.T, *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error)
	}{
		{name: "authority error", redeem: func(_ *testing.T, _ *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return goidc.HumanCodeRedemptionDecision{}, errors.New("database unavailable")
		}},
		{name: "authority panic", redeem: func(_ *testing.T, _ *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			panic("authority panic")
		}},
		{name: "zero decision", redeem: func(_ *testing.T, _ *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return goidc.HumanCodeRedemptionDecision{}, nil
		}},
		{name: "substituted client", redeem: func(t *testing.T, fixture *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
				config.ClientID = "substituted-client"
			}), nil
		}},
		{name: "substituted assertion authority", redeem: func(t *testing.T, fixture *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
				config.ClientAssertionAuthority.KeyAuthorityID = "substituted-key-authority"
			}), nil
		}},
		{name: "scope outside current authority", redeem: func(t *testing.T, fixture *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
				config.Scopes = []string{"openid", "privileged"}
			}), nil
		}},
		{name: "resource outside current authority", redeem: func(t *testing.T, fixture *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
				config.Resources = []string{"https://api.example.invalid/payroll"}
			}), nil
		}},
		{name: "authentication context outside current authority", redeem: func(t *testing.T, fixture *humanTokenFixture) (goidc.HumanCodeRedemptionDecision, error) {
			return fixture.redeemedDecision(t, func(config *goidc.HumanCodeRedemptionDecisionConfig) {
				config.AuthenticationContext = "urn:d0:acr:webauthn"
			}), nil
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHumanTokenFixture(t)
			fixture.authority.redeem = func(_ context.Context, _ goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return test.redeem(t, fixture)
			}

			_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
			assertHumanTokenError(t, err, goidc.ErrorCodeServerError)
			if fixture.authority.redeemCalls != 1 {
				t.Fatalf("RedeemAuthorizationCode() calls = %d, want 1", fixture.authority.redeemCalls)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanAuthorizationCodeUnsafeConfigurationFailsBeforeRedemption(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		mutate    func(*humanTokenFixture)
		wantError goidc.ErrorCode
	}{
		{name: "unbounded ID-token lifetime", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.IDTokenLifetimeSecs = humanTokenMaximumIDLifetime + 1
		}},
		{name: "unbounded access-token lifetime", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.HumanAccessTokenLifetimeSecs = 601
		}},
		{name: "negative authority clock skew", wantError: goidc.ErrorCodeInvalidClient, mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.JWTLeewayTimeSecs = -1
		}},
		{name: "unbounded authority clock skew", mutate: func(fixture *humanTokenFixture) {
			fixture.ctx.JWTLeewayTimeSecs = 61
		}},
		{name: "open client metadata", mutate: func(fixture *humanTokenFixture) {
			fixture.client.CustomAttributes = map[string]any{"untrusted": true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHumanTokenFixture(t)
			fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
				return fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {}), nil
			}
			test.mutate(fixture)

			_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
			wantError := test.wantError
			if wantError == "" {
				wantError = goidc.ErrorCodeServerError
			}
			assertHumanTokenError(t, err, wantError)
			if fixture.authority.redeemCalls != 0 {
				t.Fatalf("unsafe configuration reached redemption authority %d times", fixture.authority.redeemCalls)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanAuthorityDecisionWindowUsesBoundedClockSkew(t *testing.T) {
	t.Parallel()

	const now int64 = 1_800_000_000
	for _, test := range []struct {
		name      string
		createdAt int64
		expiresAt int64
		skew      int64
		want      bool
	}{
		{name: "zero skew", createdAt: now, expiresAt: now + 60, want: true},
		{name: "future created at skew boundary", createdAt: now + 30, expiresAt: now + 90, skew: 30, want: true},
		{name: "future created at skew boundary plus one", createdAt: now + 31, expiresAt: now + 91, skew: 30},
		{name: "expired at reverse skew boundary", createdAt: now - 90, expiresAt: now - 30, skew: 30, want: true},
		{name: "expired at reverse skew boundary plus one", createdAt: now - 91, expiresAt: now - 31, skew: 30},
		{name: "negative skew", createdAt: now, expiresAt: now + 60, skew: -1},
		{name: "unbounded skew", createdAt: now, expiresAt: now + 60, skew: 61},
		{name: "overflowing skew", createdAt: now, expiresAt: now + 60, skew: int64(^uint64(0) >> 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validHumanAuthorityDecisionWindow(test.createdAt, test.expiresAt, now, test.skew); got != test.want {
				t.Fatalf("validHumanAuthorityDecisionWindow() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestHumanAuthorizationCodeIssuanceFactsAreSnapshotBeforeAuthorityCallbacks(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	decision := fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {})
	fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		fixture.client.ScopeIDs = "openid privileged"
		fixture.ctx.HumanAccessTokenLifetimeSecs = 1
		fixture.ctx.IDTokenLifetimeSecs = 2
		fixture.ctx.Scopes = nil
		fixture.ctx.ACRs = nil
		fixture.ctx.ResourceIndicators = nil
		return decision, nil
	}

	resp, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	if err != nil {
		t.Fatalf("generateAuthCodeToken() error = %v", err)
	}
	if resp.ExpiresIn != 300 || resp.Scopes != "openid profile" {
		t.Fatalf("strict response used callback-mutated issuance facts: %#v", resp)
	}
	accessClaims := parseHumanPS256Token(t, fixture.ctx, resp.AccessToken, "at+jwt")
	if integerClaim(t, accessClaims, goidc.ClaimExpiry)-integerClaim(t, accessClaims, goidc.ClaimIssuedAt) != 300 {
		t.Fatal("access token used callback-mutated lifetime")
	}
	idClaims := parseHumanPS256Token(t, fixture.ctx, resp.IDToken, "JWT")
	if integerClaim(t, idClaims, goidc.ClaimExpiry)-integerClaim(t, idClaims, goidc.ClaimIssuedAt) != 600 {
		t.Fatal("ID token used callback-mutated lifetime")
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanAuthorizationIDTokenOmitsEmptyNonceClaim(t *testing.T) {
	t.Parallel()

	claims := map[string]any{}
	addHumanIDTokenNonce(claims, "")
	if _, exists := claims[goidc.ClaimNonce]; exists {
		t.Fatal("strict ID token contains an empty nonce claim")
	}
	addHumanIDTokenNonce(claims, "human-nonce-0001")
	assertHumanTokenClaim(t, claims, goidc.ClaimNonce, "human-nonce-0001")
}

func TestHumanAuthorizationTokenResponseDisablesCaching(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		response   response
		wantCache  string
		wantPragma string
	}{
		{
			name:       "strict",
			response:   response{AccessToken: "strict-access-token", noStore: true},
			wantCache:  "no-store",
			wantPragma: "no-cache",
		},
		{name: "legacy", response: response{AccessToken: "legacy-access-token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := oidctest.NewContext(t)
			recorder := httptest.NewRecorder()
			ctx.Response = recorder
			ctx.Request = httptest.NewRequest(http.MethodPost, ctx.TokenURL(), nil)
			if err := writeTokenResponse(ctx, test.response); err != nil {
				t.Fatalf("writeTokenResponse() error = %v", err)
			}
			if got := recorder.Header().Get("Cache-Control"); got != test.wantCache {
				t.Fatalf("Cache-Control = %q, want %q", got, test.wantCache)
			}
			if got := recorder.Header().Get("Pragma"); got != test.wantPragma {
				t.Fatalf("Pragma = %q, want %q", got, test.wantPragma)
			}
			if strings.Contains(recorder.Body.String(), "noStore") {
				t.Fatalf("internal cache marker leaked into JSON: %s", recorder.Body.String())
			}
		})
	}
}

func TestHumanAuthorizationStrictOnlyProviderNeverCallsLegacyCodeManager(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
	fixture.ctx.LegacyAuthorizationCodeEnabled = false
	fixture.ctx.AuthManager = humanTokenPanicAuthManager{}
	fixture.ctx.Request.PostForm["code"] = []string{"legacy-authorization-code"}

	_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, err, goidc.ErrorCodeServerError)
	if fixture.authority.redeemCalls != 0 {
		t.Fatalf("strict-only default-profile request reached human authority %d times", fixture.authority.redeemCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanAuthorizationCodeNamespaceCannotFallThroughAfterProfileDowngrade(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
	fixture.ctx.LegacyAuthorizationCodeEnabled = true
	fixture.ctx.AuthManager = humanTokenPanicAuthManager{}

	_, err := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.redeemCalls != 0 {
		t.Fatalf("downgraded strict code reached human authority %d times", fixture.authority.redeemCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanAuthorizationCodeSigningFailureBurnsCode(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	redeemed := fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {})
	rejected := mustHumanRedemptionDecision(t, goidc.HumanCodeRedemptionDecisionConfig{
		Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
	})
	fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		if fixture.authority.redeemCalls == 1 {
			return redeemed, nil
		}
		return rejected, nil
	}
	// Install a signer failure through JWKS retrieval so the first redemption
	// has already consumed the code before signing fails.
	fixture.ctx.SignerFunc = nil
	fixture.ctx.JWKSFunc = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{}, errors.New("signing authority unavailable")
	}
	_, firstErr := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, firstErr, goidc.ErrorCodeServerError)

	fixture.installRequest(t, "human-token-assertion-2")
	_, replayErr := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, replayErr, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.redeemCalls != 2 {
		t.Fatalf("RedeemAuthorizationCode() calls = %d, want 2", fixture.authority.redeemCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanAuthorizationCodeIDTokenSigningFailureBurnsCode(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	redeemed := fixture.redeemedDecision(t, func(*goidc.HumanCodeRedemptionDecisionConfig) {})
	rejected := mustHumanRedemptionDecision(t, goidc.HumanCodeRedemptionDecisionConfig{
		Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
	})
	fixture.authority.redeem = func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
		if fixture.authority.redeemCalls == 1 {
			return redeemed, nil
		}
		return rejected, nil
	}
	originalJWKS := fixture.ctx.JWKSFunc
	signingCalls := 0
	fixture.ctx.SignerFunc = nil
	fixture.ctx.JWKSFunc = func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		signingCalls++
		if signingCalls == 2 {
			return goidc.JSONWebKeySet{}, errors.New("ID-token signing authority unavailable")
		}
		return originalJWKS(ctx)
	}
	firstResponse, firstErr := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, firstErr, goidc.ErrorCodeServerError)
	if firstResponse.AccessToken != "" || firstResponse.IDToken != "" ||
		firstResponse.RefreshToken != "" || firstResponse.RefreshTokenExpiresIn != 0 ||
		firstResponse.ExpiresIn != 0 ||
		firstResponse.TokenType != "" || firstResponse.Scopes != "" ||
		firstResponse.AuthorizationDetails != nil || firstResponse.Resources != nil ||
		firstResponse.IssuedTokenType != "" || firstResponse.noStore {
		t.Fatalf("ID-token signing failure leaked a partial response: %#v", firstResponse)
	}

	fixture.installRequest(t, "human-token-assertion-id-signing-replay")
	_, replayErr := generateAuthCodeToken(fixture.ctx, newRequest(fixture.ctx.Request))
	assertHumanTokenError(t, replayErr, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.redeemCalls != 2 || signingCalls != 2 {
		t.Fatalf("redeem/signing calls = %d/%d, want 2/2", fixture.authority.redeemCalls, signingCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

type humanTokenFixture struct {
	ctx               oidc.Context
	client            *goidc.Client
	assertionKey      goidc.JSONWebKey
	verifiedAuthority goidc.VerifiedClientAssertionAuthority
	authority         *humanTokenAuthorityStub
	authManager       *humanTokenAuthManagerSpy
	grantManager      *humanTokenGrantManagerSpy
	legacyCalls       *humanTokenLegacyCalls
}

func newHumanTokenFixture(t *testing.T) *humanTokenFixture {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.HumanConfidentialBFFAuthorizationEnabled = true
	ctx.HumanAccessTokenLifetimeSecs = 300
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.IDTokenDefaultSigAlg = goidc.SigAlgPS256
	ctx.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.IDTokenLifetimeSecs = 600
	ctx.JWTLifetimeSecs = 60
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{
		goidc.SubIdentifierPublic,
		goidc.SubIdentifierPairwise,
	}
	ctx.Scopes = append(ctx.Scopes, goidc.ScopeProfile)
	ctx.ACRs = []goidc.ACR{"urn:d0:acr:passkey"}
	ctx.ResourceIndicatorsEnabled = true
	ctx.ResourceIndicators = []goidc.ResourceIndicator{"https://api.example.invalid/accounting"}

	firstKey := oidctest.PrivatePS256JWK(t, "human-key-a", goidc.KeyUsageSignature)
	assertionKey := oidctest.PrivatePS256JWK(t, "human-key-b", goidc.KeyUsageSignature)
	verifiedAuthority := goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 17,
		KeyAuthorityID:   "human-key-authority-b",
	}
	client := &goidc.Client{
		ID:                          testHumanClientID,
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 17,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{
				{Key: firstKey.Public(), KeyAuthorityID: "human-key-authority-a"},
				{Key: assertionKey.Public(), KeyAuthorityID: verifiedAuthority.KeyAuthorityID},
			},
		},
		ClientMeta: goidc.ClientMeta{
			ApplicationType: goidc.ApplicationTypeWeb,
			RedirectURIs:    []string{testHumanRedirectURI},
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes:     []goidc.ResponseType{goidc.ResponseTypeCode},
			ScopeIDs:          "openid profile",
			SubIdentifierType: goidc.SubIdentifierPairwise,
			IDTokenSigAlg:     goidc.SigAlgPS256,
			TokenAuthnMethod:  goidc.AuthnMethodPrivateKeyJWT,
			TokenAuthnSigAlg:  goidc.SigAlgPS256,
		},
	}
	ctx.StaticClients = []*goidc.Client{client}

	authority := &humanTokenAuthorityStub{}
	authManager := &humanTokenAuthManagerSpy{}
	grantManager := &humanTokenGrantManagerSpy{}
	legacyCalls := &humanTokenLegacyCalls{}
	ctx.HumanAuthorizationAuthority = authority
	ctx.AuthManager = authManager
	ctx.GrantManager = grantManager
	ctx.TokenOptionsFunc = func(context.Context, *goidc.Grant, *goidc.Client) goidc.TokenOptions {
		legacyCalls.tokenOptions++
		return goidc.TokenOptions{Format: goidc.TokenFormatOpaque, LifetimeSecs: 1}
	}
	ctx.TokenClaimsFunc = func(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
		legacyCalls.tokenClaims++
		return map[string]any{"attacker_claim": true}
	}
	ctx.IDTokenClaimsFunc = func(context.Context, *goidc.Grant) map[string]any {
		legacyCalls.idTokenClaims++
		return map[string]any{"attacker_claim": true}
	}
	ctx.HandleTokenFunc = func(context.Context, *goidc.Token, *goidc.Grant) error {
		legacyCalls.handleToken++
		return nil
	}
	ctx.PairwiseSubjectFunc = func(context.Context, string, *goidc.Client) string {
		legacyCalls.pairwiseSubject++
		return "callback-substitution"
	}
	ctx.OpaqueTokenFunc = func(context.Context, *goidc.Grant) string {
		legacyCalls.opaqueToken++
		return "opaque-substitution"
	}
	ctx.RefreshTokenShouldIssueFunc = func(context.Context, *goidc.Client, *goidc.Grant) bool {
		legacyCalls.refreshToken++
		return true
	}
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
		legacyCalls.clientCertificate++
		return nil, errors.New("not admitted")
	}

	fixture := &humanTokenFixture{
		ctx: ctx, client: client, assertionKey: assertionKey,
		verifiedAuthority: verifiedAuthority, authority: authority,
		authManager: authManager, grantManager: grantManager, legacyCalls: legacyCalls,
	}
	fixture.installRequest(t, "human-token-assertion-1")
	return fixture
}

func (fixture *humanTokenFixture) installRequest(t *testing.T, assertionID string) {
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
		"grant_type":            {string(goidc.GrantAuthorizationCode)},
		"code":                  {testHumanAuthorizationCode},
		"redirect_uri":          {testHumanRedirectURI},
		"code_verifier":         {testHumanCodeVerifier},
		"client_id":             {fixture.client.ID},
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		fixture.ctx.Issuer()+fixture.ctx.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error = %v", err)
	}
	fixture.ctx.Request = request
}

func (fixture *humanTokenFixture) redeemedDecision(
	t *testing.T,
	mutate func(*goidc.HumanCodeRedemptionDecisionConfig),
) goidc.HumanCodeRedemptionDecision {
	t.Helper()
	now := int64(timeutil.TimestampNow())
	config := goidc.HumanCodeRedemptionDecisionConfig{
		Outcome:                  goidc.HumanCodeRedemptionOutcomeRedeemed,
		GrantID:                  "human-grant-0001",
		Subject:                  testHumanSubject,
		OrganizationID:           testHumanOrganizationID,
		MembershipID:             testHumanMembershipID,
		MembershipRevision:       7,
		ClientID:                 testHumanClientID,
		ClientAssertionAuthority: fixture.verifiedAuthority,
		Scopes:                   []string{"openid", "profile"},
		Resources:                []string{"https://api.example.invalid/accounting"},
		Nonce:                    "human-nonce-0001",
		AuthenticationTime:       now - 5,
		AuthenticationContext:    "urn:d0:acr:passkey",
		AuthenticationMethods:    []string{"passkey"},
		CreatedAt:                now,
		ExpiresAt:                now + 60,
	}
	mutate(&config)
	return mustHumanRedemptionDecision(t, config)
}

func (fixture *humanTokenFixture) assertNoLegacyIssuance(t *testing.T) {
	t.Helper()
	if fixture.authManager.grantByCode != 0 || fixture.authManager.saveSession != 0 || fixture.authManager.session != 0 ||
		fixture.grantManager.saveGrant != 0 || fixture.grantManager.grant != 0 ||
		*fixture.legacyCalls != (humanTokenLegacyCalls{}) {
		t.Fatalf(
			"strict redemption reached legacy authority/callbacks: auth=%#v grant=%#v callbacks=%#v",
			fixture.authManager,
			fixture.grantManager,
			fixture.legacyCalls,
		)
	}
}

type humanTokenLegacyCalls struct {
	tokenOptions      int
	tokenClaims       int
	idTokenClaims     int
	handleToken       int
	pairwiseSubject   int
	opaqueToken       int
	refreshToken      int
	clientCertificate int
}

type humanTokenAuthManagerSpy struct {
	saveSession int
	session     int
	grantByCode int
}

type humanTokenPanicAuthManager struct{}

func (humanTokenPanicAuthManager) SaveSession(context.Context, *goidc.AuthnSession) error {
	panic("legacy SaveSession called")
}
func (humanTokenPanicAuthManager) Session(context.Context, string) (*goidc.AuthnSession, error) {
	panic("legacy Session called")
}
func (humanTokenPanicAuthManager) GrantByAuthCode(context.Context, string) (*goidc.Grant, error) {
	panic("legacy GrantByAuthCode called")
}

func (manager *humanTokenAuthManagerSpy) SaveSession(context.Context, *goidc.AuthnSession) error {
	manager.saveSession++
	return errors.New("legacy SaveSession called")
}
func (manager *humanTokenAuthManagerSpy) Session(context.Context, string) (*goidc.AuthnSession, error) {
	manager.session++
	return nil, errors.New("legacy Session called")
}
func (manager *humanTokenAuthManagerSpy) GrantByAuthCode(context.Context, string) (*goidc.Grant, error) {
	manager.grantByCode++
	return nil, goidc.ErrNotFound
}

type humanTokenGrantManagerSpy struct {
	saveGrant int
	grant     int
}

func (manager *humanTokenGrantManagerSpy) SaveGrant(context.Context, *goidc.Grant) error {
	manager.saveGrant++
	return errors.New("legacy SaveGrant called")
}
func (manager *humanTokenGrantManagerSpy) Grant(context.Context, string) (*goidc.Grant, error) {
	manager.grant++
	return nil, goidc.ErrNotFound
}

type humanTokenAuthorityStub struct {
	redeem        func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error)
	redeemCalls   int
	prepare       func(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error)
	prepareCalls  int
	activate      func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error)
	activateCalls int
	abort         func(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error)
	abortCalls    int
	revoke        func(context.Context, goidc.HumanRefreshRevocationInput) error
	revokeCalls   int
}

func (*humanTokenAuthorityStub) StorePAR(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
	panic("unexpected StorePAR")
}
func (*humanTokenAuthorityStub) ConsumePARAndStartContinuation(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
	panic("unexpected ConsumePARAndStartContinuation")
}
func (*humanTokenAuthorityStub) ConfirmBrowser(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
	panic("unexpected ConfirmBrowser")
}
func (*humanTokenAuthorityStub) CompleteAuthorization(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
	panic("unexpected CompleteAuthorization")
}
func (authority *humanTokenAuthorityStub) RedeemAuthorizationCode(
	ctx context.Context,
	input goidc.HumanCodeRedemptionInput,
) (goidc.HumanCodeRedemptionDecision, error) {
	authority.redeemCalls++
	if authority.redeem == nil {
		panic("unexpected RedeemAuthorizationCode")
	}
	return authority.redeem(ctx, input)
}
func (authority *humanTokenAuthorityStub) PrepareHumanRefreshDelivery(
	ctx context.Context,
	input goidc.HumanRefreshDeliveryPrepareInput,
) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
	authority.prepareCalls++
	if authority.prepare == nil {
		panic("unexpected PrepareHumanRefreshDelivery")
	}
	return authority.prepare(ctx, input)
}
func (authority *humanTokenAuthorityStub) ActivateHumanRefreshDelivery(
	ctx context.Context,
	input goidc.HumanRefreshDeliveryActivateInput,
) (goidc.HumanRefreshDeliveryActivateDecision, error) {
	authority.activateCalls++
	if authority.activate == nil {
		panic("unexpected ActivateHumanRefreshDelivery")
	}
	return authority.activate(ctx, input)
}
func (authority *humanTokenAuthorityStub) AbortHumanRefreshDelivery(
	ctx context.Context,
	input goidc.HumanRefreshDeliveryAbortInput,
) (goidc.HumanRefreshDeliveryAbortDecision, error) {
	authority.abortCalls++
	if authority.abort == nil {
		panic("unexpected AbortHumanRefreshDelivery")
	}
	return authority.abort(ctx, input)
}
func (authority *humanTokenAuthorityStub) RevokeRefreshToken(
	ctx context.Context,
	input goidc.HumanRefreshRevocationInput,
) error {
	authority.revokeCalls++
	if authority.revoke == nil {
		panic("unexpected RevokeRefreshToken")
	}
	return authority.revoke(ctx, input)
}

func mustHumanRedemptionDecision(
	t *testing.T,
	config goidc.HumanCodeRedemptionDecisionConfig,
) goidc.HumanCodeRedemptionDecision {
	t.Helper()
	decision, err := goidc.NewHumanCodeRedemptionDecision(config)
	if err != nil {
		t.Fatalf("NewHumanCodeRedemptionDecision() error = %v", err)
	}
	return decision
}

func parseHumanPS256Token(
	t *testing.T,
	ctx oidc.Context,
	value string,
	wantType string,
) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(value, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatalf("parse PS256 token: %v", err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].Algorithm != string(jose.PS256) ||
		parsed.Headers[0].ExtraHeaders[jose.HeaderType] != wantType {
		t.Fatalf("token header = %#v, want exact PS256 typ %q", parsed.Headers, wantType)
	}
	key := oidctest.PrivateJWKS(t, ctx).Keys[0]
	var claims map[string]any
	if err := parsed.Claims(key.Public().Key, &claims); err != nil {
		t.Fatalf("verify PS256 token: %v", err)
	}
	return claims
}

func assertHumanTokenClaim(t *testing.T, claims map[string]any, name string, want any) {
	t.Helper()
	if got := claims[name]; got != want {
		t.Fatalf("claim %q = %#v, want %#v", name, got, want)
	}
}

func integerClaim(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()
	value, ok := claims[name].(float64)
	if !ok || value != float64(int64(value)) {
		t.Fatalf("claim %q = %#v, want integer", name, claims[name])
	}
	return int64(value)
}

func stringSliceClaim(t *testing.T, claims map[string]any, name string) []string {
	t.Helper()
	values, ok := claims[name].([]any)
	if !ok {
		t.Fatalf("claim %q = %#v, want string array", name, claims[name])
	}
	result := make([]string, len(values))
	for index, value := range values {
		item, ok := value.(string)
		if !ok {
			t.Fatalf("claim %q[%d] = %#v, want string", name, index, value)
		}
		result[index] = item
	}
	return result
}

func assertHumanTokenError(t *testing.T, err error, want goidc.ErrorCode) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.Code != want {
		t.Fatalf("error = %v, want goidc error %q", err, want)
	}
}

var _ goidc.HumanAuthorizationAuthority = (*humanTokenAuthorityStub)(nil)
