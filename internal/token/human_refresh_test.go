package token

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	testHumanRefreshToken          = "d0_hrt_1_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	testHumanSuccessorRefreshToken = "d0_hrt_1_CwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	testHumanDeliveryReceipt       = "d0_hrd_1_DwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
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
		t.Fatal("offline token response is incoherent")
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
		t.Fatal("online token response exposed refresh fields")
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
	} {
		t.Run(test.name, func(t *testing.T) {
			value, expiresIn, err := humanRefreshTokenResponse(capability, true, test.expiresAt, now, test.skew)
			if (err != nil) != test.wantError {
				t.Fatalf("humanRefreshTokenResponse() error = %v, wantError %t", err, test.wantError)
			}
			if test.wantError {
				if value != "" || expiresIn != 0 {
					t.Fatal("failure returned partial refresh response")
				}
				return
			}
			if value != testHumanRefreshToken || expiresIn != test.want {
				t.Fatal("refresh response lifetime mismatch")
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
	if resp.RefreshToken != testHumanRefreshToken || resp.RefreshTokenExpiresIn != humanTokenMaximumRefreshLife {
		t.Fatal("database-ahead token response is incoherent")
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestStrictHumanRefreshGrantCannotUseDestructiveTokenEndpointRotation(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.ctx.RefreshTokenManager = humanRefreshTokenPanicManager{}
	now := timeutil.TimestampNow()
	assertion := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer: fixture.client.ID, goidc.ClaimSubject: fixture.client.ID,
		goidc.ClaimAudience: fixture.ctx.Issuer(), goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry: now + 50, goidc.ClaimTokenID: "refresh-grant-must-fail-closed",
	}, fixture.assertionKey)
	values := url.Values{
		"grant_type": {string(goidc.GrantRefreshToken)}, "refresh_token": {testHumanRefreshToken},
		"client_id": {fixture.client.ID}, "client_assertion": {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	request, err := http.NewRequest(http.MethodPost, fixture.ctx.Issuer()+fixture.ctx.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	fixture.ctx.Request = request

	_, err = generateRefreshToken(fixture.ctx, newRequest(request))
	assertHumanTokenError(t, err, goidc.ErrorCodeInvalidGrant)
	if fixture.authority.prepareCalls != 0 || fixture.authority.activateCalls != 0 || fixture.authority.abortCalls != 0 {
		t.Fatal("legacy refresh grant reached delivery authority")
	}
	fixture.assertNoLegacyIssuance(t)
}

func (fixture *humanTokenFixture) enableOfflineAccess() {
	fixture.ctx.Scopes = append(fixture.ctx.Scopes, goidc.ScopeOfflineAccess)
	fixture.client.ScopeIDs = "offline_access openid profile"
}

func mustHumanRefreshToken(t *testing.T, value string) goidc.HumanRefreshToken {
	t.Helper()
	token, err := goidc.NewHumanRefreshToken(value)
	if err != nil {
		t.Fatalf("NewHumanRefreshToken() error = %v", err)
	}
	return token
}

type humanRefreshTokenPanicManager struct{}

func (humanRefreshTokenPanicManager) GrantByRefreshToken(context.Context, string) (*goidc.Grant, error) {
	panic("legacy RefreshTokenManager called")
}
