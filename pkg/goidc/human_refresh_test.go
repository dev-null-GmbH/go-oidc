package goidc_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	testHumanRefreshToken          = "d0_hrt_1_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	testHumanSuccessorRefreshToken = "d0_hrt_1_CwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
)

func TestHumanRefreshTokenIsPurposeSeparatedRedactedAndNonSerializable(t *testing.T) {
	t.Parallel()

	token, err := goidc.NewHumanRefreshToken(testHumanRefreshToken)
	if err != nil || !token.Valid() {
		t.Fatalf("NewHumanRefreshToken() = %#v, %v", token, err)
	}
	if rendered, renderErr := token.Render(); renderErr != nil || rendered != testHumanRefreshToken {
		t.Fatalf("Render() = %q, %v", rendered, renderErr)
	}
	if got := fmt.Sprintf("%v", token); strings.Contains(got, testHumanRefreshToken) {
		t.Fatalf("formatted refresh token leaked capability: %q", got)
	}
	if encoded, marshalErr := json.Marshal(token); marshalErr == nil || encoded != nil {
		t.Fatalf("json.Marshal() = %q, %v; want nil, error", encoded, marshalErr)
	}
	for _, value := range []string{
		"d0_hac_1_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
		"d0_hrt_1_" + strings.Repeat("A", 43),
		testHumanRefreshToken[:len(testHumanRefreshToken)-1] + "F",
	} {
		if candidate, candidateErr := goidc.NewHumanRefreshToken(value); candidateErr == nil || candidate.Valid() {
			t.Fatalf("NewHumanRefreshToken(%q) = %#v, %v; want invalid", value, candidate, candidateErr)
		}
	}
}

func TestHumanCodeRedemptionRefreshCapabilityRequiresOfflineAccess(t *testing.T) {
	t.Parallel()

	refreshToken := mustHumanRefreshToken(t, testHumanRefreshToken)
	base := humanCodeRedemptionRefreshConfig(t)
	decision, err := goidc.NewHumanCodeRedemptionDecision(base)
	if err != nil || !decision.Valid() {
		t.Fatalf("NewHumanCodeRedemptionDecision() = %#v, %v", decision, err)
	}
	gotRefreshToken, ok := decision.RefreshToken()
	if !ok || !gotRefreshToken.Valid() {
		t.Fatal("RefreshToken() omitted offline_access capability")
	}
	if rendered, renderErr := gotRefreshToken.Render(); renderErr != nil || rendered != testHumanRefreshToken {
		t.Fatalf("RefreshToken().Render() = %q, %v", rendered, renderErr)
	}
	if decision.RefreshTokenExpiresAt() != base.RefreshTokenExpiresAt {
		t.Fatalf("RefreshTokenExpiresAt() = %d, want %d", decision.RefreshTokenExpiresAt(), base.RefreshTokenExpiresAt)
	}

	withoutOffline := base
	withoutOffline.Scopes = []string{"openid", "profile"}
	withoutOffline.RefreshToken = goidc.HumanRefreshToken{}
	withoutOffline.RefreshTokenExpiresAt = 0
	decision, err = goidc.NewHumanCodeRedemptionDecision(withoutOffline)
	if err != nil || !decision.Valid() {
		t.Fatalf("online-only redemption = %#v, %v", decision, err)
	}
	if token, present := decision.RefreshToken(); present || token.Valid() || decision.RefreshTokenExpiresAt() != 0 {
		t.Fatalf("online-only decision exposed refresh facts: %#v, %v, %d", token, present, decision.RefreshTokenExpiresAt())
	}

	tests := []struct {
		name   string
		mutate func(*goidc.HumanCodeRedemptionDecisionConfig)
	}{
		{name: "offline without token", mutate: func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			config.RefreshToken = goidc.HumanRefreshToken{}
		}},
		{name: "offline without expiry", mutate: func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			config.RefreshTokenExpiresAt = 0
		}},
		{name: "token without offline", mutate: func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			config.Scopes = []string{"openid", "profile"}
		}},
		{name: "family exceeds 24 hours", mutate: func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			config.RefreshTokenExpiresAt = config.CreatedAt + 86_401
		}},
		{name: "rejected carries token", mutate: func(config *goidc.HumanCodeRedemptionDecisionConfig) {
			*config = goidc.HumanCodeRedemptionDecisionConfig{
				Outcome:               goidc.HumanCodeRedemptionOutcomeRejected,
				RefreshToken:          refreshToken,
				RefreshTokenExpiresAt: base.RefreshTokenExpiresAt,
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Scopes = append([]string(nil), base.Scopes...)
			candidate.Resources = append([]string(nil), base.Resources...)
			candidate.AuthenticationMethods = append([]string(nil), base.AuthenticationMethods...)
			test.mutate(&candidate)
			if got, gotErr := goidc.NewHumanCodeRedemptionDecision(candidate); gotErr == nil || got.Valid() {
				t.Fatalf("NewHumanCodeRedemptionDecision() = %#v, %v; want invalid", got, gotErr)
			}
		})
	}
}

func TestHumanRefreshRotationTypesAreClosedDefensiveAndAuthorityBound(t *testing.T) {
	t.Parallel()

	refreshToken := mustHumanRefreshToken(t, testHumanRefreshToken)
	authority := goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 7,
		KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
	}
	input, err := goidc.NewHumanRefreshRotationInput(goidc.HumanRefreshRotationInputConfig{
		RefreshToken:             refreshToken,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !input.Valid() || input.ClientID() != "dashboard.d0.eu" ||
		input.ClientAssertionAuthority() != authority {
		t.Fatalf("NewHumanRefreshRotationInput() = %#v, %v", input, err)
	}
	if rendered, renderErr := input.RefreshToken().Render(); renderErr != nil || rendered != testHumanRefreshToken {
		t.Fatalf("input refresh token = %q, %v", rendered, renderErr)
	}

	scopes := []string{"offline_access", "openid", "profile"}
	resources := []string{"https://api.d0.eu/accounting/v1"}
	authenticationMethods := []string{"passkey"}
	config := goidc.HumanRefreshRotationDecisionConfig{
		Outcome:                  goidc.HumanRefreshRotationOutcomeRotated,
		RefreshToken:             mustHumanRefreshToken(t, testHumanSuccessorRefreshToken),
		RefreshTokenExpiresAt:    1_787_666_400,
		GrantID:                  "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject:                  "pairwise-subject-0123456789abcdef",
		OrganizationID:           "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID:             "0199303d-5b4d-7d68-8806-60acc8861791",
		MembershipRevision:       4,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
		Scopes:                   scopes,
		Resources:                resources,
		AuthenticationTime:       1_787_580_000,
		AuthenticationContext:    "urn:d0:acr:passkey",
		AuthenticationMethods:    authenticationMethods,
		CreatedAt:                1_787_580_100,
		ExpiresAt:                1_787_580_160,
	}
	decision, err := goidc.NewHumanRefreshRotationDecision(config)
	if err != nil || !decision.Valid() || decision.Outcome() != goidc.HumanRefreshRotationOutcomeRotated {
		t.Fatalf("NewHumanRefreshRotationDecision() = %#v, %v", decision, err)
	}
	scopes[0], resources[0], authenticationMethods[0] = "mutated", "mutated", "mutated"
	if decision.Scopes()[0] != "offline_access" ||
		decision.Resources()[0] != "https://api.d0.eu/accounting/v1" ||
		decision.AuthenticationMethods()[0] != "passkey" {
		t.Fatal("rotation decision retained caller-owned slices")
	}
	if decision.ClientAssertionAuthority() != authority || decision.AuthenticationTime() != config.AuthenticationTime ||
		decision.AuthenticationContext() != config.AuthenticationContext ||
		decision.RefreshTokenExpiresAt() != config.RefreshTokenExpiresAt {
		t.Fatal("rotation decision lost immutable authentication or expiry facts")
	}
	assertHumanValueRedacted(t, input, testHumanRefreshToken)
	assertHumanValueRedacted(t, decision, testHumanSuccessorRefreshToken)

	rejected, err := goidc.NewHumanRefreshRotationDecision(goidc.HumanRefreshRotationDecisionConfig{
		Outcome: goidc.HumanRefreshRotationOutcomeRejected,
	})
	if err != nil || !rejected.Valid() {
		t.Fatalf("rejected rotation = %#v, %v", rejected, err)
	}
	if token, present := rejected.RefreshToken(); present || token.Valid() {
		t.Fatalf("rejected rotation exposed successor: %#v, %v", token, present)
	}
}

func TestHumanRefreshRevocationInputIsClosedRedactedAndAuthorityBound(t *testing.T) {
	t.Parallel()

	refreshToken := mustHumanRefreshToken(t, testHumanRefreshToken)
	authority := goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 7,
		KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
	}
	input, err := goidc.NewHumanRefreshRevocationInput(goidc.HumanRefreshRevocationInputConfig{
		RefreshToken:             refreshToken,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !input.Valid() || input.ClientID() != "dashboard.d0.eu" ||
		input.ClientAssertionAuthority() != authority {
		t.Fatalf("NewHumanRefreshRevocationInput() = %#v, %v", input, err)
	}
	if rendered, renderErr := input.RefreshToken().Render(); renderErr != nil || rendered != testHumanRefreshToken {
		t.Fatalf("input refresh token = %q, %v", rendered, renderErr)
	}
	assertHumanValueRedacted(t, input, testHumanRefreshToken)

	for _, test := range []struct {
		name   string
		mutate func(*goidc.HumanRefreshRevocationInputConfig)
	}{
		{name: "missing token", mutate: func(config *goidc.HumanRefreshRevocationInputConfig) {
			config.RefreshToken = goidc.HumanRefreshToken{}
		}},
		{name: "invalid client", mutate: func(config *goidc.HumanRefreshRevocationInputConfig) {
			config.ClientID = ""
		}},
		{name: "missing authority revision", mutate: func(config *goidc.HumanRefreshRevocationInputConfig) {
			config.ClientAssertionAuthority.SnapshotRevision = 0
		}},
		{name: "invalid authority key", mutate: func(config *goidc.HumanRefreshRevocationInputConfig) {
			config.ClientAssertionAuthority.KeyAuthorityID = "contains spaces"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := goidc.HumanRefreshRevocationInputConfig{
				RefreshToken:             refreshToken,
				ClientID:                 "dashboard.d0.eu",
				ClientAssertionAuthority: authority,
			}
			test.mutate(&config)
			if candidate, candidateErr := goidc.NewHumanRefreshRevocationInput(config); candidateErr == nil || candidate.Valid() {
				t.Fatalf("NewHumanRefreshRevocationInput() = %#v, %v; want invalid", candidate, candidateErr)
			}
		})
	}
}

func TestHumanRefreshRotationDecisionRejectsOpenOrIncoherentShapes(t *testing.T) {
	t.Parallel()

	base := humanRefreshRotationConfig(t)
	tests := []struct {
		name   string
		mutate func(*goidc.HumanRefreshRotationDecisionConfig)
	}{
		{name: "missing offline access", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.Scopes = []string{"openid", "profile"}
		}},
		{name: "missing successor", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.RefreshToken = goidc.HumanRefreshToken{}
		}},
		{name: "expired family", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.RefreshTokenExpiresAt = config.CreatedAt
		}},
		{name: "family beyond 24 hours", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.RefreshTokenExpiresAt = config.CreatedAt + 86_401
		}},
		{name: "stale issuance snapshot", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.ExpiresAt = config.CreatedAt + 601
		}},
		{name: "missing authentication context", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.AuthenticationContext = ""
		}},
		{name: "authority revision missing", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			config.ClientAssertionAuthority.SnapshotRevision = 0
		}},
		{name: "rejected carries identity", mutate: func(config *goidc.HumanRefreshRotationDecisionConfig) {
			*config = goidc.HumanRefreshRotationDecisionConfig{
				Outcome: goidc.HumanRefreshRotationOutcomeRejected,
				Subject: "pairwise-subject-0123456789abcdef",
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Scopes = append([]string(nil), base.Scopes...)
			candidate.Resources = append([]string(nil), base.Resources...)
			candidate.AuthenticationMethods = append([]string(nil), base.AuthenticationMethods...)
			test.mutate(&candidate)
			if got, err := goidc.NewHumanRefreshRotationDecision(candidate); err == nil || got.Valid() {
				t.Fatalf("NewHumanRefreshRotationDecision() = %#v, %v; want invalid", got, err)
			}
		})
	}
}

func humanCodeRedemptionRefreshConfig(t *testing.T) goidc.HumanCodeRedemptionDecisionConfig {
	t.Helper()
	return goidc.HumanCodeRedemptionDecisionConfig{
		Outcome:               goidc.HumanCodeRedemptionOutcomeRedeemed,
		RefreshToken:          mustHumanRefreshToken(t, testHumanRefreshToken),
		RefreshTokenExpiresAt: 1_787_666_400,
		GrantID:               "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject:               "pairwise-subject-0123456789abcdef",
		OrganizationID:        "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID:          "0199303d-5b4d-7d68-8806-60acc8861791",
		MembershipRevision:    4,
		ClientID:              "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
		Scopes:                []string{"offline_access", "openid", "profile"},
		Resources:             []string{"https://api.d0.eu/accounting/v1"},
		Nonce:                 "nonce-0123456789abcdef",
		AuthenticationTime:    1_787_580_000,
		AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: []string{"passkey"},
		CreatedAt:             1_787_580_100,
		ExpiresAt:             1_787_580_160,
	}
}

func humanRefreshRotationConfig(t *testing.T) goidc.HumanRefreshRotationDecisionConfig {
	t.Helper()
	return goidc.HumanRefreshRotationDecisionConfig{
		Outcome:               goidc.HumanRefreshRotationOutcomeRotated,
		RefreshToken:          mustHumanRefreshToken(t, testHumanSuccessorRefreshToken),
		RefreshTokenExpiresAt: 1_787_666_400,
		GrantID:               "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject:               "pairwise-subject-0123456789abcdef",
		OrganizationID:        "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID:          "0199303d-5b4d-7d68-8806-60acc8861791",
		MembershipRevision:    4,
		ClientID:              "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
		Scopes:                []string{"offline_access", "openid", "profile"},
		Resources:             []string{"https://api.d0.eu/accounting/v1"},
		AuthenticationTime:    1_787_580_000,
		AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: []string{"passkey"},
		CreatedAt:             1_787_580_100,
		ExpiresAt:             1_787_580_160,
	}
}

func mustHumanRefreshToken(t *testing.T, value string) goidc.HumanRefreshToken {
	t.Helper()
	token, err := goidc.NewHumanRefreshToken(value)
	if err != nil {
		t.Fatalf("NewHumanRefreshToken() error = %v", err)
	}
	return token
}
