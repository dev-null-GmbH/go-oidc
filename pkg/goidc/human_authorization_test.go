package goidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	testHumanRequestURI        = goidc.HumanPushedRequestURIPrefix + "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	testEntryCapability        = "d0_hio_e1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	testBindingCapability      = "d0_hio_b1_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
	testReturnCapability       = "d0_hio_r1_AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"
	testConfirmationCapability = "d0_hio_c1_BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
	testReadyCapability        = "d0_hio_s1_BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
	testAuthorizationCode      = "d0_hac_1_BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY"
)

func TestHumanPARInputIsClosedDefensiveAndRedacted(t *testing.T) {
	scopes := []string{"einvoice.documents:read", "openid"}
	resources := []string{"https://api.d0.eu/accounting/v1"}
	acrValues := []goidc.ACR{"urn:d0:acr:passkey"}
	maxAge := 300
	input, err := goidc.NewHumanPARInput(goidc.HumanPARInputConfig{
		ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
		RedirectURI:          "https://dashboard.d0.eu/oidc/callback",
		Scopes:               scopes,
		Resources:            resources,
		State:                "state-0123456789abcdef",
		Nonce:                "nonce-0123456789abcdef",
		CodeChallenge:        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
		Prompt:               goidc.PromptTypeLogin,
		MaxAuthenticationAge: &maxAge,
		ACRValues:            acrValues,
	})
	if err != nil {
		t.Fatalf("NewHumanPARInput() error = %v", err)
	}
	if !input.Valid() {
		t.Fatal("HumanPARInput.Valid() = false")
	}

	scopes[0] = "mutated"
	resources[0] = "https://mutated.example"
	acrValues[0] = "mutated"
	maxAge = 999
	gotScopes := input.Scopes()
	gotResources := input.Resources()
	gotACRs := input.ACRValues()
	gotMaxAge, ok := input.MaxAuthenticationAge()
	if !ok || gotMaxAge != 300 || gotScopes[0] != "einvoice.documents:read" ||
		gotResources[0] != "https://api.d0.eu/accounting/v1" || gotACRs[0] != "urn:d0:acr:passkey" {
		t.Fatalf("input accessors were affected by caller mutation: scopes=%v resources=%v acr=%v max_age=%d,%v", gotScopes, gotResources, gotACRs, gotMaxAge, ok)
	}
	gotScopes[0] = "mutated-again"
	if input.Scopes()[0] != "einvoice.documents:read" {
		t.Fatal("Scopes() did not return a defensive copy")
	}
	if input.ResponseType() != goidc.ResponseTypeCode || input.ResponseMode() != goidc.ResponseModeQuery ||
		input.CodeChallengeMethod() != goidc.CodeChallengeMethodSHA256 {
		t.Fatal("closed PAR constants are not fixed to code/query/S256")
	}
	assertHumanValueRedacted(t, input, "state-0123456789abcdef")
}

func TestHumanPARInputRejectsOpenOrAmbiguousValues(t *testing.T) {
	valid := validHumanPARInputConfig()
	tests := []struct {
		name   string
		mutate func(*goidc.HumanPARInputConfig)
	}{
		{name: "zero authority revision", mutate: func(c *goidc.HumanPARInputConfig) { c.ClientAssertionAuthority.SnapshotRevision = 0 }},
		{name: "unbounded authority key", mutate: func(c *goidc.HumanPARInputConfig) {
			c.ClientAssertionAuthority.KeyAuthorityID = strings.Repeat("a", 129)
		}},
		{name: "http redirect", mutate: func(c *goidc.HumanPARInputConfig) { c.RedirectURI = "http://dashboard.d0.eu/callback" }},
		{name: "unsorted scopes", mutate: func(c *goidc.HumanPARInputConfig) { c.Scopes = []string{"openid", "einvoice.documents:read"} }},
		{name: "duplicate resources", mutate: func(c *goidc.HumanPARInputConfig) {
			c.Resources = []string{"https://api.d0.eu/accounting/v1", "https://api.d0.eu/accounting/v1"}
		}},
		{name: "missing resource", mutate: func(c *goidc.HumanPARInputConfig) { c.Resources = nil }},
		{name: "short state", mutate: func(c *goidc.HumanPARInputConfig) { c.State = "short" }},
		{name: "invalid challenge", mutate: func(c *goidc.HumanPARInputConfig) { c.CodeChallenge = strings.Repeat("+", 43) }},
		{name: "zero challenge", mutate: func(c *goidc.HumanPARInputConfig) { c.CodeChallenge = strings.Repeat("A", 43) }},
		{name: "noncanonical challenge", mutate: func(c *goidc.HumanPARInputConfig) {
			c.CodeChallenge = c.CodeChallenge[:len(c.CodeChallenge)-1] + "F"
		}},
		{name: "unsupported prompt", mutate: func(c *goidc.HumanPARInputConfig) { c.Prompt = goidc.PromptTypeConsent }},
		{name: "too many acrs", mutate: func(c *goidc.HumanPARInputConfig) { c.ACRValues = []goidc.ACR{"urn:d0:acr:a", "urn:d0:acr:b"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Scopes = append([]string(nil), valid.Scopes...)
			candidate.Resources = append([]string(nil), valid.Resources...)
			candidate.ACRValues = append([]goidc.ACR(nil), valid.ACRValues...)
			test.mutate(&candidate)
			if got, err := goidc.NewHumanPARInput(candidate); err == nil || got.Valid() {
				t.Fatalf("NewHumanPARInput() = %#v, %v; want invalid", got, err)
			}
		})
	}
}

func TestHumanBearerCapabilitiesRequireStrictNamespaceAndCanonicalNonzeroEntropy(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{name: "legacy request URI namespace", call: func() error {
			_, err := goidc.NewHumanPushedRequestURI("urn:ietf:params:oauth:request_uri:0199303d-5b4d-7d68-8806-60acc886178d")
			return err
		}},
		{name: "zero request URI", call: func() error {
			_, err := goidc.NewHumanPushedRequestURI(goidc.HumanPushedRequestURIPrefix + strings.Repeat("A", 43))
			return err
		}},
		{name: "zero entry", call: func() error {
			_, err := goidc.NewHumanInteractionEntryCapability("d0_hio_e1_" + strings.Repeat("A", 43))
			return err
		}},
		{name: "noncanonical entry", call: func() error {
			_, err := goidc.NewHumanInteractionEntryCapability(testEntryCapability[:len(testEntryCapability)-1] + "F")
			return err
		}},
		{name: "zero authorization code", call: func() error {
			_, err := goidc.NewHumanAuthorizationCode("d0_hac_1_" + strings.Repeat("A", 43))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("constructor accepted ambiguous or zero bearer capability")
			}
		})
	}
}

func TestHumanAuthorizationStageTypesRejectSubstitutionAndInvalidOutcomeShapes(t *testing.T) {
	requestURI := mustHumanPushedRequestURI(t, testHumanRequestURI)
	entry := mustHumanEntry(t, testEntryCapability)
	binding := mustHumanBinding(t, testBindingCapability)
	identityReturn := mustHumanIdentityReturn(t, testReturnCapability)
	browserReturn := mustHumanBrowserReturn(t, testConfirmationCapability)
	ready := mustHumanReady(t, testReadyCapability)
	code := mustHumanCode(t, testAuthorizationCode)

	receipt, err := goidc.NewHumanPARReceipt(requestURI, 300)
	if err != nil || !receipt.Valid() || receipt.ExpiresInSeconds() != 300 {
		t.Fatalf("NewHumanPARReceipt() = %#v, %v", receipt, err)
	}
	parDecision, err := goidc.NewHumanPARDecision(goidc.HumanPAROutcomeCreated, receipt)
	if err != nil || !parDecision.Valid() {
		t.Fatalf("NewHumanPARDecision() = %#v, %v", parDecision, err)
	}
	parRejected, err := goidc.NewHumanPARDecision(goidc.HumanPAROutcomeRejected, goidc.HumanPARReceipt{})
	if err != nil || !parRejected.Valid() {
		t.Fatalf("rejected PAR decision = %#v, %v", parRejected, err)
	}
	start, err := goidc.NewHumanStartInput("dashboard.d0.eu", requestURI)
	if err != nil || !start.Valid() {
		t.Fatalf("NewHumanStartInput() = %#v, %v", start, err)
	}
	startDecision, err := goidc.NewHumanStartDecision(goidc.HumanStartDecisionConfig{
		Outcome: goidc.HumanStartOutcomePending, EntryCapability: entry,
		BrowserBindingCapability: binding, ExpiresAt: 1_787_580_300,
	})
	if err != nil || !startDecision.Valid() {
		t.Fatalf("NewHumanStartDecision() = %#v, %v", startDecision, err)
	}
	startRejected, err := goidc.NewHumanStartDecision(goidc.HumanStartDecisionConfig{Outcome: goidc.HumanStartOutcomeRejected})
	if err != nil || !startRejected.Valid() {
		t.Fatalf("rejected start decision = %#v, %v", startRejected, err)
	}

	continuation, err := goidc.NewHumanContinuationInput(identityReturn, browserReturn, binding)
	if err != nil || !continuation.Valid() {
		t.Fatalf("NewHumanContinuationInput() = %#v, %v", continuation, err)
	}
	for _, outcome := range []goidc.HumanContinuationOutcome{
		goidc.HumanContinuationOutcomeConfirmed,
		goidc.HumanContinuationOutcomeReplayed,
	} {
		decision, decisionErr := goidc.NewHumanContinuationDecision(outcome, browserReturn)
		if decisionErr != nil || !decision.Valid() {
			t.Fatalf("NewHumanContinuationDecision(%q) = %#v, %v", outcome, decision, decisionErr)
		}
	}
	for _, outcome := range []goidc.HumanContinuationOutcome{
		goidc.HumanContinuationOutcomeExpired,
		goidc.HumanContinuationOutcomeRejected,
	} {
		decision, decisionErr := goidc.NewHumanContinuationDecision(outcome, goidc.HumanBrowserReturnCapability{})
		if decisionErr != nil || !decision.Valid() {
			t.Fatalf("NewHumanContinuationDecision(%q) = %#v, %v", outcome, decision, decisionErr)
		}
	}
	if decision, decisionErr := goidc.NewHumanContinuationDecision(goidc.HumanContinuationOutcomeExpired, browserReturn); decisionErr == nil || decision.Valid() {
		t.Fatal("expired continuation decision retained a successor")
	}

	completion, err := goidc.NewHumanCompletionInput(ready, binding)
	if err != nil || !completion.Valid() {
		t.Fatalf("NewHumanCompletionInput() = %#v, %v", completion, err)
	}
	completed, err := goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
		Outcome:                 goidc.HumanCompletionOutcomeCompleted,
		Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		ClientID:                "dashboard.d0.eu",
		ClientSnapshotRevision:  7,
		AdmissionKeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e",
		AuthorizationCode:       code,
		RedirectURI:             "https://dashboard.d0.eu/oidc/callback",
		State:                   "state-0123456789abcdef",
		CodeExpiresInSeconds:    60,
	})
	if err != nil || !completed.Valid() {
		t.Fatalf("completed decision = %#v, %v", completed, err)
	}
	failed, err := goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
		Outcome:                 goidc.HumanCompletionOutcomeFailed,
		Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		ClientID:                "dashboard.d0.eu",
		ClientSnapshotRevision:  7,
		AdmissionKeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e",
		RedirectURI:             "https://dashboard.d0.eu/oidc/callback",
		State:                   "state-0123456789abcdef",
		Failure:                 goidc.HumanAuthorizationFailureAccessDenied,
	})
	if err != nil || !failed.Valid() {
		t.Fatalf("failed decision = %#v, %v", failed, err)
	}
	if decision, decisionErr := goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
		Outcome: goidc.HumanCompletionOutcomeCompleted,
		Failure: goidc.HumanAuthorizationFailureAccessDenied,
	}); decisionErr == nil || decision.Valid() {
		t.Fatal("completed decision admitted failure fields or omitted completion fields")
	}
	for _, outcome := range []goidc.HumanCompletionOutcome{
		goidc.HumanCompletionOutcomeReplayed,
		goidc.HumanCompletionOutcomeExpired,
		goidc.HumanCompletionOutcomeRejected,
	} {
		decision, decisionErr := goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{Outcome: outcome})
		if decisionErr != nil || !decision.Valid() {
			t.Fatalf("terminal decision %q = %#v, %v", outcome, decision, decisionErr)
		}
	}

	for _, value := range []any{requestURI, entry, binding, identityReturn, browserReturn, ready, code, receipt, start, startDecision, continuation, completed} {
		assertHumanValueRedacted(t, value, "d0_hio")
	}
}

func TestHumanAuthorizationCapabilitiesRenderOnlyThroughExplicitTransportAccessors(t *testing.T) {
	requestURI := mustHumanPushedRequestURI(t, testHumanRequestURI)
	entry := mustHumanEntry(t, testEntryCapability)
	binding := mustHumanBinding(t, testBindingCapability)
	identityReturn := mustHumanIdentityReturn(t, testReturnCapability)
	browserReturn := mustHumanBrowserReturn(t, testConfirmationCapability)
	ready := mustHumanReady(t, testReadyCapability)
	code := mustHumanCode(t, testAuthorizationCode)

	for _, test := range []struct {
		name   string
		want   string
		render func() (string, error)
	}{
		{name: "request URI", want: testHumanRequestURI, render: requestURI.Render},
		{name: "entry", want: testEntryCapability, render: entry.Render},
		{name: "binding", want: testBindingCapability, render: binding.Render},
		{name: "identity return", want: testReturnCapability, render: identityReturn.Render},
		{name: "browser return", want: testConfirmationCapability, render: browserReturn.Render},
		{name: "ready", want: testReadyCapability, render: ready.Render},
		{name: "authorization code", want: testAuthorizationCode, render: code.Render},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.render()
			if err != nil || got != test.want {
				t.Fatalf("Render() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if got, err := (goidc.HumanReadyCapability{}).Render(); err == nil || got != "" {
		t.Fatalf("zero capability Render() = %q, %v; want empty, error", got, err)
	}
	for _, test := range []struct {
		name  string
		value string
		make  func(string) error
	}{
		{name: "entry as binding", value: testEntryCapability, make: func(value string) error { _, err := goidc.NewHumanBrowserBindingCapability(value); return err }},
		{name: "binding as ready", value: testBindingCapability, make: func(value string) error { _, err := goidc.NewHumanReadyCapability(value); return err }},
		{name: "ready as code", value: testReadyCapability, make: func(value string) error { _, err := goidc.NewHumanAuthorizationCode(value); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.make(test.value); err == nil {
				t.Fatal("wrong-purpose capability was admitted")
			}
		})
	}
}

func TestHumanCodeRedemptionTypesAreClosedAndDefensive(t *testing.T) {
	code := mustHumanCode(t, testAuthorizationCode)
	input, err := goidc.NewHumanCodeRedemptionInput(goidc.HumanCodeRedemptionInputConfig{
		AuthorizationCode: code,
		CodeVerifier:      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
		RedirectURI:       "https://dashboard.d0.eu/oidc/callback",
		ClientID:          "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
	})
	if err != nil || !input.Valid() {
		t.Fatalf("NewHumanCodeRedemptionInput() = %#v, %v", input, err)
	}

	scopes := []string{"einvoice.documents:read", "openid"}
	resources := []string{"https://api.d0.eu/accounting/v1"}
	amr := []string{"passkey"}
	decisionConfig := goidc.HumanCodeRedemptionDecisionConfig{
		Outcome:            goidc.HumanCodeRedemptionOutcomeRedeemed,
		GrantID:            "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject:            "pairwise-subject-0123456789abcdef",
		OrganizationID:     "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID:       "0199303d-5b4d-7d68-8806-60acc8861791",
		MembershipRevision: 4,
		ClientID:           "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
		Scopes:                scopes,
		Resources:             resources,
		Nonce:                 "nonce-0123456789abcdef",
		AuthenticationTime:    1_787_580_000,
		AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: amr,
		CreatedAt:             1_787_580_100,
		ExpiresAt:             1_787_580_160,
	}
	decision, err := goidc.NewHumanCodeRedemptionDecision(decisionConfig)
	if err != nil || !decision.Valid() {
		t.Fatalf("NewHumanCodeRedemptionDecision() = %#v, %v", decision, err)
	}
	withoutResources := decisionConfig
	withoutResources.Resources = nil
	if got, gotErr := goidc.NewHumanCodeRedemptionDecision(withoutResources); gotErr == nil || got.Valid() {
		t.Fatalf("resource-less redemption decision = %#v, %v; want invalid", got, gotErr)
	}
	scopes[0], resources[0], amr[0] = "mutated", "mutated", "mutated"
	if decision.Scopes()[0] != "einvoice.documents:read" ||
		decision.Resources()[0] != "https://api.d0.eu/accounting/v1" ||
		decision.AuthenticationMethods()[0] != "passkey" {
		t.Fatal("redemption decision retained caller slices")
	}
	assertHumanValueRedacted(t, input, testAuthorizationCode)
	assertHumanValueRedacted(t, decision, "pairwise-subject")
	rejected, err := goidc.NewHumanCodeRedemptionDecision(goidc.HumanCodeRedemptionDecisionConfig{
		Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
	})
	if err != nil || !rejected.Valid() {
		t.Fatalf("rejected redemption decision = %#v, %v", rejected, err)
	}
}

func validHumanPARInputConfig() goidc.HumanPARInputConfig {
	maxAge := 300
	return goidc.HumanPARInputConfig{
		ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 7,
			KeyAuthorityID:   "0199303d-5b4d-7d68-8806-60acc886178e",
		},
		RedirectURI:          "https://dashboard.d0.eu/oidc/callback",
		Scopes:               []string{"einvoice.documents:read", "openid"},
		Resources:            []string{"https://api.d0.eu/accounting/v1"},
		State:                "state-0123456789abcdef",
		Nonce:                "nonce-0123456789abcdef",
		CodeChallenge:        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
		Prompt:               goidc.PromptTypeLogin,
		MaxAuthenticationAge: &maxAge,
		ACRValues:            []goidc.ACR{"urn:d0:acr:passkey"},
	}
}

func mustHumanPushedRequestURI(t *testing.T, value string) goidc.HumanPushedRequestURI {
	t.Helper()
	result, err := goidc.NewHumanPushedRequestURI(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanEntry(t *testing.T, value string) goidc.HumanInteractionEntryCapability {
	t.Helper()
	result, err := goidc.NewHumanInteractionEntryCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanBinding(t *testing.T, value string) goidc.HumanBrowserBindingCapability {
	t.Helper()
	result, err := goidc.NewHumanBrowserBindingCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanIdentityReturn(t *testing.T, value string) goidc.HumanIdentityReturnCapability {
	t.Helper()
	result, err := goidc.NewHumanIdentityReturnCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanBrowserReturn(t *testing.T, value string) goidc.HumanBrowserReturnCapability {
	t.Helper()
	result, err := goidc.NewHumanBrowserReturnCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanReady(t *testing.T, value string) goidc.HumanReadyCapability {
	t.Helper()
	result, err := goidc.NewHumanReadyCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHumanCode(t *testing.T, value string) goidc.HumanAuthorizationCode {
	t.Helper()
	result, err := goidc.NewHumanAuthorizationCode(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertHumanValueRedacted(t *testing.T, value any, secret string) {
	t.Helper()
	formatted := fmt.Sprintf("%+v", value)
	logged := value.(slog.LogValuer).LogValue().String()
	encoded, marshalErr := json.Marshal(value)
	if strings.Contains(formatted, secret) || strings.Contains(logged, secret) ||
		(marshalErr == nil && strings.Contains(string(encoded), secret)) {
		t.Fatalf("human authorization value leaked through generic output: format=%q log=%q json=%q error=%v", formatted, logged, encoded, marshalErr)
	}
	if marshalErr == nil {
		t.Fatal("human authorization value unexpectedly admitted generic JSON serialization")
	}
}

type humanAuthorizationAuthorityStub struct{}

func (humanAuthorizationAuthorityStub) StorePAR(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
	return goidc.HumanPARDecision{}, nil
}
func (humanAuthorizationAuthorityStub) ConsumePARAndStartContinuation(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
	return goidc.HumanStartDecision{}, nil
}
func (humanAuthorizationAuthorityStub) ConfirmBrowser(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
	return goidc.HumanContinuationDecision{}, nil
}
func (humanAuthorizationAuthorityStub) CompleteAuthorization(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
	return goidc.HumanCompletionDecision{}, nil
}
func (humanAuthorizationAuthorityStub) RedeemAuthorizationCode(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
	return goidc.HumanCodeRedemptionDecision{}, nil
}
func (humanAuthorizationAuthorityStub) PrepareHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
	return goidc.HumanRefreshDeliveryPrepareDecision{}, nil
}
func (humanAuthorizationAuthorityStub) ActivateHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
	return goidc.HumanRefreshDeliveryActivateDecision{}, nil
}
func (humanAuthorizationAuthorityStub) AbortHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
	return goidc.HumanRefreshDeliveryAbortDecision{}, nil
}
func (humanAuthorizationAuthorityStub) RevokeRefreshToken(context.Context, goidc.HumanRefreshRevocationInput) error {
	return nil
}

var _ goidc.HumanAuthorizationAuthority = humanAuthorizationAuthorityStub{}
