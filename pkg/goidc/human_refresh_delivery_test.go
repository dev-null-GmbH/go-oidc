package goidc_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const testHumanRefreshDeliveryReceipt = "d0_hrd_1_DwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"

func TestHumanRefreshDeliveryCanonicalClientFramingIsPublic(t *testing.T) {
	t.Parallel()

	if goidc.HumanRefreshTokenPrefix != "d0_hrt_1_" ||
		goidc.HumanRefreshDeliveryReceiptPrefix != "d0_hrd_1_" ||
		goidc.HumanRefreshCapabilityEntropyBytes != 32 ||
		goidc.HumanRefreshCapabilityPayloadBytes != 43 {
		t.Fatal("public delivery framing constants changed")
	}
	entropy := make([]byte, goidc.HumanRefreshCapabilityEntropyBytes)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	payload := base64.RawURLEncoding.EncodeToString(entropy)
	if len(payload) != goidc.HumanRefreshCapabilityPayloadBytes {
		t.Fatal("public entropy and payload sizes disagree")
	}
	if token, err := goidc.NewHumanRefreshToken(goidc.HumanRefreshTokenPrefix + payload); err != nil || !token.Valid() {
		t.Fatalf("canonical caller-generated successor was rejected: %v", err)
	}
	if receipt, err := goidc.NewHumanRefreshDeliveryReceipt(goidc.HumanRefreshDeliveryReceiptPrefix + payload); err != nil || !receipt.Valid() {
		t.Fatalf("canonical caller-generated receipt was rejected: %v", err)
	}
}

func TestHumanRefreshDeliveryBoundaryTypesAreClosedRedactedAndCorrelated(t *testing.T) {
	t.Parallel()

	predecessor := mustHumanRefreshToken(t, testHumanRefreshToken)
	successor := mustHumanRefreshToken(t, testHumanSuccessorRefreshToken)
	receipt, err := goidc.NewHumanRefreshDeliveryReceipt(testHumanRefreshDeliveryReceipt)
	if err != nil || !receipt.Valid() {
		t.Fatalf("NewHumanRefreshDeliveryReceipt() = %#v, %v", receipt, err)
	}
	authority := goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 7,
		KeyAuthorityID:   "authority-key-0001",
	}
	prepare, err := goidc.NewHumanRefreshDeliveryPrepareInput(goidc.HumanRefreshDeliveryPrepareInputConfig{
		PredecessorRefreshToken:  predecessor,
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !prepare.Valid() || prepare.ClientID() != "dashboard.d0.eu" ||
		prepare.ClientAssertionAuthority() != authority {
		t.Fatalf("NewHumanRefreshDeliveryPrepareInput() = %#v, %v", prepare, err)
	}
	activate, err := goidc.NewHumanRefreshDeliveryActivateInput(goidc.HumanRefreshDeliveryActivateInputConfig{
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !activate.Valid() {
		t.Fatalf("NewHumanRefreshDeliveryActivateInput() = %#v, %v", activate, err)
	}
	abort, err := goidc.NewHumanRefreshDeliveryAbortInput(goidc.HumanRefreshDeliveryAbortInputConfig{
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !abort.Valid() {
		t.Fatalf("NewHumanRefreshDeliveryAbortInput() = %#v, %v", abort, err)
	}

	for _, value := range []any{receipt, prepare, activate, abort} {
		formatted := fmt.Sprintf("%v", value)
		if strings.Contains(formatted, testHumanRefreshToken) ||
			strings.Contains(formatted, testHumanSuccessorRefreshToken) ||
			strings.Contains(formatted, testHumanRefreshDeliveryReceipt) {
			t.Fatalf("formatted delivery value leaked capability: %q", formatted)
		}
		if encoded, marshalErr := json.Marshal(value); marshalErr == nil || encoded != nil {
			t.Fatalf("json.Marshal() = %q, %v; want nil, error", encoded, marshalErr)
		}
	}

	if rendered, renderErr := prepare.PredecessorRefreshToken().Render(); renderErr != nil || rendered != testHumanRefreshToken {
		t.Fatalf("predecessor render failed: %v", renderErr)
	}
	if rendered, renderErr := activate.SuccessorRefreshToken().Render(); renderErr != nil || rendered != testHumanSuccessorRefreshToken {
		t.Fatalf("successor render failed: %v", renderErr)
	}
	if rendered, renderErr := abort.DeliveryReceipt().Render(); renderErr != nil || rendered != testHumanRefreshDeliveryReceipt {
		t.Fatalf("receipt render failed: %v", renderErr)
	}
}

func TestHumanRefreshDeliveryInputsRejectOpenOrAmbiguousShapes(t *testing.T) {
	t.Parallel()

	predecessor := mustHumanRefreshToken(t, testHumanRefreshToken)
	successor := mustHumanRefreshToken(t, testHumanSuccessorRefreshToken)
	receipt, err := goidc.NewHumanRefreshDeliveryReceipt(testHumanRefreshDeliveryReceipt)
	if err != nil {
		t.Fatal(err)
	}
	authority := goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "authority-key-0001"}
	base := goidc.HumanRefreshDeliveryPrepareInputConfig{
		PredecessorRefreshToken:  predecessor,
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	}
	for _, test := range []struct {
		name   string
		mutate func(*goidc.HumanRefreshDeliveryPrepareInputConfig)
	}{
		{name: "missing predecessor", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) {
			config.PredecessorRefreshToken = goidc.HumanRefreshToken{}
		}},
		{name: "missing successor", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) {
			config.SuccessorRefreshToken = goidc.HumanRefreshToken{}
		}},
		{name: "same predecessor and successor", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) { config.SuccessorRefreshToken = predecessor }},
		{name: "same successor and receipt entropy", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) {
			reusedReceipt, receiptErr := goidc.NewHumanRefreshDeliveryReceipt(
				goidc.HumanRefreshDeliveryReceiptPrefix + strings.TrimPrefix(testHumanSuccessorRefreshToken, goidc.HumanRefreshTokenPrefix),
			)
			if receiptErr != nil {
				t.Fatal(receiptErr)
			}
			config.DeliveryReceipt = reusedReceipt
		}},
		{name: "missing receipt", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) {
			config.DeliveryReceipt = goidc.HumanRefreshDeliveryReceipt{}
		}},
		{name: "missing client", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) { config.ClientID = "" }},
		{name: "missing assertion authority", mutate: func(config *goidc.HumanRefreshDeliveryPrepareInputConfig) {
			config.ClientAssertionAuthority = goidc.VerifiedClientAssertionAuthority{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if input, inputErr := goidc.NewHumanRefreshDeliveryPrepareInput(candidate); inputErr == nil || input.Valid() {
				t.Fatalf("NewHumanRefreshDeliveryPrepareInput() = %#v, %v; want invalid", input, inputErr)
			}
		})
	}

	reusedReceipt, err := goidc.NewHumanRefreshDeliveryReceipt(
		goidc.HumanRefreshDeliveryReceiptPrefix + strings.TrimPrefix(testHumanSuccessorRefreshToken, goidc.HumanRefreshTokenPrefix),
	)
	if err != nil {
		t.Fatal(err)
	}
	if input, inputErr := goidc.NewHumanRefreshDeliveryActivateInput(goidc.HumanRefreshDeliveryActivateInputConfig{
		SuccessorRefreshToken: successor, DeliveryReceipt: reusedReceipt,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	}); inputErr == nil || input.Valid() {
		t.Fatalf("activate input unexpectedly accepted reused successor entropy")
	}
	if input, inputErr := goidc.NewHumanRefreshDeliveryAbortInput(goidc.HumanRefreshDeliveryAbortInputConfig{
		SuccessorRefreshToken: successor, DeliveryReceipt: reusedReceipt,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	}); inputErr == nil || input.Valid() {
		t.Fatalf("abort input unexpectedly accepted reused successor entropy")
	}

	for _, value := range []string{
		"d0_hrt_1_DwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
		"d0_hrd_1_" + strings.Repeat("A", 43),
		testHumanRefreshDeliveryReceipt[:len(testHumanRefreshDeliveryReceipt)-1] + "F",
	} {
		if candidate, candidateErr := goidc.NewHumanRefreshDeliveryReceipt(value); candidateErr == nil || candidate.Valid() {
			t.Fatalf("NewHumanRefreshDeliveryReceipt() unexpectedly accepted invalid value")
		}
	}
}

func TestHumanRefreshDeliveryDecisionsAreClosedAndDoNotCarryRawSuccessor(t *testing.T) {
	t.Parallel()

	authority := goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "authority-key-0001"}
	prepared, err := goidc.NewHumanRefreshDeliveryPrepareDecision(goidc.HumanRefreshDeliveryPrepareDecisionConfig{
		Outcome:                  goidc.HumanRefreshDeliveryPrepareOutcomePending,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
		CreatedAt:                1_787_580_100,
		ExpiresAt:                1_787_580_400,
	})
	if err != nil || !prepared.Valid() || prepared.Outcome() != goidc.HumanRefreshDeliveryPrepareOutcomePending {
		t.Fatalf("prepared decision = %#v, %v", prepared, err)
	}

	scopes := []string{"offline_access", "openid", "profile"}
	resources := []string{"https://api.d0.eu/accounting/v1"}
	methods := []string{"passkey"}
	activated, err := goidc.NewHumanRefreshDeliveryActivateDecision(goidc.HumanRefreshDeliveryActivateDecisionConfig{
		Outcome:                  goidc.HumanRefreshDeliveryActivateOutcomeActivated,
		RefreshTokenExpiresAt:    1_787_666_400,
		GrantID:                  "grant-handle-00000001",
		Subject:                  "pairwise-subject-0123456789abcdef",
		OrganizationID:           "organization-handle-0001",
		MembershipID:             "membership-handle-00001",
		MembershipRevision:       4,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
		Scopes:                   scopes,
		Resources:                resources,
		AuthenticationTime:       1_787_580_000,
		AuthenticationContext:    "urn:d0:acr:passkey",
		AuthenticationMethods:    methods,
		CreatedAt:                1_787_580_100,
		ExpiresAt:                1_787_580_160,
	})
	if err != nil || !activated.Valid() || activated.Outcome() != goidc.HumanRefreshDeliveryActivateOutcomeActivated {
		t.Fatalf("activated decision = %#v, %v", activated, err)
	}
	scopes[0], resources[0], methods[0] = "mutated", "mutated", "mutated"
	if activated.Scopes()[0] != "offline_access" || activated.Resources()[0] != "https://api.d0.eu/accounting/v1" ||
		activated.AuthenticationMethods()[0] != "passkey" {
		t.Fatal("activation decision retained caller-owned slices")
	}

	aborted, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
		Outcome:                  goidc.HumanRefreshDeliveryAbortOutcomeAborted,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !aborted.Valid() || aborted.Outcome() != goidc.HumanRefreshDeliveryAbortOutcomeAborted {
		t.Fatalf("aborted decision = %#v, %v", aborted, err)
	}
	conflict, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
		Outcome:                  goidc.HumanRefreshDeliveryAbortOutcomeActivatedConflict,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
	})
	if err != nil || !conflict.Valid() || conflict.Outcome() != goidc.HumanRefreshDeliveryAbortOutcomeActivatedConflict {
		t.Fatalf("activated abort conflict = %#v, %v", conflict, err)
	}

	for _, rejected := range []bool{
		mustPrepareRejected(t).Valid(),
		mustActivateRejected(t).Valid(),
		mustAbortRejected(t).Valid(),
	} {
		if !rejected {
			t.Fatal("rejected delivery decision is invalid")
		}
	}
}

func TestHumanRefreshDeliveryDecisionsRejectOpenOrIncoherentShapes(t *testing.T) {
	t.Parallel()

	authority := goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "authority-key-0001"}
	for _, config := range []goidc.HumanRefreshDeliveryPrepareDecisionConfig{
		{Outcome: "unknown"},
		{
			Outcome:  goidc.HumanRefreshDeliveryPrepareOutcomePending,
			ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
			CreatedAt: 1_787_580_100, ExpiresAt: 1_787_580_401,
		},
		{
			Outcome:  goidc.HumanRefreshDeliveryPrepareOutcomeRejected,
			ClientID: "dashboard.d0.eu",
		},
		{Outcome: goidc.HumanRefreshDeliveryPrepareOutcomeActivated},
		{Outcome: goidc.HumanRefreshDeliveryPrepareOutcomeAborted},
	} {
		if decision, err := goidc.NewHumanRefreshDeliveryPrepareDecision(config); err == nil || decision.Valid() {
			t.Fatalf("prepare decision unexpectedly accepted an incoherent shape")
		}
	}

	base := goidc.HumanRefreshDeliveryActivateDecisionConfig{
		Outcome:                  goidc.HumanRefreshDeliveryActivateOutcomeActivated,
		RefreshTokenExpiresAt:    1_787_666_400,
		GrantID:                  "grant-handle-00000001",
		Subject:                  "pairwise-subject-0123456789abcdef",
		OrganizationID:           "organization-handle-0001",
		MembershipID:             "membership-handle-00001",
		MembershipRevision:       4,
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: authority,
		Scopes:                   []string{"offline_access", "openid", "profile"},
		Resources:                []string{"https://api.d0.eu/accounting/v1"},
		AuthenticationTime:       1_787_580_000,
		AuthenticationContext:    "urn:d0:acr:passkey",
		AuthenticationMethods:    []string{"passkey"},
		CreatedAt:                1_787_580_100,
		ExpiresAt:                1_787_580_160,
	}
	for _, mutate := range []func(*goidc.HumanRefreshDeliveryActivateDecisionConfig){
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) {
			config.Scopes = []string{"openid", "profile"}
		},
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) {
			config.RefreshTokenExpiresAt = config.CreatedAt
		},
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) {
			config.RefreshTokenExpiresAt = config.CreatedAt + 86_401
		},
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) {
			config.ExpiresAt = config.CreatedAt + 601
		},
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) { config.AuthenticationContext = "" },
		func(config *goidc.HumanRefreshDeliveryActivateDecisionConfig) {
			*config = goidc.HumanRefreshDeliveryActivateDecisionConfig{
				Outcome:               goidc.HumanRefreshDeliveryActivateOutcomeRejected,
				RefreshTokenExpiresAt: base.RefreshTokenExpiresAt,
			}
		},
	} {
		candidate := base
		candidate.Scopes = append([]string(nil), base.Scopes...)
		candidate.Resources = append([]string(nil), base.Resources...)
		candidate.AuthenticationMethods = append([]string(nil), base.AuthenticationMethods...)
		mutate(&candidate)
		if decision, err := goidc.NewHumanRefreshDeliveryActivateDecision(candidate); err == nil || decision.Valid() {
			t.Fatal("activation decision unexpectedly accepted an incoherent shape")
		}
	}

	for _, config := range []goidc.HumanRefreshDeliveryAbortDecisionConfig{
		{Outcome: "unknown"},
		{Outcome: goidc.HumanRefreshDeliveryAbortOutcomeRejected, ClientID: "dashboard.d0.eu"},
		{Outcome: goidc.HumanRefreshDeliveryAbortOutcomeActivatedConflict},
	} {
		if decision, err := goidc.NewHumanRefreshDeliveryAbortDecision(config); err == nil || decision.Valid() {
			t.Fatal("abort decision unexpectedly accepted an incoherent shape")
		}
	}
}

func mustPrepareRejected(t *testing.T) goidc.HumanRefreshDeliveryPrepareDecision {
	t.Helper()
	decision, err := goidc.NewHumanRefreshDeliveryPrepareDecision(goidc.HumanRefreshDeliveryPrepareDecisionConfig{
		Outcome: goidc.HumanRefreshDeliveryPrepareOutcomeRejected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func mustActivateRejected(t *testing.T) goidc.HumanRefreshDeliveryActivateDecision {
	t.Helper()
	decision, err := goidc.NewHumanRefreshDeliveryActivateDecision(goidc.HumanRefreshDeliveryActivateDecisionConfig{
		Outcome: goidc.HumanRefreshDeliveryActivateOutcomeRejected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func mustAbortRejected(t *testing.T) goidc.HumanRefreshDeliveryAbortDecision {
	t.Helper()
	decision, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
		Outcome: goidc.HumanRefreshDeliveryAbortOutcomeRejected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}
