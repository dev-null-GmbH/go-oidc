package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanAuthorizationContextWrappersValidateEveryAuthorityDecision(t *testing.T) {
	fixtures := newHumanAuthorizationContextFixtures(t)
	authority := &humanAuthorizationContextAuthority{
		storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			return fixtures.parDecision, nil
		},
		start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
			return fixtures.startDecision, nil
		},
		confirmBrowser: func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
			return fixtures.continuationDecision, nil
		},
		complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			return fixtures.completionDecision, nil
		},
		redeem: func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
			return fixtures.redemptionDecision, nil
		},
		prepare: func(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
			return fixtures.prepareDecision, nil
		},
		activate: func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
			return fixtures.activateDecision, nil
		},
		abort: func(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
			return fixtures.abortDecision, nil
		},
		revoke: func(context.Context, goidc.HumanRefreshRevocationInput) error {
			return nil
		},
	}
	ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
	if decision, err := ctx.HumanStorePAR(fixtures.parInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanStorePAR() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanConsumePARAndStartContinuation(fixtures.startInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanConsumePARAndStartContinuation() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanConfirmBrowser(fixtures.continuationInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanConfirmBrowser() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanCompleteAuthorization(fixtures.completionInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanCompleteAuthorization() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanRedeemAuthorizationCode(fixtures.redemptionInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanRedeemAuthorizationCode() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanPrepareRefreshDelivery(fixtures.prepareInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanPrepareRefreshDelivery() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanActivateRefreshDelivery(fixtures.activateInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanActivateRefreshDelivery() = %#v, %v", decision, err)
	}
	if decision, err := ctx.HumanAbortRefreshDelivery(fixtures.abortInput); err != nil || !decision.Valid() {
		t.Fatalf("HumanAbortRefreshDelivery() = %#v, %v", decision, err)
	}
	if err := ctx.HumanRevokeRefreshToken(fixtures.revocationInput); err != nil {
		t.Fatalf("HumanRevokeRefreshToken() = %v", err)
	}
	if authority.calls != 9 {
		t.Fatalf("authority calls = %d, want 9", authority.calls)
	}
}

func TestHumanAuthorizationAuthorityReceivesOnlyRequestContext(t *testing.T) {
	fixtures := newHumanAuthorizationContextFixtures(t)
	type contextKey struct{}
	requestContext := context.WithValue(t.Context(), contextKey{}, "trace-0123456789abcdef")
	assertRequestContext := func(callbackContext context.Context) {
		t.Helper()
		if _, exposesInternalContext := callbackContext.(Context); exposesInternalContext {
			t.Fatal("authority callback received the internal OIDC context")
		}
		if got := callbackContext.Value(contextKey{}); got != "trace-0123456789abcdef" {
			t.Fatalf("request context value = %#v", got)
		}
	}
	authority := &humanAuthorizationContextAuthority{
		storePAR: func(callbackContext context.Context, _ goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			assertRequestContext(callbackContext)
			return fixtures.parDecision, nil
		},
		revoke: func(callbackContext context.Context, _ goidc.HumanRefreshRevocationInput) error {
			assertRequestContext(callbackContext)
			return nil
		},
	}
	ctx := NewContext(requestContext, &Configuration{HumanAuthorizationAuthority: authority})
	decision, err := ctx.HumanStorePAR(fixtures.parInput)
	if err != nil || !decision.Valid() {
		t.Fatalf("HumanStorePAR() = %#v, %v", decision, err)
	}
	if err := ctx.HumanRevokeRefreshToken(fixtures.revocationInput); err != nil {
		t.Fatalf("HumanRevokeRefreshToken() = %v", err)
	}
}

func TestHumanAuthorizationContextWrappersContainPanicsCancellationAndInvalidOutputs(t *testing.T) {
	fixtures := newHumanAuthorizationContextFixtures(t)

	t.Run("panic", func(t *testing.T) {
		authority := &humanAuthorizationContextAuthority{storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			panic("sensitive authority panic")
		}}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		decision, err := ctx.HumanStorePAR(fixtures.parInput)
		assertHumanAuthorizationServerError(t, decision.Valid(), err)
	})

	t.Run("pre-cancelled", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		authority := &humanAuthorizationContextAuthority{storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			t.Fatal("authority called for cancelled context")
			return fixtures.parDecision, nil
		}}
		ctx := NewContext(cancelled, &Configuration{HumanAuthorizationAuthority: authority})
		decision, err := ctx.HumanStorePAR(fixtures.parInput)
		assertHumanAuthorizationServerError(t, decision.Valid(), err)
	})

	t.Run("cancelled during callback", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(t.Context())
		authority := &humanAuthorizationContextAuthority{storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			cancel()
			return fixtures.parDecision, nil
		}}
		ctx := NewContext(cancelled, &Configuration{HumanAuthorizationAuthority: authority})
		decision, err := ctx.HumanStorePAR(fixtures.parInput)
		assertHumanAuthorizationServerError(t, decision.Valid(), err)
	})

	t.Run("invalid output", func(t *testing.T) {
		authority := &humanAuthorizationContextAuthority{start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
			return goidc.HumanStartDecision{}, nil
		}}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		decision, err := ctx.HumanConsumePARAndStartContinuation(fixtures.startInput)
		assertHumanAuthorizationServerError(t, decision.Valid(), err)
	})

	t.Run("browser-return substitution", func(t *testing.T) {
		substituted, err := goidc.NewHumanBrowserReturnCapability(
			"d0_hio_c1_CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
		)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := goidc.NewHumanContinuationDecision(
			goidc.HumanContinuationOutcomeConfirmed,
			substituted,
		)
		if err != nil {
			t.Fatal(err)
		}
		authority := &humanAuthorizationContextAuthority{
			confirmBrowser: func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
				return decision, nil
			},
		}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		got, gotErr := ctx.HumanConfirmBrowser(fixtures.continuationInput)
		assertHumanAuthorizationServerError(t, got.Valid(), gotErr)
	})

	t.Run("redemption binding substitution", func(t *testing.T) {
		mismatched := fixtures.redemptionDecisionConfig
		mismatched.ClientID = "other.d0.eu"
		decision, err := goidc.NewHumanCodeRedemptionDecision(mismatched)
		if err != nil {
			t.Fatal(err)
		}
		authority := &humanAuthorizationContextAuthority{redeem: func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
			return decision, nil
		}}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		got, gotErr := ctx.HumanRedeemAuthorizationCode(fixtures.redemptionInput)
		assertHumanAuthorizationServerError(t, got.Valid(), gotErr)
	})

	t.Run("ordinary rejection", func(t *testing.T) {
		rejected, err := goidc.NewHumanCodeRedemptionDecision(goidc.HumanCodeRedemptionDecisionConfig{
			Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
		})
		if err != nil {
			t.Fatal(err)
		}
		authority := &humanAuthorizationContextAuthority{redeem: func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
			return rejected, nil
		}}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		got, gotErr := ctx.HumanRedeemAuthorizationCode(fixtures.redemptionInput)
		if gotErr != nil || got.Outcome() != goidc.HumanCodeRedemptionOutcomeRejected {
			t.Fatalf("ordinary rejection = %#v, %v", got, gotErr)
		}
	})

	t.Run("refresh activation binding substitution", func(t *testing.T) {
		mismatched := fixtures.activateDecisionConfig
		mismatched.ClientAssertionAuthority.KeyAuthorityID = "0199303d-5b4d-7d68-8806-60acc8861799"
		decision, err := goidc.NewHumanRefreshDeliveryActivateDecision(mismatched)
		if err != nil {
			t.Fatal(err)
		}
		authority := &humanAuthorizationContextAuthority{
			activate: func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
				return decision, nil
			},
		}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		got, gotErr := ctx.HumanActivateRefreshDelivery(fixtures.activateInput)
		assertHumanAuthorizationServerError(t, got.Valid(), gotErr)
	})

	t.Run("ordinary refresh rejection", func(t *testing.T) {
		rejected, err := goidc.NewHumanRefreshDeliveryActivateDecision(goidc.HumanRefreshDeliveryActivateDecisionConfig{
			Outcome: goidc.HumanRefreshDeliveryActivateOutcomeRejected,
		})
		if err != nil {
			t.Fatal(err)
		}
		authority := &humanAuthorizationContextAuthority{
			activate: func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
				return rejected, nil
			},
		}
		ctx := NewContext(t.Context(), &Configuration{HumanAuthorizationAuthority: authority})
		got, gotErr := ctx.HumanActivateRefreshDelivery(fixtures.activateInput)
		if gotErr != nil || got.Outcome() != goidc.HumanRefreshDeliveryActivateOutcomeRejected {
			t.Fatalf("ordinary refresh rejection = %#v, %v", got, gotErr)
		}
	})
}

func assertHumanAuthorizationServerError(t *testing.T, outputValid bool, err error) {
	t.Helper()
	var oidcErr goidc.Error
	if outputValid || !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeServerError ||
		err.Error() != "server_error server error: human authorization authority failed" {
		t.Fatalf("result valid=%v error=%#v, want bounded server_error", outputValid, err)
	}
}

type humanAuthorizationContextAuthority struct {
	calls          int
	storePAR       func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error)
	start          func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error)
	confirmBrowser func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error)
	complete       func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error)
	redeem         func(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error)
	prepare        func(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error)
	activate       func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error)
	abort          func(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error)
	revoke         func(context.Context, goidc.HumanRefreshRevocationInput) error
}

func (authority *humanAuthorizationContextAuthority) StorePAR(ctx context.Context, input goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
	authority.calls++
	return authority.storePAR(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) ConsumePARAndStartContinuation(ctx context.Context, input goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
	authority.calls++
	return authority.start(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) ConfirmBrowser(ctx context.Context, input goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
	authority.calls++
	return authority.confirmBrowser(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) CompleteAuthorization(ctx context.Context, input goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
	authority.calls++
	return authority.complete(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) RedeemAuthorizationCode(ctx context.Context, input goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
	authority.calls++
	return authority.redeem(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) PrepareHumanRefreshDelivery(ctx context.Context, input goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
	authority.calls++
	return authority.prepare(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) ActivateHumanRefreshDelivery(ctx context.Context, input goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
	authority.calls++
	return authority.activate(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) AbortHumanRefreshDelivery(ctx context.Context, input goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
	authority.calls++
	return authority.abort(ctx, input)
}
func (authority *humanAuthorizationContextAuthority) RevokeRefreshToken(ctx context.Context, input goidc.HumanRefreshRevocationInput) error {
	authority.calls++
	return authority.revoke(ctx, input)
}

type humanAuthorizationContextFixtures struct {
	parInput                 goidc.HumanPARInput
	parDecision              goidc.HumanPARDecision
	startInput               goidc.HumanStartInput
	startDecision            goidc.HumanStartDecision
	continuationInput        goidc.HumanContinuationInput
	continuationDecision     goidc.HumanContinuationDecision
	completionInput          goidc.HumanCompletionInput
	completionDecision       goidc.HumanCompletionDecision
	redemptionInput          goidc.HumanCodeRedemptionInput
	redemptionDecision       goidc.HumanCodeRedemptionDecision
	redemptionDecisionConfig goidc.HumanCodeRedemptionDecisionConfig
	prepareInput             goidc.HumanRefreshDeliveryPrepareInput
	prepareDecision          goidc.HumanRefreshDeliveryPrepareDecision
	activateInput            goidc.HumanRefreshDeliveryActivateInput
	activateDecision         goidc.HumanRefreshDeliveryActivateDecision
	activateDecisionConfig   goidc.HumanRefreshDeliveryActivateDecisionConfig
	abortInput               goidc.HumanRefreshDeliveryAbortInput
	abortDecision            goidc.HumanRefreshDeliveryAbortDecision
	revocationInput          goidc.HumanRefreshRevocationInput
}

func newHumanAuthorizationContextFixtures(t *testing.T) humanAuthorizationContextFixtures {
	t.Helper()
	must := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}
	parInput, err := goidc.NewHumanPARInput(goidc.HumanPARInputConfig{
		ClientID:                 "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"},
		RedirectURI:              "https://dashboard.d0.eu/oidc/callback", Scopes: []string{"einvoice.documents:read", "openid"},
		Resources: []string{"https://api.d0.eu/accounting/v1"}, State: "state-0123456789abcdef", Nonce: "nonce-0123456789abcdef",
		CodeChallenge: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", Prompt: goidc.PromptTypeLogin,
	})
	must(err)
	requestURI, err := goidc.NewHumanPushedRequestURI(goidc.HumanPushedRequestURIPrefix + "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
	must(err)
	receipt, err := goidc.NewHumanPARReceipt(requestURI, 300)
	must(err)
	parDecision, err := goidc.NewHumanPARDecision(goidc.HumanPAROutcomeCreated, receipt)
	must(err)
	startInput, err := goidc.NewHumanStartInput("dashboard.d0.eu", requestURI)
	must(err)
	entry, err := goidc.NewHumanInteractionEntryCapability("d0_hio_e1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	must(err)
	binding, err := goidc.NewHumanBrowserBindingCapability("d0_hio_b1_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	must(err)
	startDecision, err := goidc.NewHumanStartDecision(goidc.HumanStartDecisionConfig{Outcome: goidc.HumanStartOutcomePending, EntryCapability: entry, BrowserBindingCapability: binding, ExpiresAt: 1_787_580_300})
	must(err)
	identityReturn, err := goidc.NewHumanIdentityReturnCapability("d0_hio_r1_AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM")
	must(err)
	browserReturn, err := goidc.NewHumanBrowserReturnCapability("d0_hio_c1_BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ")
	must(err)
	continuationInput, err := goidc.NewHumanContinuationInput(identityReturn, browserReturn, binding)
	must(err)
	ready, err := goidc.NewHumanReadyCapability("d0_hio_s1_BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU")
	must(err)
	continuationDecision, err := goidc.NewHumanContinuationDecision(goidc.HumanContinuationOutcomeConfirmed, browserReturn)
	must(err)
	completionInput, err := goidc.NewHumanCompletionInput(ready, binding)
	must(err)
	code, err := goidc.NewHumanAuthorizationCode("d0_hac_1_BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY")
	must(err)
	completionDecision, err := goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
		Outcome: goidc.HumanCompletionOutcomeCompleted, Profile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		ClientID: "dashboard.d0.eu", ClientSnapshotRevision: 7, AdmissionKeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e",
		AuthorizationCode: code, RedirectURI: "https://dashboard.d0.eu/oidc/callback", State: "state-0123456789abcdef", CodeExpiresInSeconds: 60,
	})
	must(err)
	redemptionInput, err := goidc.NewHumanCodeRedemptionInput(goidc.HumanCodeRedemptionInputConfig{
		AuthorizationCode: code, CodeVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
		RedirectURI: "https://dashboard.d0.eu/oidc/callback", ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"},
	})
	must(err)
	redemptionConfig := goidc.HumanCodeRedemptionDecisionConfig{
		Outcome: goidc.HumanCodeRedemptionOutcomeRedeemed, GrantID: "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject: "pairwise-subject-0123456789abcdef", OrganizationID: "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID: "0199303d-5b4d-7d68-8806-60acc8861791", MembershipRevision: 4, ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"},
		Scopes:                   []string{"einvoice.documents:read", "openid"}, Resources: []string{"https://api.d0.eu/accounting/v1"},
		Nonce: "nonce-0123456789abcdef", AuthenticationTime: 1_787_580_000, AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: []string{"passkey"}, CreatedAt: 1_787_580_100, ExpiresAt: 1_787_580_160,
	}
	redemptionDecision, err := goidc.NewHumanCodeRedemptionDecision(redemptionConfig)
	must(err)
	refreshToken, err := goidc.NewHumanRefreshToken("d0_hrt_1_BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
	must(err)
	revocationInput, err := goidc.NewHumanRefreshRevocationInput(goidc.HumanRefreshRevocationInputConfig{
		RefreshToken: refreshToken, ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"},
	})
	must(err)
	successor, err := goidc.NewHumanRefreshToken("d0_hrt_1_CwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
	must(err)
	deliveryReceipt, err := goidc.NewHumanRefreshDeliveryReceipt("d0_hrd_1_DwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
	must(err)
	authority := goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"}
	prepareInput, err := goidc.NewHumanRefreshDeliveryPrepareInput(goidc.HumanRefreshDeliveryPrepareInputConfig{
		PredecessorRefreshToken: refreshToken, SuccessorRefreshToken: successor,
		DeliveryReceipt: deliveryReceipt, ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	})
	must(err)
	activateInput, err := goidc.NewHumanRefreshDeliveryActivateInput(goidc.HumanRefreshDeliveryActivateInputConfig{
		SuccessorRefreshToken: successor, DeliveryReceipt: deliveryReceipt,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	})
	must(err)
	abortInput, err := goidc.NewHumanRefreshDeliveryAbortInput(goidc.HumanRefreshDeliveryAbortInputConfig{
		SuccessorRefreshToken: successor, DeliveryReceipt: deliveryReceipt,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	})
	must(err)
	prepareDecision, err := goidc.NewHumanRefreshDeliveryPrepareDecision(goidc.HumanRefreshDeliveryPrepareDecisionConfig{
		Outcome:  goidc.HumanRefreshDeliveryPrepareOutcomePending,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
		CreatedAt: 1_787_580_100, ExpiresAt: 1_787_580_400,
	})
	must(err)
	activateConfig := goidc.HumanRefreshDeliveryActivateDecisionConfig{
		Outcome:               goidc.HumanRefreshDeliveryActivateOutcomeActivated,
		RefreshTokenExpiresAt: 1_787_666_400, GrantID: "0199303d-5b4d-7d68-8806-60acc886178f",
		Subject: "pairwise-subject-0123456789abcdef", OrganizationID: "0199303d-5b4d-7d68-8806-60acc8861790",
		MembershipID: "0199303d-5b4d-7d68-8806-60acc8861791", MembershipRevision: 4, ClientID: "dashboard.d0.eu",
		ClientAssertionAuthority: goidc.VerifiedClientAssertionAuthority{SnapshotRevision: 7, KeyAuthorityID: "0199303d-5b4d-7d68-8806-60acc886178e"},
		Scopes:                   []string{"offline_access", "openid"}, Resources: []string{"https://api.d0.eu/accounting/v1"},
		AuthenticationTime: 1_787_580_000, AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: []string{"passkey"}, CreatedAt: 1_787_580_100, ExpiresAt: 1_787_580_160,
	}
	activateDecision, err := goidc.NewHumanRefreshDeliveryActivateDecision(activateConfig)
	must(err)
	abortDecision, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
		Outcome:  goidc.HumanRefreshDeliveryAbortOutcomeAborted,
		ClientID: "dashboard.d0.eu", ClientAssertionAuthority: authority,
	})
	must(err)
	return humanAuthorizationContextFixtures{
		parInput: parInput, parDecision: parDecision, startInput: startInput, startDecision: startDecision,
		continuationInput: continuationInput, continuationDecision: continuationDecision,
		completionInput: completionInput, completionDecision: completionDecision,
		redemptionInput: redemptionInput, redemptionDecision: redemptionDecision,
		redemptionDecisionConfig: redemptionConfig,
		prepareInput:             prepareInput, prepareDecision: prepareDecision,
		activateInput: activateInput, activateDecision: activateDecision,
		activateDecisionConfig: activateConfig,
		abortInput:             abortInput, abortDecision: abortDecision,
		revocationInput: revocationInput,
	}
}

var _ goidc.HumanAuthorizationAuthority = (*humanAuthorizationContextAuthority)(nil)
