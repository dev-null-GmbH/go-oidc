package token

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanRefreshDeliveryPrepareIsPendingNoStoreAndDoesNotSign(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryPrepareRoute, "prepare-assertion", true)
	fixture.authority.prepare = func(_ context.Context, input goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
		if input.ClientID() != fixture.client.ID || input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatal("prepare input lost authenticated client binding")
		}
		predecessor, predecessorErr := input.PredecessorRefreshToken().Render()
		successor, successorErr := input.SuccessorRefreshToken().Render()
		receipt, receiptErr := input.DeliveryReceipt().Render()
		if predecessorErr != nil || successorErr != nil || receiptErr != nil ||
			predecessor != testHumanRefreshToken || successor != testHumanSuccessorRefreshToken ||
			receipt != testHumanDeliveryReceipt {
			t.Fatal("prepare input did not preserve the exact delivery tuple")
		}
		return fixture.pendingDeliveryDecision(t), nil
	}
	fixture.ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		panic("prepare attempted signing")
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleHumanRefreshDeliveryPrepare(fixture.ctx)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("Pragma") != "no-cache" || fixture.authority.prepareCalls != 1 {
		t.Fatalf("prepare response status/headers/calls = %d/%v/%d", recorder.Code, recorder.Header(), fixture.authority.prepareCalls)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 2 || payload["status"] != "delivery_pending" ||
		payload["expires_in"] != float64(300) || responseContainsDeliveryCapability(recorder.Body.String()) {
		t.Fatal("prepare response was not the bounded capability-free receipt")
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshDeliveryActivationCommitsBeforeSigningAndReturnsCallerSuccessor(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryActivateRoute, "activate-assertion", false)
	activated := false
	fixture.authority.activate = func(_ context.Context, input goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
		activated = true
		if input.ClientID() != fixture.client.ID || input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatal("activation input lost authenticated client binding")
		}
		return fixture.activatedDeliveryDecision(t), nil
	}
	signingKey := oidctest.PrivateJWKS(t, fixture.ctx).Keys[0]
	privateSigner, ok := signingKey.Key.(crypto.Signer)
	if !ok {
		t.Fatal("test signing key is not a crypto.Signer")
	}
	fixture.ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		if !activated {
			panic("signing preceded activation")
		}
		return signingKey.KeyID, privateSigner, nil
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleHumanRefreshDeliveryActivate(fixture.ctx)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("Pragma") != "no-cache" || fixture.authority.activateCalls != 1 {
		t.Fatalf("activate response status/headers/calls = %d/%v/%d", recorder.Code, recorder.Header(), fixture.authority.activateCalls)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	accessToken, accessTokenOK := payload["access_token"].(string)
	if len(payload) != 7 || !accessTokenOK || accessToken == "" ||
		payload["refresh_token"] != testHumanSuccessorRefreshToken || payload["token_type"] != "Bearer" ||
		payload["expires_in"] != float64(300) || payload["scope"] != "offline_access openid profile" {
		t.Fatal("activation response is incoherent")
	}
	if _, present := payload["id_token"]; present {
		t.Fatal("activation response contained an ID token")
	}
	claims := parseHumanPS256Token(t, fixture.ctx, accessToken, "at+jwt")
	assertHumanTokenClaim(t, claims, goidc.ClaimGrantID, "human-grant-0001")
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshDeliveryActivatedReplayRecoversAfterSigningFailure(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	decision := fixture.activatedDeliveryDecision(t)
	fixture.authority.activate = func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
		if decision.RefreshTokenExpiresAt() == 0 {
			t.Fatal("activated replay lost the absolute family deadline")
		}
		return decision, nil
	}
	fixture.ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		return "", nil, errors.New("signing backend unavailable")
	}
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryActivateRoute, "activate-before-lost-response", false)
	first := httptest.NewRecorder()
	fixture.ctx.Response = first
	handleHumanRefreshDeliveryActivate(fixture.ctx)
	if first.Code != http.StatusInternalServerError || responseContainsDeliveryCapability(first.Body.String()) {
		t.Fatal("failed activation signing did not return a redacted server error")
	}

	fixture.ctx.SignerFunc = nil
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryActivateRoute, "activate-replay-after-lost-response", false)
	second := httptest.NewRecorder()
	fixture.ctx.Response = second
	handleHumanRefreshDeliveryActivate(fixture.ctx)
	if second.Code != http.StatusOK || fixture.authority.activateCalls != 2 {
		t.Fatalf("activated replay status/calls = %d/%d", second.Code, fixture.authority.activateCalls)
	}
	var payload map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["refresh_token"] != testHumanSuccessorRefreshToken {
		t.Fatal("activated replay did not confirm the caller-owned successor")
	}
	secondAccessToken, ok := payload["access_token"].(string)
	if !ok || secondAccessToken == "" {
		t.Fatal("activated replay did not issue an access token")
	}
	secondRefreshLifetime := payload["refresh_token_expires_in"]

	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryActivateRoute, "activate-second-exact-replay", false)
	third := httptest.NewRecorder()
	fixture.ctx.Response = third
	handleHumanRefreshDeliveryActivate(fixture.ctx)
	if third.Code != http.StatusOK || fixture.authority.activateCalls != 3 {
		t.Fatalf("second activated replay status/calls = %d/%d", third.Code, fixture.authority.activateCalls)
	}
	var replayPayload map[string]any
	if err := json.Unmarshal(third.Body.Bytes(), &replayPayload); err != nil {
		t.Fatal(err)
	}
	if replayPayload["access_token"] == secondAccessToken ||
		replayPayload["refresh_token"] != testHumanSuccessorRefreshToken ||
		replayPayload["refresh_token_expires_in"].(float64) > secondRefreshLifetime.(float64) {
		t.Fatal("exact activation replay rotated or extended the refresh family")
	}
}

func TestHumanRefreshDeliveryPrepareExactReplayReportsTerminalState(t *testing.T) {
	t.Parallel()

	for _, terminal := range []goidc.HumanRefreshDeliveryPrepareOutcome{
		goidc.HumanRefreshDeliveryPrepareOutcomeActivated,
		goidc.HumanRefreshDeliveryPrepareOutcomeAborted,
	} {
		t.Run(string(terminal), func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.enableOfflineAccess()
			fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryPrepareRoute, "terminal-prepare-"+string(terminal), true)
			fixture.authority.prepare = func(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
				now := int64(timeutil.TimestampNow())
				decision, err := goidc.NewHumanRefreshDeliveryPrepareDecision(goidc.HumanRefreshDeliveryPrepareDecisionConfig{
					Outcome: terminal, ClientID: fixture.client.ID,
					ClientAssertionAuthority: fixture.verifiedAuthority,
					CreatedAt:                now - 600, ExpiresAt: now - 300,
				})
				if err != nil {
					t.Fatal(err)
				}
				return decision, nil
			}
			recorder := httptest.NewRecorder()
			fixture.ctx.Response = recorder
			handleHumanRefreshDeliveryPrepare(fixture.ctx)
			if recorder.Code != http.StatusOK {
				t.Fatalf("terminal prepare replay status = %d", recorder.Code)
			}
			var payload map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["status"] != string(terminal) || payload["expires_in"] != float64(0) {
				t.Fatal("terminal prepare replay was indistinguishable from an unknown tuple")
			}
		})
	}
}

func TestHumanRefreshDeliveryAbortIsNoStoreAndCannotSign(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryAbortRoute, "abort-assertion", false)
	fixture.authority.abort = func(_ context.Context, input goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
		if input.ClientID() != fixture.client.ID || input.ClientAssertionAuthority() != fixture.verifiedAuthority {
			t.Fatal("abort input lost authenticated client binding")
		}
		return fixture.abortedDeliveryDecision(t), nil
	}
	fixture.ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		panic("abort attempted signing")
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder

	handleHumanRefreshDeliveryAbort(fixture.ctx)

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("Pragma") != "no-cache" || recorder.Body.String() != "{\"status\":\"aborted\"}\n" ||
		fixture.authority.abortCalls != 1 {
		t.Fatalf("abort response status/headers/body/calls = %d/%v/%q/%d", recorder.Code, recorder.Header(), recorder.Body.String(), fixture.authority.abortCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestHumanRefreshDeliveryAbortActivatedTupleIsTerminalConflict(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	fixture.enableOfflineAccess()
	fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryAbortRoute, "abort-activated-conflict", false)
	fixture.authority.abort = func(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
		decision, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
			Outcome:  goidc.HumanRefreshDeliveryAbortOutcomeActivatedConflict,
			ClientID: fixture.client.ID, ClientAssertionAuthority: fixture.verifiedAuthority,
		})
		if err != nil {
			t.Fatal(err)
		}
		return decision, nil
	}
	recorder := httptest.NewRecorder()
	fixture.ctx.Response = recorder
	handleHumanRefreshDeliveryAbort(fixture.ctx)
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "{\"status\":\"activated_conflict\"}\n" ||
		recorder.Header().Get("Content-Type") != "application/json" ||
		recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" ||
		responseContainsDeliveryCapability(recorder.Body.String()) {
		t.Fatal("activated abort did not return a credential-free terminal conflict")
	}
}

func TestHumanRefreshDeliveryAuthorityFailuresAreRedactedAndDoNotFallThrough(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		path    string
		install func(*humanTokenAuthorityStub)
		handle  func(oidc.Context)
	}{
		{
			name: "prepare error", path: goidc.HumanRefreshDeliveryPrepareRoute,
			install: func(authority *humanTokenAuthorityStub) {
				authority.prepare = func(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
					return goidc.HumanRefreshDeliveryPrepareDecision{}, errors.New("sensitive prepare failure")
				}
			},
			handle: handleHumanRefreshDeliveryPrepare,
		},
		{
			name: "activate panic", path: goidc.HumanRefreshDeliveryActivateRoute,
			install: func(authority *humanTokenAuthorityStub) {
				authority.activate = func(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
					panic("sensitive activation panic")
				}
			},
			handle: handleHumanRefreshDeliveryActivate,
		},
		{
			name: "abort invalid output", path: goidc.HumanRefreshDeliveryAbortRoute,
			install: func(authority *humanTokenAuthorityStub) {
				authority.abort = func(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
					return goidc.HumanRefreshDeliveryAbortDecision{}, nil
				}
			},
			handle: handleHumanRefreshDeliveryAbort,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.enableOfflineAccess()
			fixture.installDeliveryRequest(t, test.path, "failure-"+strings.ReplaceAll(test.name, " ", "-"), test.path == goidc.HumanRefreshDeliveryPrepareRoute)
			test.install(fixture.authority)
			recorder := httptest.NewRecorder()
			fixture.ctx.Response = recorder
			test.handle(fixture.ctx)
			if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "sensitive") ||
				recorder.Header().Get("Content-Type") != "application/json" ||
				recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" ||
				responseContainsDeliveryCapability(recorder.Body.String()) {
				t.Fatal("authority failure was not a bounded redacted server error")
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

func TestHumanRefreshDeliveryFormsAreExactAndRejectedBeforeAuthority(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "duplicate successor", mutate: func(request *http.Request) {
			request.PostForm[humanRefreshDeliverySuccessorParameter] = append(request.PostForm[humanRefreshDeliverySuccessorParameter], testHumanSuccessorRefreshToken)
		}},
		{name: "missing receipt", mutate: func(request *http.Request) { delete(request.PostForm, humanRefreshDeliveryReceiptParameter) }},
		{name: "same successor and receipt entropy", mutate: func(request *http.Request) {
			request.PostForm.Set(
				humanRefreshDeliveryReceiptParameter,
				goidc.HumanRefreshDeliveryReceiptPrefix+strings.TrimPrefix(testHumanSuccessorRefreshToken, goidc.HumanRefreshTokenPrefix),
			)
		}},
		{name: "unexpected scope", mutate: func(request *http.Request) { request.PostForm["scope"] = []string{"openid"} }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "trace=1" }},
		{name: "authorization header", mutate: func(request *http.Request) { request.Header.Set("Authorization", "Basic ignored") }},
		{name: "dpop", mutate: func(request *http.Request) { request.Header.Set(goidc.HeaderDPoP, "ignored") }},
		{name: "wrong content type", mutate: func(request *http.Request) {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		}},
		{name: "wrong method", mutate: func(request *http.Request) { request.Method = http.MethodGet }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.enableOfflineAccess()
			fixture.installDeliveryRequest(t, goidc.HumanRefreshDeliveryPrepareRoute, "invalid-form-"+strings.ReplaceAll(test.name, " ", "-"), true)
			test.mutate(fixture.ctx.Request)
			recorder := httptest.NewRecorder()
			fixture.ctx.Response = recorder
			handleHumanRefreshDeliveryPrepare(fixture.ctx)
			if recorder.Code != http.StatusBadRequest || fixture.authority.prepareCalls != 0 ||
				recorder.Header().Get("Content-Type") != "application/json" ||
				recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" ||
				fixture.authority.activateCalls != 0 || fixture.authority.abortCalls != 0 {
				t.Fatalf("invalid form status/calls = %d/%d/%d/%d", recorder.Code, fixture.authority.prepareCalls, fixture.authority.activateCalls, fixture.authority.abortCalls)
			}
		})
	}
}

func TestHumanRefreshDeliveryRoutesEnforceBoundedBodies(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	mux := http.NewServeMux()
	RegisterHandlers(mux, fixture.ctx.Configuration)
	body := strings.Repeat("x", int(humanRefreshDeliveryMaxFormBytes)+1)
	request := httptest.NewRequest(http.MethodPost, fixture.ctx.EndpointPrefix+goidc.HumanRefreshDeliveryPrepareRoute, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || fixture.authority.prepareCalls != 0 ||
		recorder.Header().Get("Content-Type") != "application/json" ||
		recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" ||
		responseContainsDeliveryCapability(recorder.Body.String()) {
		t.Fatal("oversized delivery body did not fail before authority")
	}
}

func (fixture *humanTokenFixture) installDeliveryRequest(
	t *testing.T,
	route string,
	assertionID string,
	includePredecessor bool,
) {
	t.Helper()
	now := timeutil.TimestampNow()
	endpoint := fixture.ctx.Issuer() + fixture.ctx.EndpointPrefix + route
	assertion := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer: fixture.client.ID, goidc.ClaimSubject: fixture.client.ID,
		goidc.ClaimAudience: fixture.ctx.Issuer(), goidc.ClaimIssuedAt: now, goidc.ClaimExpiry: now + 50,
		goidc.ClaimTokenID: assertionID,
	}, fixture.assertionKey)
	values := url.Values{
		humanRefreshDeliverySuccessorParameter: {testHumanSuccessorRefreshToken},
		humanRefreshDeliveryReceiptParameter:   {testHumanDeliveryReceipt},
		"client_id":                            {fixture.client.ID}, "client_assertion": {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	if includePredecessor {
		values.Set(humanRefreshDeliveryPredecessorParameter, testHumanRefreshToken)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	fixture.ctx.Request = request
}

func (fixture *humanTokenFixture) pendingDeliveryDecision(t *testing.T) goidc.HumanRefreshDeliveryPrepareDecision {
	t.Helper()
	now := int64(timeutil.TimestampNow())
	decision, err := goidc.NewHumanRefreshDeliveryPrepareDecision(goidc.HumanRefreshDeliveryPrepareDecisionConfig{
		Outcome:  goidc.HumanRefreshDeliveryPrepareOutcomePending,
		ClientID: fixture.client.ID, ClientAssertionAuthority: fixture.verifiedAuthority,
		CreatedAt: now, ExpiresAt: now + 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func (fixture *humanTokenFixture) activatedDeliveryDecision(t *testing.T) goidc.HumanRefreshDeliveryActivateDecision {
	t.Helper()
	now := int64(timeutil.TimestampNow())
	decision, err := goidc.NewHumanRefreshDeliveryActivateDecision(goidc.HumanRefreshDeliveryActivateDecisionConfig{
		Outcome:               goidc.HumanRefreshDeliveryActivateOutcomeActivated,
		RefreshTokenExpiresAt: now + 86_400, GrantID: "human-grant-0001",
		Subject: testHumanSubject, OrganizationID: testHumanOrganizationID,
		MembershipID: testHumanMembershipID, MembershipRevision: 7,
		ClientID: fixture.client.ID, ClientAssertionAuthority: fixture.verifiedAuthority,
		Scopes:             []string{"offline_access", "openid", "profile"},
		Resources:          []string{"https://api.example.invalid/accounting"},
		AuthenticationTime: now - 5, AuthenticationContext: "urn:d0:acr:passkey",
		AuthenticationMethods: []string{"passkey"}, CreatedAt: now, ExpiresAt: now + 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func (fixture *humanTokenFixture) abortedDeliveryDecision(t *testing.T) goidc.HumanRefreshDeliveryAbortDecision {
	t.Helper()
	decision, err := goidc.NewHumanRefreshDeliveryAbortDecision(goidc.HumanRefreshDeliveryAbortDecisionConfig{
		Outcome:  goidc.HumanRefreshDeliveryAbortOutcomeAborted,
		ClientID: fixture.client.ID, ClientAssertionAuthority: fixture.verifiedAuthority,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func responseContainsDeliveryCapability(response string) bool {
	return strings.Contains(response, testHumanRefreshToken) ||
		strings.Contains(response, testHumanSuccessorRefreshToken) ||
		strings.Contains(response, testHumanDeliveryReceipt)
}
