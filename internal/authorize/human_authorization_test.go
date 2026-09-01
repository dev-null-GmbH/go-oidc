package authorize

import (
	"context"
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

const (
	strictHumanTestRequestURI = goidc.HumanPushedRequestURIPrefix + "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
	strictHumanTestEntry      = "d0_hio_e1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	strictHumanTestBinding    = "d0_hio_b1_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
)

func TestHumanConfidentialBFFPARUsesOnlyAtomicAuthority(t *testing.T) {
	t.Parallel()

	ctx, client, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	ctx.HumanConfidentialBFFAuthorizationEnabled = true
	var captured goidc.HumanPARInput
	ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
		storePAR: func(_ context.Context, input goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			captured = input
			uri := mustHumanPushedRequestURI(t, strictHumanTestRequestURI)
			receipt, err := goidc.NewHumanPARReceipt(uri, 60)
			if err != nil {
				t.Fatalf("NewHumanPARReceipt() error = %v", err)
			}
			return mustHumanPARDecision(t, goidc.HumanPAROutcomeCreated, receipt), nil
		},
	}
	legacyPARHandlerCalled := false
	ctx.PARHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
		legacyPARHandlerCalled = true
		return errors.New("legacy PAR handler must not run")
	}

	request := newStrictPARHTTPRequest(values)
	ctx.Request = request
	response, err := pushAuth(ctx, newFormRequest(request))
	if err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if response.RequestURI != strictHumanTestRequestURI || response.ExpiresIn != 60 {
		t.Fatalf("pushAuth() response = %#v", response)
	}
	if legacyPARHandlerCalled {
		t.Fatal("strict PAR called the legacy PAR session handler")
	}
	if !captured.Valid() || captured.ClientID() != client.ID ||
		captured.ClientAssertionAuthority().SnapshotRevision != 17 ||
		captured.ClientAssertionAuthority().KeyAuthorityID != "strict-human-authority-key" ||
		captured.RedirectURI() != client.RedirectURIs[0] ||
		captured.ResponseType() != goidc.ResponseTypeCode ||
		captured.ResponseMode() != goidc.ResponseModeQuery ||
		captured.CodeChallengeMethod() != goidc.CodeChallengeMethodSHA256 {
		t.Fatalf("atomic PAR input = %#v", captured)
	}
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("strict PAR persisted %d legacy sessions", len(sessions))
	}
}

func TestHumanConfidentialBFFOuterAuthorizationUsesOnlyAtomicAuthority(t *testing.T) {
	t.Parallel()

	ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
	ctx.HumanConfidentialBFFAuthorizationEnabled = true
	ctx.HumanIdentityInteractionEndpoint = "https://id.d0.eu/oidc/interaction/identity"
	ctx.HumanBrowserBindingCookieName = "__Host-d0-human-oidc"
	recorder := httptest.NewRecorder()
	ctx.Response = recorder
	expiresAt := int64(timeutil.TimestampNow() + 300)

	var captured goidc.HumanStartInput
	ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
		start: func(_ context.Context, input goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
			captured = input
			entry, err := goidc.NewHumanInteractionEntryCapability(strictHumanTestEntry)
			if err != nil {
				t.Fatalf("NewHumanInteractionEntryCapability() error = %v", err)
			}
			binding, err := goidc.NewHumanBrowserBindingCapability(strictHumanTestBinding)
			if err != nil {
				t.Fatalf("NewHumanBrowserBindingCapability() error = %v", err)
			}
			return mustHumanStartDecision(t, goidc.HumanStartDecisionConfig{
				Outcome: goidc.HumanStartOutcomePending, EntryCapability: entry,
				BrowserBindingCapability: binding, ExpiresAt: expiresAt,
			}), nil
		},
	}
	ctx.PARManager = panicPARManager{}
	ctx.AuthManager = panicAuthManager{}
	ctx.AuthPolicies = []goidc.AuthnPolicy{goidc.NewPolicy(
		"must-not-run",
		func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { panic("legacy policy setup called") },
		func(http.ResponseWriter, *http.Request, *goidc.AuthnSession, *goidc.Client) (goidc.Status, error) {
			panic("legacy policy authentication called")
		},
	)}

	httpRequest := newStrictOuterHTTPRequest(client.ID, requestURI)
	ctx.Request = httpRequest
	if err := initAuth(ctx, newRequest(httpRequest)); err != nil {
		t.Fatalf("initAuth() error = %v", err)
	}
	if !captured.Valid() || captured.ClientID() != client.ID {
		t.Fatalf("atomic start input = %#v", captured)
	}
	renderedURI, err := captured.RequestURI().Render()
	if err != nil || renderedURI != requestURI {
		t.Fatalf("start request_uri = %q, %v", renderedURI, err)
	}
	result := recorder.Result()
	if result.StatusCode != http.StatusSeeOther ||
		result.Header.Get("Location") != "https://id.d0.eu/oidc/interaction/identity#"+strictHumanTestEntry {
		t.Fatalf("start response = status %d, location %q", result.StatusCode, result.Header.Get("Location"))
	}
	if result.Header.Get("Cache-Control") != "no-store" || result.Header.Get("Pragma") != "no-cache" ||
		result.Header.Get("Referrer-Policy") != "no-referrer" || recorder.Body.Len() != 0 {
		t.Fatalf("start response metadata = %#v, body = %q", result.Header, recorder.Body.String())
	}
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("start cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-d0-human-oidc" || cookie.Value != strictHumanTestBinding ||
		cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.Domain != "" || cookie.MaxAge < 1 || cookie.MaxAge > 300 || cookie.Expires.Unix() != expiresAt {
		t.Fatalf("browser-binding cookie = %#v", cookie)
	}
}

func TestHumanConfidentialBFFStartRejectsUnboundedDeadlineBeforeBrowserEffects(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		expiresAt func() int64
	}{
		{name: "expired", expiresAt: func() int64 { return int64(timeutil.TimestampNow()) }},
		{name: "beyond five minutes", expiresAt: func() int64 { return int64(timeutil.TimestampNow() + 301) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
			recorder := httptest.NewRecorder()
			ctx.Response = recorder
			ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
				start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
					entry, err := goidc.NewHumanInteractionEntryCapability(strictHumanTestEntry)
					if err != nil {
						t.Fatal(err)
					}
					binding, err := goidc.NewHumanBrowserBindingCapability(strictHumanTestBinding)
					if err != nil {
						t.Fatal(err)
					}
					return mustHumanStartDecision(t, goidc.HumanStartDecisionConfig{
						Outcome:                  goidc.HumanStartOutcomePending,
						EntryCapability:          entry,
						BrowserBindingCapability: binding,
						ExpiresAt:                test.expiresAt(),
					}), nil
				},
			}
			httpRequest := newStrictOuterHTTPRequest(client.ID, requestURI)
			ctx.Request = httpRequest
			assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeServerError)
			if recorder.Header().Get("Location") != "" || len(recorder.Result().Cookies()) != 0 {
				t.Fatalf("invalid deadline produced browser effects: %#v", recorder.Header())
			}
		})
	}
}

func TestHumanConfidentialBFFStartDeadlineUsesBoundedClockSkew(t *testing.T) {
	t.Parallel()

	const now int64 = 1_800_000_000
	for _, test := range []struct {
		name      string
		expiresAt int64
		skew      int
		wantAge   int
		wantValid bool
	}{
		{name: "zero skew", expiresAt: now + 300, wantAge: 300, wantValid: true},
		{name: "positive skew boundary", expiresAt: now + 300 + 30, skew: 30, wantAge: 300, wantValid: true},
		{name: "positive skew boundary plus one", expiresAt: now + 300 + 31, skew: 30},
		{name: "negative skew", expiresAt: now + 300, skew: -1},
		{name: "unbounded skew", expiresAt: now + 300, skew: 61},
		{name: "overflowing skew", expiresAt: now + 300, skew: int(^uint(0) >> 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			maxAge, valid := humanConfidentialBFFStartDeadline(test.expiresAt, now, test.skew)
			if valid != test.wantValid || maxAge != test.wantAge {
				t.Fatalf("humanConfidentialBFFStartDeadline() = (%d, %t), want (%d, %t)",
					maxAge, valid, test.wantAge, test.wantValid,
				)
			}
		})
	}
}

func TestHumanConfidentialBFFStartAcceptsDatabaseClockAheadWithinSkew(t *testing.T) {
	t.Parallel()

	ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
	ctx.JWTLeewayTimeSecs = 30
	ctx.HumanIdentityInteractionEndpoint = "https://id.d0.eu/oidc/interaction/identity"
	ctx.HumanBrowserBindingCookieName = "__Host-d0-human-oidc"
	recorder := httptest.NewRecorder()
	ctx.Response = recorder
	ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
		start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
			entry, err := goidc.NewHumanInteractionEntryCapability(strictHumanTestEntry)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := goidc.NewHumanBrowserBindingCapability(strictHumanTestBinding)
			if err != nil {
				t.Fatal(err)
			}
			return mustHumanStartDecision(t, goidc.HumanStartDecisionConfig{
				Outcome:                  goidc.HumanStartOutcomePending,
				EntryCapability:          entry,
				BrowserBindingCapability: binding,
				ExpiresAt:                int64(timeutil.TimestampNow() + 330),
			}), nil
		},
	}

	httpRequest := newStrictOuterHTTPRequest(client.ID, requestURI)
	ctx.Request = httpRequest
	if err := initAuth(ctx, newRequest(httpRequest)); err != nil {
		t.Fatalf("initAuth() error = %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != 300 {
		t.Fatalf("database-ahead browser-binding cookies = %#v, want MaxAge 300", cookies)
	}
}

func TestHumanConfidentialBFFNeverFallsBackWhenAtomicAuthorityIsMissing(t *testing.T) {
	t.Parallel()

	ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
	ctx.HumanConfidentialBFFAuthorizationEnabled = true
	ctx.HumanAuthorizationAuthority = nil
	ctx.PARManager = panicPARManager{}
	ctx.AuthManager = panicAuthManager{}
	httpRequest := newStrictOuterHTTPRequest(client.ID, requestURI)
	ctx.Request = httpRequest

	err := initAuth(ctx, newRequest(httpRequest))
	assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
}

func TestDisabledLegacyAuthorizationAuthoritiesFailClosedBeforeManagerCalls(t *testing.T) {
	t.Parallel()

	t.Run("PAR", func(t *testing.T) {
		t.Parallel()
		ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileDefault)
		ctx.LegacyPAREnabled = false
		ctx.PARManager = panicPARManager{}
		httpRequest := newStrictPARHTTPRequest(values)
		ctx.Request = httpRequest
		_, err := pushAuth(ctx, newFormRequest(httpRequest))
		assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
	})

	t.Run("authorization", func(t *testing.T) {
		t.Parallel()
		ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
		client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
		ctx.LegacyAuthorizationCodeEnabled = false
		ctx.AuthManager = panicAuthManager{}
		httpRequest := newStrictOuterHTTPRequest(client.ID, requestURI)
		ctx.Request = httpRequest
		assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeServerError)
	})
}

func newStrictPARHTTPRequest(values url.Values) *http.Request {
	request, err := http.NewRequest(
		http.MethodPost,
		"https://auth.d0.eu/par",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func newStrictOuterHTTPRequest(clientID, requestURI string) *http.Request {
	request, err := http.NewRequest(
		http.MethodGet,
		"https://auth.d0.eu/authorize?"+outerAuthorizationValues(clientID, requestURI).Encode(),
		nil,
	)
	if err != nil {
		panic(err)
	}
	return request
}

type stubHumanAuthorizationAuthority struct {
	storePAR func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error)
	start    func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error)
}

func (authority *stubHumanAuthorizationAuthority) StorePAR(
	ctx context.Context,
	input goidc.HumanPARInput,
) (goidc.HumanPARDecision, error) {
	if authority == nil || authority.storePAR == nil {
		return goidc.HumanPARDecision{}, errors.New("unexpected StorePAR call")
	}
	return authority.storePAR(ctx, input)
}

func (authority *stubHumanAuthorizationAuthority) ConsumePARAndStartContinuation(
	ctx context.Context,
	input goidc.HumanStartInput,
) (goidc.HumanStartDecision, error) {
	if authority == nil || authority.start == nil {
		return goidc.HumanStartDecision{}, errors.New("unexpected ConsumePARAndStartContinuation call")
	}
	return authority.start(ctx, input)
}

func (*stubHumanAuthorizationAuthority) ConfirmBrowser(
	context.Context,
	goidc.HumanContinuationInput,
) (goidc.HumanContinuationDecision, error) {
	return goidc.HumanContinuationDecision{}, errors.New("unexpected ConfirmBrowser call")
}

func (*stubHumanAuthorizationAuthority) CompleteAuthorization(
	context.Context,
	goidc.HumanCompletionInput,
) (goidc.HumanCompletionDecision, error) {
	return goidc.HumanCompletionDecision{}, errors.New("unexpected CompleteAuthorization call")
}

func (*stubHumanAuthorizationAuthority) RedeemAuthorizationCode(
	context.Context,
	goidc.HumanCodeRedemptionInput,
) (goidc.HumanCodeRedemptionDecision, error) {
	return goidc.HumanCodeRedemptionDecision{}, errors.New("unexpected RedeemAuthorizationCode call")
}

func (*stubHumanAuthorizationAuthority) PrepareHumanRefreshDelivery(
	context.Context,
	goidc.HumanRefreshDeliveryPrepareInput,
) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
	return goidc.HumanRefreshDeliveryPrepareDecision{}, errors.New("unexpected PrepareHumanRefreshDelivery call")
}

func (*stubHumanAuthorizationAuthority) ActivateHumanRefreshDelivery(
	context.Context,
	goidc.HumanRefreshDeliveryActivateInput,
) (goidc.HumanRefreshDeliveryActivateDecision, error) {
	return goidc.HumanRefreshDeliveryActivateDecision{}, errors.New("unexpected ActivateHumanRefreshDelivery call")
}

func (*stubHumanAuthorizationAuthority) AbortHumanRefreshDelivery(
	context.Context,
	goidc.HumanRefreshDeliveryAbortInput,
) (goidc.HumanRefreshDeliveryAbortDecision, error) {
	return goidc.HumanRefreshDeliveryAbortDecision{}, errors.New("unexpected AbortHumanRefreshDelivery call")
}

func (*stubHumanAuthorizationAuthority) RevokeRefreshToken(
	context.Context,
	goidc.HumanRefreshRevocationInput,
) error {
	return errors.New("unexpected RevokeRefreshToken call")
}

func mustHumanPushedRequestURI(t *testing.T, value string) goidc.HumanPushedRequestURI {
	t.Helper()
	uri, err := goidc.NewHumanPushedRequestURI(value)
	if err != nil {
		t.Fatalf("NewHumanPushedRequestURI() error = %v", err)
	}
	return uri
}

func mustHumanPARDecision(
	t *testing.T,
	outcome goidc.HumanPAROutcome,
	receipt goidc.HumanPARReceipt,
) goidc.HumanPARDecision {
	t.Helper()
	decision, err := goidc.NewHumanPARDecision(outcome, receipt)
	if err != nil {
		t.Fatalf("NewHumanPARDecision() error = %v", err)
	}
	return decision
}

func mustHumanStartDecision(
	t *testing.T,
	config goidc.HumanStartDecisionConfig,
) goidc.HumanStartDecision {
	t.Helper()
	decision, err := goidc.NewHumanStartDecision(config)
	if err != nil {
		t.Fatalf("NewHumanStartDecision() error = %v", err)
	}
	return decision
}

type panicPARManager struct{}

func (panicPARManager) SessionByPushedAuthReqID(context.Context, string) (*goidc.AuthnSession, error) {
	panic("legacy PAR manager called")
}

type panicAuthManager struct{}

func (panicAuthManager) SaveSession(context.Context, *goidc.AuthnSession) error {
	panic("legacy auth manager SaveSession called")
}
func (panicAuthManager) Session(context.Context, string) (*goidc.AuthnSession, error) {
	panic("legacy auth manager Session called")
}
func (panicAuthManager) GrantByAuthCode(context.Context, string) (*goidc.Grant, error) {
	panic("legacy auth manager GrantByAuthCode called")
}
