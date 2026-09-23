package authorize

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	humanBrowserInteractionPath = "/oidc/interaction/browser"
	humanConsumeInteractionPath = "/oidc/interaction/consume"
)

func TestHumanBrowserInteractionGETMintsFreshSuccessorForOneNativePOST(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)

	first := serveHumanInteraction(t, router, http.MethodGet, humanBrowserInteractionPath, nil, nil)
	second := serveHumanInteraction(t, router, http.MethodGet, humanBrowserInteractionPath, nil, nil)
	for _, response := range []*httptest.ResponseRecorder{first, second} {
		if response.Code != http.StatusOK {
			t.Fatalf("browser GET status = %d, want 200", response.Code)
		}
		if response.Header().Get("Set-Cookie") != "" {
			t.Fatal("browser GET minted or changed the browser-binding cookie")
		}
		assertHumanInteractionSecurityHeaders(t, response.Header())
		assertHumanInteractionFormAction(t, response.Header(), "'self' https://id.d0.eu")
		body := response.Body.String()
		assertHumanInteractionCSPMatchesPageScript(t, response.Header(), body)
		if !strings.Contains(body, `action="/oidc/interaction/browser"`) ||
			!strings.Contains(body, `<meta name="referrer" content="same-origin">`) ||
			!strings.Contains(body, `name="identity_return" value=""`) ||
			!strings.Contains(body, `^d0_hio_r1_[A-Za-z0-9_-]{43}$`) ||
			!strings.Contains(body, "form.submit()") ||
			!strings.Contains(body, `addEventListener("pagehide"`) ||
			strings.Contains(body, `<button`) || strings.Contains(body, "fetch(") ||
			strings.Contains(body, "localStorage") || strings.Contains(body, "sessionStorage") ||
			strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Fatal("browser GET is not a closed native navigation page")
		}
		if strings.Index(body, `name="browser_return"`) > strings.Index(body, "location.hash") {
			t.Fatal("browser successor was not generated before fragment handling script")
		}
		if strings.Index(body, "history.replaceState") > strings.Index(body, "form.submit()") ||
			strings.Index(body, `^d0_hio_r1_[A-Za-z0-9_-]{43}$`) > strings.Index(body, "form.submit()") {
			t.Fatal("browser form submits before fragment clearing or validation")
		}
	}
	firstCapability := browserReturnFromPage(t, first.Body.String())
	secondCapability := browserReturnFromPage(t, second.Body.String())
	if firstCapability == secondCapability {
		t.Fatal("browser GET reused its 256-bit successor capability")
	}
	if _, err := goidc.NewHumanBrowserReturnCapability(firstCapability); err != nil {
		t.Fatalf("browser GET capability is not canonical: %v", err)
	}

	query := serveHumanInteraction(t, router, http.MethodGet, humanBrowserInteractionPath+"?unexpected=1", nil, nil)
	if query.Code != http.StatusBadRequest {
		t.Fatalf("browser GET with query status = %d, want 400", query.Code)
	}
	assertHumanInteractionSecurityHeaders(t, query.Header())
}

func TestHumanBrowserInteractionPOSTConfirmsExactCapabilities(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	identityReturn := testHumanCapability("d0_hio_r1_", 3)
	browserReturn := testHumanCapability("d0_hio_c1_", 4)
	browserBinding := testHumanCapability("d0_hio_b1_", 5)
	identityReadyEndpoint := ctx.HumanIdentityReadyEndpoint
	calls := 0
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		confirm: func(_ context.Context, input goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
			calls++
			assertRenderedHumanCapability(t, input.IdentityReturnCapability().Render, identityReturn)
			assertRenderedHumanCapability(t, input.BrowserReturnCapability().Render, browserReturn)
			assertRenderedHumanCapability(t, input.BrowserBindingCapability().Render, browserBinding)
			ctx.HumanIdentityReadyEndpoint = "https://attacker.invalid/oidc/interaction/ready"
			return mustHumanContinuationDecision(t, goidc.HumanContinuationOutcomeConfirmed, browserReturn), nil
		},
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)

	response := serveHumanInteraction(t, router, http.MethodPost, humanBrowserInteractionPath,
		url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}},
		map[string]string{
			"Origin":            ctx.Host,
			"Referer":           ctx.Host + humanBrowserInteractionPath,
			"Cookie":            ctx.HumanBrowserBindingCookieName + "=" + browserBinding,
			"X-Forwarded-Host":  strings.TrimPrefix(ctx.Host, "https://"),
			"X-Forwarded-Proto": "https",
			"Traceparent":       "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		})
	ctx.HumanIdentityReadyEndpoint = identityReadyEndpoint
	if calls != 1 {
		t.Fatalf("ConfirmBrowser calls = %d, want 1", calls)
	}
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != identityReadyEndpoint+"#"+browserReturn ||
		strings.Contains(response.Header().Get("Location"), "attacker.invalid") ||
		response.Body.Len() != 0 {
		t.Fatalf("browser POST response = status %d, location %q, body %q",
			response.Code, response.Header().Get("Location"), response.Body.String())
	}
	assertHumanInteractionSecurityHeaders(t, response.Header())

	for _, test := range []struct {
		name    string
		target  string
		form    url.Values
		headers map[string]string
	}{
		{name: "query", target: humanBrowserInteractionPath + "?x=1", form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding}},
		{name: "extra form field", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}, "extra": {"x"}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding}},
		{name: "duplicate field", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn, identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding}},
		{name: "missing binding", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host}},
		{name: "duplicate binding", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding + "; " + ctx.HumanBrowserBindingCookieName + "=" + browserBinding}},
		{name: "cross origin", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": "https://attacker.invalid", "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding}},
		{name: "credential header", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding, "Authorization": "Bearer attacker"}},
		{name: "parameterized content type", target: humanBrowserInteractionPath, form: url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}}, headers: map[string]string{"Origin": ctx.Host, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding, "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.headers["Referer"] = ctx.Host + humanBrowserInteractionPath
			before := calls
			result := serveHumanInteraction(t, router, http.MethodPost, test.target, test.form, test.headers)
			if result.Code != http.StatusBadRequest || result.Body.String() != humanInteractionRejectedBody {
				t.Fatalf("malformed browser POST = status %d, body %q", result.Code, result.Body.String())
			}
			if calls != before {
				t.Fatal("malformed browser POST reached the authority")
			}
			assertHumanInteractionSecurityHeaders(t, result.Header())
		})
	}

	for _, header := range []struct {
		name  string
		value string
	}{
		{name: "Content-Type", value: "application/x-www-form-urlencoded"},
		{name: "Origin", value: ctx.Host},
		{name: "Referer", value: ctx.Host + humanBrowserInteractionPath},
		{name: "Sec-Fetch-Site", value: "same-origin"},
	} {
		t.Run("duplicate "+header.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				ctx.Host+humanBrowserInteractionPath,
				strings.NewReader("identity_return=placeholder"),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", ctx.Host)
			request.Header.Set("Referer", ctx.Host+humanBrowserInteractionPath)
			if header.name == "Sec-Fetch-Site" {
				request.Header.Add(header.name, header.value)
			}
			request.Header.Add(header.name, header.value)
			if validHumanInteractionPOSTTransport(request, humanBrowserInteractionPath, ctx.Host) {
				t.Fatalf("duplicate %s accepted", header.name)
			}
		})
	}
}

func TestHumanInteractionPOSTTransportRequiresCanonicalSameOriginReferer(t *testing.T) {
	t.Parallel()

	issuer := "https://auth.d0.eu"
	newRequest := func() *http.Request {
		request := httptest.NewRequest(
			http.MethodPost,
			issuer+humanBrowserInteractionPath,
			strings.NewReader("identity_return=placeholder"),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", issuer)
		return request
	}
	for _, test := range []struct {
		name     string
		referers []string
		want     bool
	}{
		{
			name:     "exact clean same-origin page",
			referers: []string{issuer + humanBrowserInteractionPath},
			want:     true,
		},
		{name: "missing"},
		{name: "null", referers: []string{"null"}},
		{name: "cross origin", referers: []string{"https://attacker.invalid/oidc/interaction/browser"}},
		{name: "wrong clean path", referers: []string{issuer + humanConsumeInteractionPath}},
		{name: "query", referers: []string{issuer + humanBrowserInteractionPath + "?unexpected=1"}},
		{name: "duplicate", referers: []string{issuer + humanBrowserInteractionPath, issuer + humanBrowserInteractionPath}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest()
			for _, referer := range test.referers {
				request.Header.Add("Referer", referer)
			}
			if got := validHumanInteractionPOSTTransport(
				request,
				humanBrowserInteractionPath,
				issuer,
			); got != test.want {
				t.Fatalf("transport accepted = %t, want %t", got, test.want)
			}
		})
	}
}

func TestHumanInteractionAutomaticNavigationRequiresSameOriginMetadata(t *testing.T) {
	t.Parallel()
	const issuer = "https://auth.d0.eu"
	for _, path := range []string{humanBrowserInteractionPath, humanConsumeInteractionPath} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, issuer+path, strings.NewReader("ready=x"))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", issuer)
			request.Header.Set("Referer", issuer+path)
			request.Header.Set("Sec-Fetch-Dest", "document")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			// Native form.submit() has no user activation, so Sec-Fetch-User is absent.
			if !validHumanInteractionPOSTTransport(request, path, issuer) {
				t.Fatal("same-origin automatic form navigation was rejected")
			}
			request.Header.Set("Sec-Fetch-Site", "cross-site")
			if validHumanInteractionPOSTTransport(request, path, issuer) {
				t.Fatal("cross-site automatic form navigation was accepted")
			}
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			request.Header.Set("Sec-Fetch-Mode", "cors")
			if validHumanInteractionPOSTTransport(request, path, issuer) {
				t.Fatal("fetch-style request was accepted as navigation")
			}
		})
	}
}

func TestHumanBrowserInteractionPOSTRejectsMiddlewareRecoveredMalformedForm(t *testing.T) {
	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	identityReturn := testHumanCapability("d0_hio_r1_", 3)
	browserReturn := testHumanCapability("d0_hio_c1_", 4)
	browserBinding := testHumanCapability("d0_hio_b1_", 5)
	authorityCalls := 0
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		confirm: func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
			authorityCalls++
			return mustHumanContinuationDecision(
				t,
				goidc.HumanContinuationOutcomeConfirmed,
				browserReturn,
			), nil
		},
	}
	var middlewareParseErr error
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			middlewareParseErr = request.ParseForm()
			next.ServeHTTP(response, request)
		})
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration, middleware)
	form := url.Values{
		humanIdentityReturnFormField: {identityReturn},
		humanBrowserReturnFormField:  {browserReturn},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		ctx.Issuer()+humanBrowserInteractionPath,
		strings.NewReader(form.Encode()+"&dropped=%ZZ"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", ctx.Host)
	request.Header.Set("Referer", ctx.Host+humanBrowserInteractionPath)
	request.Header.Set("Cookie", ctx.HumanBrowserBindingCookieName+"="+browserBinding)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if middlewareParseErr != nil {
		t.Fatalf("middleware saw preserved parse failure directly: %v", middlewareParseErr)
	}
	if response.Code != http.StatusBadRequest || authorityCalls != 0 {
		t.Fatalf(
			"malformed browser interaction = status %d authority calls %d body %q",
			response.Code,
			authorityCalls,
			response.Body.String(),
		)
	}
}

func TestHumanConsumeInteractionPOSTRejectsMiddlewareRecoveredMalformedForm(t *testing.T) {
	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ready := testHumanCapability("d0_hio_s1_", 6)
	browserBinding := testHumanCapability("d0_hio_b1_", 7)
	authorityCalls := 0
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			authorityCalls++
			return goidc.HumanCompletionDecision{}, nil
		},
	}
	var middlewareParseErr error
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			middlewareParseErr = request.ParseForm()
			next.ServeHTTP(response, request)
		})
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration, middleware)
	form := url.Values{humanReadyFormField: {ready}}
	request := httptest.NewRequest(
		http.MethodPost,
		ctx.Issuer()+humanConsumeInteractionPath,
		strings.NewReader(form.Encode()+"&dropped=%ZZ"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", ctx.Host)
	request.Header.Set("Referer", ctx.Host+humanConsumeInteractionPath)
	request.Header.Set("Cookie", ctx.HumanBrowserBindingCookieName+"="+browserBinding)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if middlewareParseErr != nil {
		t.Fatalf("middleware saw preserved parse failure directly: %v", middlewareParseErr)
	}
	if response.Code != http.StatusBadRequest || authorityCalls != 0 {
		t.Fatalf(
			"malformed consume interaction = status %d authority calls %d body %q",
			response.Code,
			authorityCalls,
			response.Body.String(),
		)
	}
}

func TestHumanInteractionRoutesHaveNoDynamicOrDisabledSurface(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	for _, target := range []string{
		humanBrowserInteractionPath + "/callback",
		humanConsumeInteractionPath + "/callback",
	} {
		response := serveHumanInteraction(t, router, http.MethodGet, target, nil, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("dynamic interaction path %q status = %d, want 404", target, response.Code)
		}
	}
	methodResponse := serveHumanInteraction(t, router, http.MethodPut, humanBrowserInteractionPath, nil, nil)
	if methodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected method status = %d, want 405", methodResponse.Code)
	}
	assertHumanInteractionSecurityHeaders(t, methodResponse.Header())

	disabled, _, _ := newStrictOuterAuthorizationContext(t)
	disabled.HumanConfidentialBFFAuthorizationEnabled = false
	disabledRouter := http.NewServeMux()
	RegisterHandlers(disabledRouter, disabled.Configuration)
	response := serveHumanInteraction(t, disabledRouter, http.MethodGet, humanBrowserInteractionPath, nil, nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled interaction route status = %d, want 404", response.Code)
	}
}

func TestHumanInteractionRoutesHonorProviderPathPrefix(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ctx.EndpointPrefix = "/tenant"
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)

	for _, test := range []struct {
		path   string
		action string
	}{
		{path: humanBrowserInteractionPath, action: `/tenant/oidc/interaction/browser`},
		{path: humanConsumeInteractionPath, action: `/tenant/oidc/interaction/consume`},
	} {
		if response := serveHumanInteraction(t, router, http.MethodGet, test.path, nil, nil); response.Code != http.StatusNotFound {
			t.Fatalf("unprefixed interaction route %q status = %d, want 404", test.path, response.Code)
		}
		response := serveHumanInteraction(t, router, http.MethodGet, "/tenant"+test.path, nil, nil)
		if response.Code != http.StatusOK ||
			!strings.Contains(response.Body.String(), `action="`+test.action+`"`) {
			t.Fatalf(
				"prefixed interaction route %q = status %d body %q",
				test.path,
				response.Code,
				response.Body.String(),
			)
		}
	}
}

func TestHumanBrowserInteractionLogicalRejectionsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	identityReturn := testHumanCapability("d0_hio_r1_", 22)
	browserReturn := testHumanCapability("d0_hio_c1_", 23)
	browserBinding := testHumanCapability("d0_hio_b1_", 24)
	var referenceBody string
	for _, outcome := range []goidc.HumanContinuationOutcome{
		goidc.HumanContinuationOutcomeExpired,
		goidc.HumanContinuationOutcomeRejected,
	} {
		ctx, _, _ := newStrictOuterAuthorizationContext(t)
		configureHumanInteractionTestContext(ctx)
		ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
			confirm: func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
				return mustHumanContinuationDecision(t, outcome, ""), nil
			},
		}
		router := http.NewServeMux()
		RegisterHandlers(router, ctx.Configuration)
		response := serveHumanInteraction(t, router, http.MethodPost, humanBrowserInteractionPath,
			url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}},
			map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanBrowserInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", outcome, response.Code)
		}
		if referenceBody == "" {
			referenceBody = response.Body.String()
		} else if response.Body.String() != referenceBody {
			t.Fatalf("%s response differs from the other logical rejection", outcome)
		}
	}
}

func TestHumanBrowserInteractionReplaysOnlyTheExactSuccessor(t *testing.T) {
	t.Parallel()

	identityReturn := testHumanCapability("d0_hio_r1_", 11)
	browserReturn := testHumanCapability("d0_hio_c1_", 12)
	browserBinding := testHumanCapability("d0_hio_b1_", 13)
	for _, test := range []struct {
		name       string
		decision   func(*testing.T) (goidc.HumanContinuationDecision, error)
		wantStatus int
	}{
		{
			name: "replayed exact successor",
			decision: func(t *testing.T) (goidc.HumanContinuationDecision, error) {
				return mustHumanContinuationDecision(t, goidc.HumanContinuationOutcomeReplayed, browserReturn), nil
			},
			wantStatus: http.StatusSeeOther,
		},
		{
			name: "replayed substituted successor",
			decision: func(t *testing.T) (goidc.HumanContinuationDecision, error) {
				return mustHumanContinuationDecision(t, goidc.HumanContinuationOutcomeReplayed,
					testHumanCapability("d0_hio_c1_", 14)), nil
			},
			wantStatus: http.StatusInternalServerError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _, _ := newStrictOuterAuthorizationContext(t)
			configureHumanInteractionTestContext(ctx)
			ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
				confirm: func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
					return test.decision(t)
				},
			}
			router := http.NewServeMux()
			RegisterHandlers(router, ctx.Configuration)
			response := serveHumanInteraction(t, router, http.MethodPost, humanBrowserInteractionPath,
				url.Values{"identity_return": {identityReturn}, "browser_return": {browserReturn}},
				map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanBrowserInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if test.wantStatus == http.StatusSeeOther &&
				response.Header().Get("Location") != ctx.HumanIdentityReadyEndpoint+"#"+browserReturn {
				t.Fatalf("replay location = %q", response.Header().Get("Location"))
			}
			if strings.Contains(response.Body.String(), browserReturn) {
				t.Fatal("browser capability leaked into the response body")
			}
		})
	}
}

func TestHumanConsumeInteractionGETKeepsReadyCapabilityOutOfDocument(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	response := serveHumanInteraction(t, router, http.MethodGet, humanConsumeInteractionPath, nil, nil)

	if response.Code != http.StatusOK {
		t.Fatalf("consume GET status = %d, want 200", response.Code)
	}
	assertHumanInteractionSecurityHeaders(t, response.Header())
	assertHumanInteractionFormAction(t, response.Header(), "'self' https://human-bff.example.invalid")
	body := response.Body.String()
	assertHumanInteractionCSPMatchesPageScript(t, response.Header(), body)
	if !strings.Contains(body, `action="/oidc/interaction/consume"`) ||
		!strings.Contains(body, `<meta name="referrer" content="same-origin">`) ||
		!strings.Contains(body, `name="ready" value=""`) ||
		!strings.Contains(body, `^d0_hio_s1_[A-Za-z0-9_-]{43}$`) ||
		!strings.Contains(body, "form.submit()") ||
		!strings.Contains(body, `addEventListener("pagehide"`) ||
		strings.Contains(body, `<button`) || strings.Contains(body, "fetch(") ||
		strings.Contains(body, "localStorage") ||
		strings.Contains(body, "sessionStorage") || strings.Contains(body, "http://") ||
		strings.Contains(body, "https://") {
		t.Fatalf("consume GET is not a closed native navigation page: %q", body)
	}
	if strings.Index(body, "history.replaceState") > strings.Index(body, "form.submit()") ||
		strings.Index(body, `^d0_hio_s1_[A-Za-z0-9_-]{43}$`) > strings.Index(body, "form.submit()") {
		t.Fatal("consume form submits before fragment clearing or validation")
	}
}

func TestHumanInteractionPagesIgnoreForwardedFormActionOrigins(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	headers := map[string]string{
		"Forwarded":         "host=attacker.invalid;proto=https",
		"X-Forwarded-Host":  "attacker.invalid",
		"X-Forwarded-Proto": "https",
	}
	for _, test := range []struct {
		path string
		want string
	}{
		{path: humanBrowserInteractionPath, want: "'self' https://id.d0.eu"},
		{path: humanConsumeInteractionPath, want: "'self' https://human-bff.example.invalid"},
	} {
		response := serveHumanInteraction(t, router, http.MethodGet, test.path, nil, headers)
		if response.Code != http.StatusOK ||
			strings.Contains(response.Header().Get("Content-Security-Policy"), "attacker.invalid") {
			t.Fatalf("forwarded authority changed %s response", test.path)
		}
		assertHumanInteractionFormAction(t, response.Header(), test.want)
	}
}

func TestHumanInteractionConfigurationRejectsInjectedBrowserOrigin(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ctx.HumanBrowserOrigin = "https://app.d0.eu; form-action *"
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	response := serveHumanInteraction(t, router, http.MethodGet, humanConsumeInteractionPath, nil, nil)

	if response.Code != http.StatusInternalServerError || response.Body.String() != humanInteractionServerBody ||
		strings.Contains(response.Header().Get("Content-Security-Policy"), "app.d0.eu") ||
		strings.Contains(response.Header().Get("Content-Security-Policy"), "*") {
		t.Fatalf("injected browser origin changed bounded error response")
	}
	assertHumanInteractionFormAction(t, response.Header(), "'self'")
}

func TestHumanConsumeInteractionPOSTCompletesAgainstFreshClientAuthority(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ctx.StaticClients = nil
	ctx.AuthManager = panicAuthManager{}
	ctx.PARManager = panicPARManager{}
	resolveCalls := 0
	ctx.ResolveClientFunc = func(_ context.Context, clientID string) (*goidc.Client, error) {
		resolveCalls++
		if clientID != client.ID {
			return nil, errors.New("unexpected client")
		}
		return client, nil
	}
	ready := testHumanCapability("d0_hio_s1_", 6)
	browserBinding := testHumanCapability("d0_hio_b1_", 7)
	authorizationCode := testHumanCapability("d0_hac_1_", 8)
	state := "opaque-client-state-value"
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		complete: func(_ context.Context, input goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			assertRenderedHumanCapability(t, input.ReadyCapability().Render, ready)
			assertRenderedHumanCapability(t, input.BrowserBindingCapability().Render, browserBinding)
			return mustHumanCompletionDecision(t, goidc.HumanCompletionDecisionConfig{
				Outcome:                 goidc.HumanCompletionOutcomeCompleted,
				Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
				ClientID:                client.ID,
				ClientSnapshotRevision:  client.PrivateKeyJWTAuthority.SnapshotRevision,
				AdmissionKeyAuthorityID: client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID,
				AuthorizationCode:       mustHumanAuthorizationCode(t, authorizationCode),
				RedirectURI:             client.RedirectURIs[0],
				State:                   state,
				CodeExpiresInSeconds:    60,
			}), nil
		},
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)

	response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
		url.Values{"ready": {ready}},
		map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
	if resolveCalls != 1 {
		t.Fatalf("fresh ResolveClient calls = %d, want 1", resolveCalls)
	}
	wantLocation := client.RedirectURIs[0] + "?code=" + authorizationCode +
		"&iss=https%3A%2F%2Fexample.com&state=opaque-client-state-value"
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != wantLocation || response.Body.Len() != 0 {
		t.Fatalf("consume POST response = status %d, location %q, body %q",
			response.Code, response.Header().Get("Location"), response.Body.String())
	}
	assertHumanInteractionSecurityHeaders(t, response.Header())
	assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
}

func TestHumanConsumeInteractionRejectsRegisteredRedirectOutsideConfiguredBrowserOrigin(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ctx.HumanBrowserOrigin = "https://attacker.invalid"
	ready := testHumanCapability("d0_hio_s1_", 34)
	browserBinding := testHumanCapability("d0_hio_b1_", 35)
	authorizationCode := testHumanCapability("d0_hac_1_", 36)
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			ctx.HumanBrowserOrigin = "https://human-bff.example.invalid"
			return mustHumanCompletionDecision(t, goidc.HumanCompletionDecisionConfig{
				Outcome:                 goidc.HumanCompletionOutcomeCompleted,
				Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
				ClientID:                client.ID,
				ClientSnapshotRevision:  client.PrivateKeyJWTAuthority.SnapshotRevision,
				AdmissionKeyAuthorityID: client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID,
				AuthorizationCode:       mustHumanAuthorizationCode(t, authorizationCode),
				RedirectURI:             client.RedirectURIs[0],
				State:                   "opaque-client-state-value",
				CodeExpiresInSeconds:    60,
			}), nil
		},
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)

	response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
		url.Values{"ready": {ready}},
		map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
	if response.Code != http.StatusInternalServerError || response.Header().Get("Location") != "" ||
		response.Body.String() != humanInteractionServerBody ||
		strings.Contains(response.Header().Get("Content-Security-Policy"), "attacker.invalid") ||
		strings.Contains(response.Body.String(), authorizationCode) {
		t.Fatalf("cross-browser-origin completion = status %d, location %q, body %q",
			response.Code, response.Header().Get("Location"), response.Body.String())
	}
	assertHumanInteractionFormAction(t, response.Header(), "'self'")
	assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
}

func TestHumanConsumeInteractionFailsClosedAfterCurrentAuthorityChanges(t *testing.T) {
	t.Parallel()

	ctx, admittedClient, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ctx.StaticClients = nil
	currentClient, err := cloneHumanConfidentialBFFClient(admittedClient)
	if err != nil {
		t.Fatal(err)
	}
	currentClient.PrivateKeyJWTAuthority.SnapshotRevision++
	ctx.ResolveClientFunc = func(context.Context, string) (*goidc.Client, error) {
		return currentClient, nil
	}
	ready := testHumanCapability("d0_hio_s1_", 15)
	browserBinding := testHumanCapability("d0_hio_b1_", 16)
	authorizationCode := testHumanCapability("d0_hac_1_", 17)
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			return mustHumanCompletionDecision(t, goidc.HumanCompletionDecisionConfig{
				Outcome:                 goidc.HumanCompletionOutcomeCompleted,
				Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
				ClientID:                admittedClient.ID,
				ClientSnapshotRevision:  admittedClient.PrivateKeyJWTAuthority.SnapshotRevision,
				AdmissionKeyAuthorityID: admittedClient.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID,
				AuthorizationCode:       mustHumanAuthorizationCode(t, authorizationCode),
				RedirectURI:             admittedClient.RedirectURIs[0],
				State:                   "opaque-client-state-value",
				CodeExpiresInSeconds:    60,
			}), nil
		},
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
		url.Values{"ready": {ready}},
		map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
	if response.Code != http.StatusInternalServerError || response.Header().Get("Location") != "" ||
		strings.Contains(response.Body.String(), authorizationCode) {
		t.Fatalf("changed authority response = status %d, location %q, body %q",
			response.Code, response.Header().Get("Location"), response.Body.String())
	}
	assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
}

func TestHumanConsumeInteractionCleanFailureUsesBoundedRedirect(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	configureHumanInteractionTestContext(ctx)
	ready := testHumanCapability("d0_hio_s1_", 18)
	browserBinding := testHumanCapability("d0_hio_b1_", 19)
	ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
		complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
			return mustHumanCompletionDecision(t, goidc.HumanCompletionDecisionConfig{
				Outcome:                 goidc.HumanCompletionOutcomeFailed,
				Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
				ClientID:                client.ID,
				ClientSnapshotRevision:  client.PrivateKeyJWTAuthority.SnapshotRevision,
				AdmissionKeyAuthorityID: client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID,
				RedirectURI:             client.RedirectURIs[0],
				State:                   "opaque-client-state-value",
				Failure:                 goidc.HumanAuthorizationFailureAccessDenied,
			}), nil
		},
	}
	router := http.NewServeMux()
	RegisterHandlers(router, ctx.Configuration)
	response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
		url.Values{"ready": {ready}},
		map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
	want := client.RedirectURIs[0] + "?error=access_denied&iss=https%3A%2F%2Fexample.com&state=opaque-client-state-value"
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want || response.Body.Len() != 0 {
		t.Fatalf("clean failure response = status %d, location %q, body %q",
			response.Code, response.Header().Get("Location"), response.Body.String())
	}
	assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
}

func TestHumanConsumeInteractionAuthorityFailureBurnsBrowserBinding(t *testing.T) {
	t.Parallel()

	ready := testHumanCapability("d0_hio_s1_", 20)
	browserBinding := testHumanCapability("d0_hio_b1_", 21)
	for _, authorityFailure := range []func() error{
		func() error { return errors.New("authority unavailable") },
		func() error { panic("authority panic") },
	} {
		ctx, _, _ := newStrictOuterAuthorizationContext(t)
		configureHumanInteractionTestContext(ctx)
		ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
			complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
				return goidc.HumanCompletionDecision{}, authorityFailure()
			},
		}
		router := http.NewServeMux()
		RegisterHandlers(router, ctx.Configuration)
		response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
			url.Values{"ready": {ready}},
			map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
		if response.Code != http.StatusInternalServerError || response.Body.String() != humanInteractionServerBody {
			t.Fatalf("authority failure = status %d, body %q", response.Code, response.Body.String())
		}
		assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
	}
}

func TestHumanConsumeInteractionTerminalRejectionsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	ready := testHumanCapability("d0_hio_s1_", 9)
	browserBinding := testHumanCapability("d0_hio_b1_", 10)
	var referenceBody string
	for _, outcome := range []goidc.HumanCompletionOutcome{
		goidc.HumanCompletionOutcomeReplayed,
		goidc.HumanCompletionOutcomeExpired,
		goidc.HumanCompletionOutcomeRejected,
	} {
		ctx, _, _ := newStrictOuterAuthorizationContext(t)
		configureHumanInteractionTestContext(ctx)
		ctx.HumanAuthorizationAuthority = humanInteractionAuthorityStub{
			complete: func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
				return mustHumanCompletionDecision(t, goidc.HumanCompletionDecisionConfig{Outcome: outcome}), nil
			},
		}
		router := http.NewServeMux()
		RegisterHandlers(router, ctx.Configuration)
		response := serveHumanInteraction(t, router, http.MethodPost, humanConsumeInteractionPath,
			url.Values{"ready": {ready}},
			map[string]string{"Origin": ctx.Host, "Referer": ctx.Host + humanConsumeInteractionPath, "Cookie": ctx.HumanBrowserBindingCookieName + "=" + browserBinding})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", outcome, response.Code)
		}
		if referenceBody == "" {
			referenceBody = response.Body.String()
		} else if response.Body.String() != referenceBody {
			t.Fatalf("%s body differs from other terminal rejection", outcome)
		}
		assertHumanBrowserBindingCleared(t, response.Result(), ctx.HumanBrowserBindingCookieName)
	}
}

func serveHumanInteraction(
	t *testing.T,
	router http.Handler,
	method string,
	target string,
	form url.Values,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(method, "https://example.com"+target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func configureHumanInteractionTestContext(ctx oidc.Context) {
	ctx.HumanIdentityReadyEndpoint = "https://id.d0.eu/oidc/interaction/ready"
	ctx.HumanBrowserOrigin = "https://human-bff.example.invalid"
	ctx.IssuerRespParamEnabled = true
}

func assertHumanInteractionSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	if header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache" ||
		header.Get("Referrer-Policy") != "same-origin" ||
		!strings.Contains(header.Get("Content-Security-Policy"), "default-src 'none'") ||
		header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("interaction security headers = %#v", header)
	}
}

func assertHumanInteractionCSPMatchesPageScript(t *testing.T, header http.Header, body string) {
	t.Helper()
	match := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("interaction page script missing")
	}
	digest := sha256.Sum256([]byte(match[1]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	if !strings.Contains(header.Get("Content-Security-Policy"), want) {
		t.Fatalf("CSP does not authorize only the rendered script: want %s in %q", want,
			header.Get("Content-Security-Policy"))
	}
}

func assertHumanInteractionFormAction(t *testing.T, header http.Header, want string) {
	t.Helper()
	directives := make(map[string]string)
	for _, directive := range strings.Split(header.Get("Content-Security-Policy"), ";") {
		directive = strings.TrimSpace(directive)
		name, value, found := strings.Cut(directive, " ")
		if !found || name == "" || value == "" {
			t.Fatalf("invalid CSP directive %q", directive)
		}
		if _, duplicate := directives[name]; duplicate {
			t.Fatalf("duplicate CSP directive %q", name)
		}
		directives[name] = value
	}
	if got := directives["form-action"]; got != want {
		t.Fatalf("form-action = %q, want %q", got, want)
	}
	fixed := map[string]string{
		"default-src":     "'none'",
		"style-src":       "'none'",
		"img-src":         "'none'",
		"font-src":        "'none'",
		"media-src":       "'none'",
		"connect-src":     "'none'",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"frame-ancestors": "'none'",
	}
	if len(directives) != len(fixed)+2 {
		t.Fatalf("CSP directive count = %d, want %d", len(directives), len(fixed)+2)
	}
	for name, value := range fixed {
		if directives[name] != value {
			t.Fatalf("%s = %q, want %q", name, directives[name], value)
		}
	}
	if script := directives["script-src"]; script != "'none'" &&
		(!strings.HasPrefix(script, "'sha256-") || !strings.HasSuffix(script, "'")) {
		t.Fatalf("script-src = %q, want none or one SHA-256 source", script)
	}
}

func browserReturnFromPage(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="browser_return" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("browser-return capability missing from page: %q", body)
	}
	return match[1]
}

func testHumanCapability(prefix string, value byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func assertRenderedHumanCapability(t *testing.T, render func() (string, error), want string) {
	t.Helper()
	got, err := render()
	if err != nil || got != want {
		t.Fatalf("rendered capability = %q, %v; want %q", got, err, want)
	}
}

func mustHumanContinuationDecision(
	t *testing.T,
	outcome goidc.HumanContinuationOutcome,
	rawBrowserReturn string,
) goidc.HumanContinuationDecision {
	t.Helper()
	var browserReturn goidc.HumanBrowserReturnCapability
	if rawBrowserReturn != "" {
		var err error
		browserReturn, err = goidc.NewHumanBrowserReturnCapability(rawBrowserReturn)
		if err != nil {
			t.Fatal(err)
		}
	}
	decision, err := goidc.NewHumanContinuationDecision(outcome, browserReturn)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func mustHumanCompletionDecision(
	t *testing.T,
	config goidc.HumanCompletionDecisionConfig,
) goidc.HumanCompletionDecision {
	t.Helper()
	decision, err := goidc.NewHumanCompletionDecision(config)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func mustHumanAuthorizationCode(t *testing.T, value string) goidc.HumanAuthorizationCode {
	t.Helper()
	code, err := goidc.NewHumanAuthorizationCode(value)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func assertHumanBrowserBindingCleared(t *testing.T, response *http.Response, name string) {
	t.Helper()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("terminal response cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != name || cookie.Value != "" || cookie.Path != "/" || cookie.Domain != "" ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.MaxAge != -1 || !cookie.Expires.Before(time.Now()) {
		t.Fatalf("cleared browser-binding cookie = %#v", cookie)
	}
}

type humanInteractionAuthorityStub struct {
	confirm  func(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error)
	complete func(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error)
}

func (humanInteractionAuthorityStub) StorePAR(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
	return goidc.HumanPARDecision{}, errors.New("unexpected StorePAR call")
}

func (humanInteractionAuthorityStub) ConsumePARAndStartContinuation(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
	return goidc.HumanStartDecision{}, errors.New("unexpected ConsumePARAndStartContinuation call")
}

func (stub humanInteractionAuthorityStub) ConfirmBrowser(ctx context.Context, input goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
	if stub.confirm == nil {
		return goidc.HumanContinuationDecision{}, errors.New("unexpected ConfirmBrowser call")
	}
	return stub.confirm(ctx, input)
}

func (stub humanInteractionAuthorityStub) CompleteAuthorization(ctx context.Context, input goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
	if stub.complete == nil {
		return goidc.HumanCompletionDecision{}, errors.New("unexpected CompleteAuthorization call")
	}
	return stub.complete(ctx, input)
}

func (humanInteractionAuthorityStub) RedeemAuthorizationCode(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
	return goidc.HumanCodeRedemptionDecision{}, errors.New("unexpected RedeemAuthorizationCode call")
}
func (humanInteractionAuthorityStub) PrepareHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryPrepareInput) (goidc.HumanRefreshDeliveryPrepareDecision, error) {
	return goidc.HumanRefreshDeliveryPrepareDecision{}, errors.New("unexpected PrepareHumanRefreshDelivery call")
}
func (humanInteractionAuthorityStub) ActivateHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryActivateInput) (goidc.HumanRefreshDeliveryActivateDecision, error) {
	return goidc.HumanRefreshDeliveryActivateDecision{}, errors.New("unexpected ActivateHumanRefreshDelivery call")
}
func (humanInteractionAuthorityStub) AbortHumanRefreshDelivery(context.Context, goidc.HumanRefreshDeliveryAbortInput) (goidc.HumanRefreshDeliveryAbortDecision, error) {
	return goidc.HumanRefreshDeliveryAbortDecision{}, errors.New("unexpected AbortHumanRefreshDelivery call")
}
func (humanInteractionAuthorityStub) RevokeRefreshToken(context.Context, goidc.HumanRefreshRevocationInput) error {
	return errors.New("unexpected RevokeRefreshToken call")
}

var _ goidc.HumanAuthorizationAuthority = humanInteractionAuthorityStub{}
