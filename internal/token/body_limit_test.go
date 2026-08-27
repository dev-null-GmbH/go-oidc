package token

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanTokenEndpointCapsFormBodyBeforeParsing(t *testing.T) {
	t.Parallel()

	fixture := newHumanTokenFixture(t)
	body := fixture.ctx.Request.PostForm.Encode() + "&padding=" + strings.Repeat(
		"x",
		int(humanTokenMaxFormBytes),
	)
	counted := newTokenCountingBody(body)
	request := httptest.NewRequest(
		http.MethodPost,
		fixture.ctx.Issuer()+fixture.ctx.TokenEndpoint,
		counted,
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	fixture.ctx.Request = request
	fixture.ctx.Response = response

	handleCreate(fixture.ctx)

	assertCappedTokenBody(t, counted, len(body))
	if response.Code != http.StatusBadRequest || response.Body.Len() > 1024 ||
		strings.Contains(response.Body.String(), testHumanAuthorizationCode) {
		t.Fatalf(
			"oversized token response = status %d body %q",
			response.Code,
			response.Body.String(),
		)
	}
	if fixture.authority.redeemCalls != 0 {
		t.Fatalf("oversized token request reached human authority %d times", fixture.authority.redeemCalls)
	}
	fixture.assertNoLegacyIssuance(t)
}

func TestLegacyTokenWithoutHumanAuthorizationRetainsExistingBodyHandling(t *testing.T) {
	t.Parallel()

	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	values := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
		"scope":         {"scope1"},
		"padding":       {strings.Repeat("x", int(humanTokenMaxFormBytes))},
	}
	body := values.Encode()
	counted := newTokenCountingBody(body)
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, counted)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

	if response.Code != http.StatusOK {
		t.Fatalf("legacy token status = %d body %q", response.Code, response.Body.String())
	}
	if counted.bytesRead != len(body) {
		t.Fatalf("legacy token request read %d of %d bytes", counted.bytesRead, len(body))
	}
}

func TestHumanTokenBodyLimitWrapsConfiguredMiddleware(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint func(oidc.Context) string
	}{
		{name: "token", endpoint: func(ctx oidc.Context) string { return ctx.TokenEndpoint }},
		{name: "revocation", endpoint: func(ctx oidc.Context) string { return ctx.TokenRevocationEndpoint }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			fixture.ctx.TokenEndpoint = "/token"
			fixture.ctx.TokenRevocationEndpoint = "/revoke"
			fixture.ctx.TokenRevocationEnabled = true
			var middlewareParseErr error
			middleware := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					middlewareParseErr = request.ParseForm()
					next.ServeHTTP(response, request)
				})
			}
			router := http.NewServeMux()
			RegisterHandlers(router, fixture.ctx.Configuration, middleware)
			body := "padding=" + strings.Repeat("x", int(humanTokenMaxFormBytes)+1024)
			counted := newTokenCountingBody(body)
			request := httptest.NewRequest(
				http.MethodPost,
				fixture.ctx.Issuer()+test.endpoint(fixture.ctx),
				counted,
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if middlewareParseErr != nil {
				t.Fatalf("middleware saw the preserved parse failure directly: %v", middlewareParseErr)
			}
			if counted.bytesRead == 0 || counted.bytesRead > int(humanTokenMaxFormBytes)+1 ||
				counted.bytesRead >= len(body) {
				t.Fatalf(
					"middleware read %d of %d bytes with %d-byte outer cap",
					counted.bytesRead,
					len(body),
					humanTokenMaxFormBytes,
				)
			}
			if fixture.authority.redeemCalls != 0 || fixture.authority.revokeCalls != 0 {
				t.Fatal("oversized middleware-parsed body reached the Human authority")
			}
			if response.Code < http.StatusBadRequest {
				t.Fatalf("oversized request status = %d", response.Code)
			}
		})
	}
}

func TestHumanTokenMalformedFormCannotBeRecoveredByMiddleware(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, *humanTokenFixture)
		path    func(oidc.Context) string
		calls   func(*humanTokenAuthorityStub) int
	}{
		{
			name: "token",
			prepare: func(_ *testing.T, fixture *humanTokenFixture) {
				fixture.ctx.TokenEndpoint = "/token"
			},
			path:  func(ctx oidc.Context) string { return ctx.TokenEndpoint },
			calls: func(authority *humanTokenAuthorityStub) int { return authority.redeemCalls },
		},
		{
			name: "revocation",
			prepare: func(t *testing.T, fixture *humanTokenFixture) {
				fixture.ctx.TokenRevocationEnabled = true
				fixture.ctx.TokenRevocationEndpoint = "/revoke"
				fixture.installRevocationRequest(
					t,
					"human-malformed-revocation-assertion",
					testHumanRefreshToken,
				)
			},
			path:  func(ctx oidc.Context) string { return ctx.TokenRevocationEndpoint },
			calls: func(authority *humanTokenAuthorityStub) int { return authority.revokeCalls },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanTokenFixture(t)
			test.prepare(t, fixture)
			var middlewareParseErr error
			middleware := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					middlewareParseErr = request.ParseForm()
					next.ServeHTTP(response, request)
				})
			}
			router := http.NewServeMux()
			RegisterHandlers(router, fixture.ctx.Configuration, middleware)
			body := fixture.ctx.Request.PostForm.Encode() + "&dropped=%ZZ"
			request := httptest.NewRequest(
				http.MethodPost,
				fixture.ctx.Issuer()+test.path(fixture.ctx),
				strings.NewReader(body),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if middlewareParseErr != nil {
				t.Fatalf("middleware saw preserved parse failure directly: %v", middlewareParseErr)
			}
			if response.Code != http.StatusBadRequest || test.calls(fixture.authority) != 0 {
				t.Fatalf(
					"malformed %s = status %d authority calls %d body %q",
					test.name,
					response.Code,
					test.calls(fixture.authority),
					response.Body.String(),
				)
			}
			fixture.assertNoLegacyIssuance(t)
		})
	}
}

type tokenCountingBody struct {
	reader    *strings.Reader
	bytesRead int
}

func newTokenCountingBody(value string) *tokenCountingBody {
	return &tokenCountingBody{reader: strings.NewReader(value)}
}

func (body *tokenCountingBody) Read(buffer []byte) (int, error) {
	read, err := body.reader.Read(buffer)
	body.bytesRead += read
	return read, err
}

func (*tokenCountingBody) Close() error {
	return nil
}

func assertCappedTokenBody(t *testing.T, body *tokenCountingBody, total int) {
	t.Helper()
	if body.bytesRead == 0 || body.bytesRead > int(humanTokenMaxFormBytes)+1 ||
		body.bytesRead >= total {
		t.Fatalf(
			"token body read %d of %d bytes with %d-byte cap",
			body.bytesRead,
			total,
			humanTokenMaxFormBytes,
		)
	}
}
