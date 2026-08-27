package authorize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanAuthorizationHandlersCapFormBodiesBeforeParsing(t *testing.T) {
	t.Parallel()

	t.Run("PAR", func(t *testing.T) {
		t.Parallel()
		ctx, _, values := newStrictPARContext(
			t,
			goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		)
		storeCalls := 0
		ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
			storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
				storeCalls++
				return goidc.HumanPARDecision{}, nil
			},
		}
		body := values.Encode() + "&padding=" + strings.Repeat(
			"x",
			int(humanAuthorizationMaxFormBytes),
		)
		counted := newAuthorizationCountingBody(body)
		request := httptest.NewRequest(http.MethodPost, "https://example.com/par", counted)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = request

		handlerPAR(ctx)

		response := ctx.Response.(*httptest.ResponseRecorder)
		assertCappedAuthorizationBody(t, counted, len(body))
		if response.Code != http.StatusUnauthorized || response.Body.Len() > 1024 ||
			strings.Contains(response.Body.String(), strictHumanTestRequestURI) {
			t.Fatalf(
				"oversized PAR response = status %d body %q",
				response.Code,
				response.Body.String(),
			)
		}
		if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
			t.Fatalf("oversized PAR persisted %d sessions", len(sessions))
		}
		if storeCalls != 0 {
			t.Fatalf("oversized PAR reached human authority %d times", storeCalls)
		}
	})

	t.Run("POST authorize", func(t *testing.T) {
		t.Parallel()
		ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
		startCalls := 0
		ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
			start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
				startCalls++
				return goidc.HumanStartDecision{}, nil
			},
		}
		values := outerAuthorizationValues(client.ID, requestURI)
		body := values.Encode() + "&padding=" + strings.Repeat(
			"x",
			int(humanAuthorizationMaxFormBytes),
		)
		counted := newAuthorizationCountingBody(body)
		request := httptest.NewRequest(
			http.MethodPost,
			"https://example.com/authorize",
			counted,
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = request

		handler(ctx)

		response := ctx.Response.(*httptest.ResponseRecorder)
		assertCappedAuthorizationBody(t, counted, len(body))
		if response.Code != http.StatusUnauthorized || response.Body.Len() > 1024 ||
			strings.Contains(response.Body.String(), requestURI) {
			t.Fatalf(
				"oversized POST authorize response = status %d body %q",
				response.Code,
				response.Body.String(),
			)
		}
		if startCalls != 0 {
			t.Fatalf("oversized POST authorize reached human authority %d times", startCalls)
		}
	})
}

func TestLegacyPARWithoutHumanAuthorizationRetainsExistingBodyHandling(t *testing.T) {
	t.Parallel()

	ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileDefault)
	body := values.Encode() + "&padding=" + strings.Repeat(
		"x",
		int(humanAuthorizationMaxFormBytes),
	)
	counted := newAuthorizationCountingBody(body)
	request := httptest.NewRequest(http.MethodPost, "https://example.com/par", counted)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = request

	handlerPAR(ctx)

	response := ctx.Response.(*httptest.ResponseRecorder)
	if response.Code != http.StatusCreated {
		t.Fatalf("legacy PAR status = %d body %q", response.Code, response.Body.String())
	}
	if counted.bytesRead != len(body) {
		t.Fatalf("legacy PAR read %d of %d bytes", counted.bytesRead, len(body))
	}
}

func TestHumanAuthorizationFormLimitLeavesPreparsedBodyAlone(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	request := httptest.NewRequest(
		http.MethodPost,
		"https://example.com/authorize",
		strings.NewReader("client_id=already-parsed"),
	)
	request.PostForm = url.Values{"client_id": {"already-parsed"}}
	original := request.Body
	ctx.Request = request

	limitHumanAuthorizationFormBody(ctx)

	if ctx.Request.Body != original {
		t.Fatal("preparsed authorization body was wrapped after form parsing")
	}
}

func TestHumanAuthorizationBodyLimitWrapsConfiguredMiddleware(t *testing.T) {
	ctx, _, _ := newStrictPARContext(
		t,
		goidc.AuthorizationRequestProfileHumanConfidentialBFF,
	)

	for _, test := range []struct {
		name         string
		path         string
		maximumBytes int64
	}{
		{name: "PAR", path: ctx.PAREndpoint, maximumBytes: humanAuthorizationMaxFormBytes},
		{name: "POST authorize", path: ctx.AuthorizationEndpoint, maximumBytes: humanAuthorizationMaxFormBytes},
		{name: "browser interaction", path: humanBrowserInteractionRoute, maximumBytes: humanInteractionMaxFormBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			var middlewareParseErr error
			middleware := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					middlewareParseErr = request.ParseForm()
					next.ServeHTTP(response, request)
				})
			}
			router := http.NewServeMux()
			RegisterHandlers(router, ctx.Configuration, middleware)
			body := "padding=" + strings.Repeat("x", int(test.maximumBytes)+1024)
			counted := newAuthorizationCountingBody(body)
			request := httptest.NewRequest(
				http.MethodPost,
				"https://example.com"+test.path,
				counted,
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if middlewareParseErr != nil {
				t.Fatalf("middleware saw the preserved parse failure directly: %v", middlewareParseErr)
			}
			if counted.bytesRead == 0 || counted.bytesRead > int(test.maximumBytes)+1 ||
				counted.bytesRead >= len(body) {
				t.Fatalf(
					"middleware read %d of %d bytes with %d-byte outer cap",
					counted.bytesRead,
					len(body),
					test.maximumBytes,
				)
			}
			if response.Code < http.StatusBadRequest {
				t.Fatalf("oversized request status = %d", response.Code)
			}
		})
	}
}

func TestHumanAuthorizationMalformedFormCannotBeRecoveredByMiddleware(t *testing.T) {
	t.Run("PAR", func(t *testing.T) {
		ctx, _, values := newStrictPARContext(
			t,
			goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		)
		storeCalls := 0
		ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
			storePAR: func(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
				storeCalls++
				return goidc.HumanPARDecision{}, nil
			},
		}
		middlewareCalls := 0
		var middlewareParseErr error
		middleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				middlewareCalls++
				middlewareParseErr = request.ParseForm()
				next.ServeHTTP(response, request)
			})
		}
		router := http.NewServeMux()
		RegisterHandlers(router, ctx.Configuration, middleware)
		request := httptest.NewRequest(
			http.MethodPost,
			ctx.Issuer()+ctx.PAREndpoint,
			strings.NewReader(values.Encode()+"&dropped=%ZZ"),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if middlewareCalls != 1 || middlewareParseErr != nil {
			t.Fatalf("middleware calls/error = %d/%v, want 1/nil", middlewareCalls, middlewareParseErr)
		}
		if response.Code != http.StatusBadRequest || storeCalls != 0 {
			t.Fatalf(
				"malformed PAR = status %d authority calls %d body %q",
				response.Code,
				storeCalls,
				response.Body.String(),
			)
		}
		if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
			t.Fatalf("malformed PAR persisted %d sessions", len(sessions))
		}
	})

	t.Run("POST authorize", func(t *testing.T) {
		ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
		startCalls := 0
		ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
			start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
				startCalls++
				return goidc.HumanStartDecision{}, nil
			},
		}
		middlewareCalls := 0
		var middlewareParseErr error
		middleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				middlewareCalls++
				middlewareParseErr = request.ParseForm()
				next.ServeHTTP(response, request)
			})
		}
		router := http.NewServeMux()
		RegisterHandlers(router, ctx.Configuration, middleware)
		body := outerAuthorizationValues(client.ID, requestURI).Encode() + "&dropped=%ZZ"
		request := httptest.NewRequest(
			http.MethodPost,
			ctx.Issuer()+ctx.AuthorizationEndpoint,
			strings.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if middlewareCalls != 1 || middlewareParseErr != nil {
			t.Fatalf("middleware calls/error = %d/%v, want 1/nil", middlewareCalls, middlewareParseErr)
		}
		if response.Code != http.StatusBadRequest || startCalls != 0 {
			t.Fatalf(
				"malformed authorize = status %d authority calls %d body %q",
				response.Code,
				startCalls,
				response.Body.String(),
			)
		}
	})
}

type authorizationCountingBody struct {
	reader    *strings.Reader
	bytesRead int
}

func newAuthorizationCountingBody(value string) *authorizationCountingBody {
	return &authorizationCountingBody{reader: strings.NewReader(value)}
}

func (body *authorizationCountingBody) Read(buffer []byte) (int, error) {
	read, err := body.reader.Read(buffer)
	body.bytesRead += read
	return read, err
}

func (*authorizationCountingBody) Close() error {
	return nil
}

func assertCappedAuthorizationBody(
	t *testing.T,
	body *authorizationCountingBody,
	total int,
) {
	t.Helper()
	if body.bytesRead == 0 || body.bytesRead > int(humanAuthorizationMaxFormBytes)+1 ||
		body.bytesRead >= total {
		t.Fatalf(
			"authorization body read %d of %d bytes with %d-byte cap",
			body.bytesRead,
			total,
			humanAuthorizationMaxFormBytes,
		)
	}
}
