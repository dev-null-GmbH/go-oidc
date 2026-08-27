package authorize

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/google/go-cmp/cmp"
)

type strictMetadataThatMustNotMarshal struct {
	LargeInteger int64
}

type strictNestedHiddenMutable struct {
	hidden [1]struct {
		pointer *int
	}
}

type strictMutableCurve struct {
	elliptic.Curve
	pointer *int
}

type strictOversizedCloneAllocation [maxHumanConfidentialBFFCloneBytes + 1]byte

type strictOversizedHiddenZeroArray struct {
	hidden [maxHumanConfidentialBFFCloneElements + 1]struct{}
}

func (strictMetadataThatMustNotMarshal) MarshalJSON() ([]byte, error) {
	panic("strict client isolation must not invoke client metadata JSON methods")
}

func TestHumanConfidentialBFFOuterAuthorizationAdmissionIsExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		raw     func(*goidc.Client, string) string
		wantErr goidc.ErrorCode
	}{
		{
			name:   "exact GET",
			method: http.MethodGet,
			raw: func(client *goidc.Client, requestURI string) string {
				return outerAuthorizationValues(client.ID, requestURI).Encode()
			},
		},
		{
			name:   "exact POST form",
			method: http.MethodPost,
			raw: func(client *goidc.Client, requestURI string) string {
				return outerAuthorizationValues(client.ID, requestURI).Encode()
			},
		},
		{
			name:   "GET unknown parameter",
			method: http.MethodGet,
			raw: func(client *goidc.Client, requestURI string) string {
				values := outerAuthorizationValues(client.ID, requestURI)
				values.Set("redirect_uri", client.RedirectURIs[0])
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "GET percent-encoded unknown parameter name",
			method: http.MethodGet,
			raw: func(client *goidc.Client, requestURI string) string {
				return outerAuthorizationValues(client.ID, requestURI).Encode() + "&%75nknown=value"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "GET duplicate request_uri",
			method: http.MethodGet,
			raw: func(client *goidc.Client, requestURI string) string {
				return "client_id=" + url.QueryEscape(client.ID) +
					"&request_uri=" + url.QueryEscape(requestURI) +
					"&request_uri=" + url.QueryEscape(requestURI)
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "GET percent-encoded duplicate client_id name",
			method: http.MethodGet,
			raw: func(client *goidc.Client, requestURI string) string {
				return "client_id=" + url.QueryEscape(client.ID) +
					"&%63lient_id=" + url.QueryEscape(client.ID) +
					"&request_uri=" + url.QueryEscape(requestURI)
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "POST percent-encoded duplicate request_uri name",
			method: http.MethodPost,
			raw: func(client *goidc.Client, requestURI string) string {
				return "client_id=" + url.QueryEscape(client.ID) +
					"&request_uri=" + url.QueryEscape(requestURI) +
					"&request_%75ri=" + url.QueryEscape(requestURI)
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "POST percent-encoded unknown parameter name",
			method: http.MethodPost,
			raw: func(client *goidc.Client, requestURI string) string {
				return outerAuthorizationValues(client.ID, requestURI).Encode() + "&unk%6eown=value"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name:   "POST malformed form encoding",
			method: http.MethodPost,
			raw: func(client *goidc.Client, requestURI string) string {
				return outerAuthorizationValues(client.ID, requestURI).Encode() + "&unknown=%ZZ"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
			raw := test.raw(client, requestURI)
			var httpRequest *http.Request
			if test.method == http.MethodPost {
				httpRequest = httptest.NewRequest(test.method, "https://example.com/authorize", strings.NewReader(raw))
				httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				httpRequest = httptest.NewRequest(test.method, "https://example.com/authorize?"+raw, nil)
			}
			ctx.Request = httpRequest

			var req request
			if test.method == http.MethodPost {
				req = newFormRequest(httpRequest)
			} else {
				req = newRequest(httpRequest)
			}
			err := initAuth(ctx, req)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("initAuth() error = %v", err)
				}
				return
			}
			assertAuthorizationErrorCode(t, err, test.wantErr)
		})
	}
}

func TestHumanConfidentialBFFAuthorizationRejectsDirectAndJARFallback(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		extra string
	}{
		{name: "direct authorization"},
		{name: "request object", extra: "&request=not-a-jwt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, _ := newStrictOuterAuthorizationContext(t)
			raw := "client_id=" + url.QueryEscape(client.ID) +
				"&redirect_uri=" + url.QueryEscape(client.RedirectURIs[0]) +
				"&response_type=code&scope=openid" + test.extra
			httpRequest := httptest.NewRequest(http.MethodGet, "https://example.com/authorize?"+raw, nil)
			ctx.Request = httpRequest

			assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeInvalidRequest)
		})
	}
}

func TestDuplicateLegacyClientIDCannotRedeemHumanPARHandle(t *testing.T) {
	t.Parallel()

	ctx, humanClient, requestURI := newStrictOuterAuthorizationContext(t)
	legacyClient, _ := oidctest.NewClient(t)
	legacyClient.ID = "legacy-machine-client"
	ctx.StaticClients = append(ctx.StaticClients, legacyClient)
	raw := "client_id=" + url.QueryEscape(legacyClient.ID) +
		"&client_id=" + url.QueryEscape(humanClient.ID) +
		"&request_uri=" + url.QueryEscape(requestURI)
	httpRequest := httptest.NewRequest(http.MethodGet, "https://example.com/authorize?"+raw, nil)
	ctx.Request = httpRequest

	assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeServerError)
	session, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(requestURI, parRequestURIPrefix))
	if err != nil {
		t.Fatalf("PARSessionByPushedAuthReqID() error = %v", err)
	}
	if session.Status != goidc.StatusPending {
		t.Fatalf("human PAR session status = %q, want %q", session.Status, goidc.StatusPending)
	}
}

func TestHumanConfidentialBFFSimplePARAdmissionIsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(url.Values) string
		wantErr goidc.ErrorCode
	}{
		{
			name: "exact form",
			mutate: func(values url.Values) string {
				return values.Encode()
			},
		},
		{
			name: "request object",
			mutate: func(values url.Values) string {
				values.Set("request", "not-a-jwt")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unknown parameter",
			mutate: func(values url.Values) string {
				values.Set("unknown", "value")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported display parameter",
			mutate: func(values url.Values) string {
				values.Set("display", "page")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported claims parameter",
			mutate: func(values url.Values) string {
				values.Set("claims", `{}`)
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported authorization_details parameter",
			mutate: func(values url.Values) string {
				values.Set("authorization_details", `[]`)
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported login_hint parameter",
			mutate: func(values url.Values) string {
				values.Set("login_hint", "person@example.invalid")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported id_token_hint parameter",
			mutate: func(values url.Values) string {
				values.Set("id_token_hint", "opaque")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "unsupported dpop_jkt parameter",
			mutate: func(values url.Values) string {
				values.Set("dpop_jkt", "opaque")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "request_uri is not a simple PAR parameter",
			mutate: func(values url.Values) string {
				values.Set("request_uri", parRequestURIPrefix+"nested")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing redirect URI cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("redirect_uri")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing response type cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("response_type")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing PKCE challenge cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("code_challenge")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "all-zero PKCE challenge",
			mutate: func(values url.Values) string {
				values.Set("code_challenge", strings.Repeat("A", 43))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "noncanonical PKCE challenge",
			mutate: func(values url.Values) string {
				values.Set("code_challenge", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing response mode cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("response_mode")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing openid scope cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("scope")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing state cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("state")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "state shorter than sixteen octets",
			mutate: func(values url.Values) string {
				values.Set("state", strings.Repeat("s", 15))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "state longer than five hundred twelve octets",
			mutate: func(values url.Values) string {
				values.Set("state", strings.Repeat("s", 513))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "state contains space",
			mutate: func(values url.Values) string {
				values.Set("state", "opaque state value")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing nonce cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("nonce")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "nonce shorter than sixteen octets",
			mutate: func(values url.Values) string {
				values.Set("nonce", strings.Repeat("n", 15))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "nonce longer than five hundred twelve octets",
			mutate: func(values url.Values) string {
				values.Set("nonce", strings.Repeat("n", 513))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "nonce contains non ASCII",
			mutate: func(values url.Values) string {
				values.Set("nonce", "opaque-nonce-äbc")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "scope set is not sorted",
			mutate: func(values url.Values) string {
				values.Set("scope", "profile openid")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "scope set contains a duplicate",
			mutate: func(values url.Values) string {
				values.Set("scope", "openid openid")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "scope set has noncanonical spacing",
			mutate: func(values url.Values) string {
				values.Set("scope", "openid  profile")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "scope set exceeds thirty two values",
			mutate: func(values url.Values) string {
				scopes := make([]string, 33)
				for index := range scopes {
					scopes[index] = "scope" + strconv.Itoa(index+10)
				}
				values.Set("scope", strings.Join(scopes, " "))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "resource set is not sorted",
			mutate: func(values url.Values) string {
				values["resource"] = []string{
					"https://api.example.invalid/billing",
					"https://api.example.invalid/accounting",
				}
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing resource",
			mutate: func(values url.Values) string {
				values.Del("resource")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "resource contains a query",
			mutate: func(values url.Values) string {
				values["resource"] = []string{"https://api.example.invalid/accounting?tenant=test"}
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "resource exceeds five hundred twelve octets",
			mutate: func(values url.Values) string {
				values["resource"] = []string{"https://api.example.invalid/" + strings.Repeat("a", 490)}
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "multiple assurance values",
			mutate: func(values url.Values) string {
				values.Set("acr_values", "loa:1 loa:2")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "assurance value has invalid syntax",
			mutate: func(values url.Values) string {
				values.Set("acr_values", "loa~1")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "missing PKCE method cannot be completed at the outer endpoint",
			mutate: func(values url.Values) string {
				values.Del("code_challenge_method")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "malformed max age",
			mutate: func(values url.Values) string {
				values.Set("max_age", "not-an-integer")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "negative max age",
			mutate: func(values url.Values) string {
				values.Set("max_age", "-1")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "noncanonical max age",
			mutate: func(values url.Values) string {
				values.Set("max_age", "0300")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "max age exceeds human profile bound",
			mutate: func(values url.Values) string {
				values.Set("max_age", "86401")
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "percent-encoded unknown parameter name",
			mutate: func(values url.Values) string {
				return values.Encode() + "&unk%6eown=value"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "malformed form encoding",
			mutate: func(values url.Values) string {
				return values.Encode() + "&unknown=%ZZ"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "duplicate scope",
			mutate: func(values url.Values) string {
				values.Add("scope", values.Get("scope"))
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "duplicate resource value",
			mutate: func(values url.Values) string {
				resource := values.Get("resource")
				values["resource"] = []string{resource, resource}
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "more than eight resource values",
			mutate: func(values url.Values) string {
				values["resource"] = []string{
					"https://api.example.invalid/01",
					"https://api.example.invalid/02",
					"https://api.example.invalid/03",
					"https://api.example.invalid/04",
					"https://api.example.invalid/05",
					"https://api.example.invalid/06",
					"https://api.example.invalid/07",
					"https://api.example.invalid/08",
					"https://api.example.invalid/09",
				}
				return values.Encode()
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "percent-encoded duplicate client_id name",
			mutate: func(values url.Values) string {
				return values.Encode() + "&%63lient_id=" + url.QueryEscape(values.Get("client_id"))
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "percent-encoded duplicate assertion type name",
			mutate: func(values url.Values) string {
				return values.Encode() + "&client_assertion_%74ype=" +
					url.QueryEscape(values.Get("client_assertion_type"))
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
			raw := test.mutate(values)
			httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(raw))
			httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ctx.Request = httpRequest

			response, err := pushAuth(ctx, newFormRequest(httpRequest))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("pushAuth() error = %v", err)
				}
				if response.RequestURI != strictHumanTestRequestURI {
					t.Fatalf("request_uri = %q", response.RequestURI)
				}
				if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
					t.Fatalf("atomic strict PAR persisted %d legacy sessions", len(sessions))
				}
				return
			}
			assertAuthorizationErrorCode(t, err, test.wantErr)
			if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
				t.Fatalf("strictly rejected PAR persisted %d sessions", len(sessions))
			}
		})
	}
}

func TestHumanConfidentialBFFRejectsMixedAndMultipartTransports(t *testing.T) {
	t.Parallel()

	t.Run("outer POST query plus form", func(t *testing.T) {
		t.Parallel()
		ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
		httpRequest := httptest.NewRequest(
			http.MethodPost,
			"https://example.com/authorize?state=smuggled",
			strings.NewReader(outerAuthorizationValues(client.ID, requestURI).Encode()),
		)
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = httpRequest
		assertAuthorizationErrorCode(t, initAuth(ctx, newFormRequest(httpRequest)), goidc.ErrorCodeInvalidRequest)
	})

	t.Run("outer GET query plus body", func(t *testing.T) {
		t.Parallel()
		ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
		httpRequest := httptest.NewRequest(
			http.MethodGet,
			"https://example.com/authorize?"+outerAuthorizationValues(client.ID, requestURI).Encode(),
			strings.NewReader("state=smuggled"),
		)
		ctx.Request = httpRequest
		assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeInvalidRequest)
	})

	t.Run("PAR query plus form", func(t *testing.T) {
		t.Parallel()
		ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
		httpRequest := httptest.NewRequest(
			http.MethodPost,
			"https://example.com/par?state=smuggled",
			strings.NewReader(values.Encode()),
		)
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = httpRequest
		_, err := pushAuth(ctx, newFormRequest(httpRequest))
		assertAuthorizationErrorCode(t, err, goidc.ErrorCodeInvalidRequest)
	})

	for _, mediaType := range []struct {
		name  string
		value string
	}{
		{name: "PAR missing content type"},
		{name: "PAR wrong content type", value: "text/plain"},
	} {
		t.Run(mediaType.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
			httpRequest := httptest.NewRequest(
				http.MethodPost,
				"https://example.com/par",
				strings.NewReader(values.Encode()),
			)
			httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			parsed := newFormRequest(httpRequest)
			if mediaType.value == "" {
				httpRequest.Header.Del("Content-Type")
			} else {
				httpRequest.Header.Set("Content-Type", mediaType.value)
			}
			ctx.Request = httpRequest
			_, err := pushAuth(ctx, parsed)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeInvalidRequest)
		})
	}

	t.Run("PAR multipart form", func(t *testing.T) {
		t.Parallel()
		ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for name, members := range values {
			for _, member := range members {
				if err := writer.WriteField(name, member); err != nil {
					t.Fatalf("WriteField() error = %v", err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("multipart Close() error = %v", err)
		}
		httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", &body)
		httpRequest.Header.Set("Content-Type", writer.FormDataContentType())
		ctx.Request = httpRequest
		handlerPAR(ctx)
		response := ctx.Response.(*httptest.ResponseRecorder)
		if response.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("multipart PAR status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
		}
		if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
			t.Fatalf("multipart PAR persisted %d sessions", len(sessions))
		}
	})
}

func TestUnknownAuthorizationRequestProfileFailsClosed(t *testing.T) {
	t.Parallel()

	ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfile("future-profile"))
	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest

	_, err := pushAuth(ctx, newFormRequest(httpRequest))
	assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("unknown admission profile persisted %d sessions", len(sessions))
	}
}

func TestUnknownAuthorizationRequestProfileFailsClosedAtAuthorize(t *testing.T) {
	t.Parallel()

	ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
	client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfile("future-profile")
	httpRequest := httptest.NewRequest(
		http.MethodGet,
		"https://example.com/authorize?"+outerAuthorizationValues(client.ID, requestURI).Encode(),
		nil,
	)
	ctx.Request = httpRequest

	assertAuthorizationErrorCode(t, initAuth(ctx, newRequest(httpRequest)), goidc.ErrorCodeServerError)
	session, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(requestURI, parRequestURIPrefix))
	if err != nil {
		t.Fatalf("PARSessionByPushedAuthReqID() error = %v", err)
	}
	if session.Status != goidc.StatusPending {
		t.Fatalf("unknown-profile authorize mutated PAR session status to %q", session.Status)
	}
}

func TestLegacyPARParsingRemainsUnchanged(t *testing.T) {
	t.Parallel()

	baselineCtx, _, baselineValues := newStrictPARContext(t, goidc.AuthorizationRequestProfileDefault)
	baselineRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(baselineValues.Encode()))
	baselineRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	baselineCtx.Request = baselineRequest
	baselineResponse, err := pushAuth(baselineCtx, newFormRequest(baselineRequest))
	if err != nil {
		t.Fatalf("baseline pushAuth() error = %v", err)
	}

	legacyCtx, _, legacyValues := newStrictPARContext(t, goidc.AuthorizationRequestProfileDefault)
	legacyValues.Add("scope", legacyValues.Get("scope"))
	legacyRaw := legacyValues.Encode() + "&legacy_%75nknown=value"
	legacyRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(legacyRaw))
	legacyRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	legacyCtx.Request = legacyRequest
	legacyResponse, err := pushAuth(legacyCtx, newFormRequest(legacyRequest))
	if err != nil {
		t.Fatalf("legacy pushAuth() error = %v", err)
	}
	if diff := cmp.Diff(baselineResponse, legacyResponse); diff != "" {
		t.Fatalf("legacy parser response changed (-baseline +duplicate/unknown):\n%s", diff)
	}
}

func TestPARHandlerCannotMutateRetainedHumanAdmissionProfile(t *testing.T) {
	t.Parallel()

	ctx, client, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	ctx.PARHandleSessionFunc = func(_ context.Context, _ *goidc.AuthnSession, callbackClient *goidc.Client) error {
		callbackClient.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
		callbackClient.RedirectURIs[0] = "https://attacker.example.invalid/callback"
		callbackClient.GrantTypes[0] = goidc.GrantImplicit
		callbackClient.PrivateKeyJWTAuthority.SnapshotRevision++
		callbackClient.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = "attacker-authority"
		callbackClient.PrivateKeyJWTAuthority.Keys[0].Key.KeyID = "attacker-key"
		publicKey, ok := callbackClient.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("strict callback key type = %T, want *rsa.PublicKey", callbackClient.PrivateKeyJWTAuthority.Keys[0].Key.Key)
		}
		publicKey.E = 3
		return nil
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest
	if _, err := pushAuth(ctx, newFormRequest(httpRequest)); err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		client.RedirectURIs[0] != "https://human-bff.example.invalid/callback" ||
		client.GrantTypes[0] != goidc.GrantAuthorizationCode ||
		client.PrivateKeyJWTAuthority.SnapshotRevision != 17 ||
		client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID != "strict-human-authority-key" ||
		client.PrivateKeyJWTAuthority.Keys[0].Key.KeyID != "strict-human-key" ||
		client.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey).E != 65537 {
		t.Fatalf("PAR callback mutated retained strict client authority: %#v", client)
	}
}

func TestHumanConfidentialBFFClientIsolationPreservesMetadataWithoutJSON(t *testing.T) {
	t.Parallel()

	largeInteger := int64(1<<60 + 1)
	authorityPrivateJWK := oidctest.PrivatePS256JWK(t, "metadata-authority", goidc.KeyUsageSignature)
	authorityJWK := authorityPrivateJWK.Public()
	authorityPublicKey := authorityJWK.Key.(*rsa.PublicKey)
	contacts := []string{
		"https://human-bff.example.invalid/callback",
		"https://attacker.example.invalid/callback",
	}
	redirects := []string{"https://human-bff.example.invalid/callback"}
	sharedMetadataSlice := []string{"retained"}
	nested := map[string]any{
		"values": []string{"retained"},
	}
	emptyJWKS := &goidc.JSONWebKeySet{}
	client := &goidc.Client{
		ID:                          "human-confidential-bff",
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 1,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{{
				Key:            authorityJWK,
				KeyAuthorityID: "metadata-authority-id",
			}},
		},
		ClientMeta: goidc.ClientMeta{
			ApplicationType:   goidc.ApplicationTypeWeb,
			Contacts:          contacts,
			RedirectURIs:      redirects,
			JWKS:              emptyJWKS,
			ScopeIDs:          goidc.ScopeOpenID.ID,
			SubIdentifierType: goidc.SubIdentifierPairwise,
			IDTokenSigAlg:     goidc.SigAlgPS256,
			TokenAuthnMethod:  goidc.AuthnMethodPrivateKeyJWT,
			TokenAuthnSigAlg:  goidc.SigAlgPS256,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			CustomAttributes: map[string]any{
				"large_integer": largeInteger,
				"custom":        strictMetadataThatMustNotMarshal{LargeInteger: largeInteger},
				"nested":        nested,
				"keyed":         map[*rsa.PublicKey]string{authorityPublicKey: "authority"},
				"alias_one":     sharedMetadataSlice,
				"alias_two":     sharedMetadataSlice,
			},
		},
	}
	client.CacheJWKS(emptyJWKS)

	clone, err := cloneHumanConfidentialBFFClient(client)
	if err != nil {
		t.Fatalf("cloneHumanConfidentialBFFClient() error = %v", err)
	}
	if got, ok := clone.CustomAttributes["large_integer"].(int64); !ok || got != largeInteger {
		t.Fatalf("cloned large integer = %#v, want int64(%d)", clone.CustomAttributes["large_integer"], largeInteger)
	}
	if got, ok := clone.CustomAttributes["custom"].(strictMetadataThatMustNotMarshal); !ok || got.LargeInteger != largeInteger {
		t.Fatalf("cloned custom metadata = %#v", clone.CustomAttributes["custom"])
	}
	if clone.JWKS == nil || len(clone.JWKS.Keys) != 0 || clone.JWKS == client.JWKS {
		t.Fatalf("cloned empty JWKS = %#v, source = %#v", clone.JWKS, client.JWKS)
	}
	if clone.CachedJWKS() == nil || len(clone.CachedJWKS().Keys) != 0 || clone.CachedJWKS() == client.CachedJWKS() {
		t.Fatalf("cloned empty cached JWKS = %#v, source = %#v", clone.CachedJWKS(), client.CachedJWKS())
	}
	if clone.JWKS != clone.CachedJWKS() {
		t.Fatalf("aliased direct/cached JWKS split during clone: direct=%p cached=%p", clone.JWKS, clone.CachedJWKS())
	}
	if len(clone.Contacts) != 2 || len(clone.RedirectURIs) != 1 ||
		clone.RedirectURIs[0] != "https://human-bff.example.invalid/callback" {
		t.Fatalf("overlapping client slices changed shape: contacts=%#v redirects=%#v", clone.Contacts, clone.RedirectURIs)
	}
	cloneAuthorityKey := clone.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey)
	for metadataKey := range clone.CustomAttributes["keyed"].(map[*rsa.PublicKey]string) {
		if metadataKey == authorityPublicKey || metadataKey != cloneAuthorityKey {
			t.Fatalf("cloned metadata key authority alias = %p, source=%p clone authority=%p", metadataKey, authorityPublicKey, cloneAuthorityKey)
		}
		metadataKey.E = 3
	}
	if authorityPublicKey.E != 65537 {
		t.Fatalf("cloned metadata map key mutated retained authority exponent to %d", authorityPublicKey.E)
	}

	clone.CustomAttributes["large_integer"] = int64(0)
	cloneNested := clone.CustomAttributes["nested"].(map[string]any)
	cloneNested["values"].([]string)[0] = "mutated"
	cloneAliasOne := clone.CustomAttributes["alias_one"].([]string)
	cloneAliasTwo := clone.CustomAttributes["alias_two"].([]string)
	cloneAliasOne[0] = "alias-mutated"
	if cloneAliasTwo[0] != "alias-mutated" {
		t.Fatalf("exact shared slice identity was split: first=%#v second=%#v", cloneAliasOne, cloneAliasTwo)
	}
	if client.CustomAttributes["large_integer"] != largeInteger || nested["values"].([]string)[0] != "retained" {
		t.Fatalf("clone mutation reached retained custom metadata: %#v", client.CustomAttributes)
	}
	if sharedMetadataSlice[0] != "retained" {
		t.Fatalf("cloned shared slice mutation reached retained metadata: %#v", sharedMetadataSlice)
	}

	nilJWKSClient := *client
	nilJWKSClient.JWKS = nil
	nilJWKSClient.CacheJWKS(nil)
	nilJWKSClone, err := cloneHumanConfidentialBFFClient(&nilJWKSClient)
	if err != nil {
		t.Fatalf("nil-JWKS cloneHumanConfidentialBFFClient() = (%#v, %v)", nilJWKSClone, err)
	}
	if nilJWKSClone.JWKS != nil || nilJWKSClone.CachedJWKS() != nil {
		t.Fatalf("nil JWKS changed during clone: direct=%#v cached=%#v", nilJWKSClone.JWKS, nilJWKSClone.CachedJWKS())
	}

	nonAliasedClient := *client
	nonAliasedClient.JWKS = &goidc.JSONWebKeySet{}
	nonAliasedClient.CacheJWKS(&goidc.JSONWebKeySet{})
	nonAliasedClone, err := cloneHumanConfidentialBFFClient(&nonAliasedClient)
	if err != nil {
		t.Fatalf("non-aliased JWKS cloneHumanConfidentialBFFClient() = (%#v, %v)", nonAliasedClone, err)
	}
	if nonAliasedClone.JWKS == nil || nonAliasedClone.CachedJWKS() == nil ||
		nonAliasedClone.JWKS == nonAliasedClone.CachedJWKS() {
		t.Fatalf("non-aliased direct/cached JWKS changed identity: direct=%p cached=%p", nonAliasedClone.JWKS, nonAliasedClone.CachedJWKS())
	}
}

func TestHumanConfidentialBFFClientIsolationRejectsUnsupportedMetadataReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
	}{
		{name: "function", value: func() {}},
		{name: "nested hidden pointer", value: func() any {
			value := 1
			metadata := strictNestedHiddenMutable{}
			metadata.hidden[0].pointer = &value
			return metadata
		}()},
		{name: "custom elliptic curve", value: func() any {
			value := 1
			return &strictMutableCurve{Curve: elliptic.P256(), pointer: &value}
		}()},
		{name: "overlapping slice views", value: func() any {
			backing := []string{"first", "second", "third"}
			return map[string]any{
				"prefix": backing[:2],
				"suffix": backing[1:],
			}
		}()},
		{name: "slice and element pointer aliases", value: func() any {
			backing := []int{1}
			return map[string]any{
				"slice":   backing,
				"element": &backing[0],
			}
		}()},
		{name: "struct and field pointer aliases", value: func() any {
			type aliased struct {
				Value int
			}
			owner := &aliased{Value: 1}
			return map[string]any{
				"owner": owner,
				"field": &owner.Value,
			}
		}()},
		{name: "excessive container", value: make([]int, 1, maxHumanConfidentialBFFCloneElements+1)},
		{name: "excessive depth", value: func() any {
			var nested any = "leaf"
			for range maxHumanConfidentialBFFCloneDepth + 1 {
				nested = map[string]any{"next": nested}
			}
			return nested
		}()},
		{name: "excessive allocation", value: &strictOversizedCloneAllocation{}},
		{name: "zero-size oversized hidden array", value: strictOversizedHiddenZeroArray{
			hidden: [maxHumanConfidentialBFFCloneElements + 1]struct{}{},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, client, _ := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
			client.CustomAttributes = map[string]any{"unsupported": test.value}

			clone, err := cloneHumanConfidentialBFFClient(client)
			if clone != nil || err == nil {
				t.Fatalf("cloneHumanConfidentialBFFClient() = (%#v, %v), want nil, error", clone, err)
			}
		})
	}
}

func TestHumanConfidentialBFFAuthenticationOutputsCannotExpandAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*goidc.AuthnSession)
	}{
		{
			name: "unrequested scope",
			mutate: func(session *goidc.AuthnSession) {
				session.GrantedScopes = "admin openid"
			},
		},
		{
			name: "missing openid scope",
			mutate: func(session *goidc.AuthnSession) {
				session.GrantedScopes = ""
			},
		},
		{
			name: "missing authenticated subject",
			mutate: func(session *goidc.AuthnSession) {
				session.Subject = ""
			},
		},
		{
			name: "oversized authenticated subject",
			mutate: func(session *goidc.AuthnSession) {
				session.Subject = strings.Repeat("s", 129)
			},
		},
		{
			name: "noncanonical authenticated subject",
			mutate: func(session *goidc.AuthnSession) {
				session.Subject = "human subject"
			},
		},
		{
			name: "forbidden username",
			mutate: func(session *goidc.AuthnSession) {
				session.Username = "human-user"
			},
		},
		{
			name: "unrequested resource",
			mutate: func(session *goidc.AuthnSession) {
				session.GrantedResources = goidc.Resources{"https://attacker.example.invalid/resource"}
			},
		},
		{
			name: "forbidden authorization details",
			mutate: func(session *goidc.AuthnSession) {
				session.GrantedAuthDetails = []goidc.AuthDetail{{"type": "attacker_authority"}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, _ := newStrictOuterAuthorizationContext(t)
			policy := goidc.NewPolicy(
				"strict-output-policy",
				func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
				func(
					_ http.ResponseWriter,
					_ *http.Request,
					session *goidc.AuthnSession,
					_ *goidc.Client,
				) (goidc.Status, error) {
					session.Subject = "human-subject"
					session.GrantedScopes = goidc.ScopeOpenID.ID
					test.mutate(session)
					return goidc.StatusSuccess, nil
				},
			)
			ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
			session := oidctest.AuthnSessions(t, ctx)[0]
			session.PolicyID = policy.ID
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			err := continueAuth(ctx, session.ID)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("unauthorized callback outputs issued %d grants", len(grants))
			}
		})
	}
}

func TestHumanConfidentialBFFNonSuccessCannotRetainGrantOutputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status goidc.Status
		mutate func(*goidc.AuthnSession)
	}{
		{name: "pending subject", status: goidc.StatusPending, mutate: func(session *goidc.AuthnSession) {
			session.Subject = "stale-subject"
		}},
		{name: "pending username", status: goidc.StatusPending, mutate: func(session *goidc.AuthnSession) {
			session.Username = "stale-username"
		}},
		{name: "pending scopes", status: goidc.StatusPending, mutate: func(session *goidc.AuthnSession) {
			session.GrantedScopes = goidc.ScopeOpenID.ID
		}},
		{name: "pending resources", status: goidc.StatusPending, mutate: func(session *goidc.AuthnSession) {
			session.GrantedResources = goidc.Resources{"https://api.example.invalid/accounting"}
		}},
		{name: "failure subject", status: goidc.StatusFailure, mutate: func(session *goidc.AuthnSession) {
			session.Subject = "stale-subject"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, _ := newStrictOuterAuthorizationContext(t)
			policy := goidc.NewPolicy(
				"strict-non-success-policy",
				func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
				func(
					_ http.ResponseWriter,
					_ *http.Request,
					session *goidc.AuthnSession,
					_ *goidc.Client,
				) (goidc.Status, error) {
					test.mutate(session)
					session.Store["interaction"] = "allowed"
					return test.status, nil
				},
			)
			ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
			session := oidctest.AuthnSessions(t, ctx)[0]
			session.PolicyID = policy.ID
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			err := continueAuth(ctx, session.ID)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("non-success callback outputs issued %d grants", len(grants))
			}
		})
	}
}

func TestHumanConfidentialBFFCallbackErrorOverridesSuccess(t *testing.T) {
	t.Parallel()

	ctx, _, _ := newStrictOuterAuthorizationContext(t)
	policyErr := errors.New("authentication evidence unavailable")
	policy := goidc.NewPolicy(
		"strict-error-policy",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
		func(
			_ http.ResponseWriter,
			_ *http.Request,
			session *goidc.AuthnSession,
			_ *goidc.Client,
		) (goidc.Status, error) {
			session.Subject = "human-subject"
			session.GrantedScopes = goidc.ScopeOpenID.ID
			return goidc.StatusSuccess, policyErr
		},
	)
	ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
	session := oidctest.AuthnSessions(t, ctx)[0]
	session.PolicyID = policy.ID
	if err := ctx.AuthSaveSession(session); err != nil {
		t.Fatalf("AuthSaveSession() error = %v", err)
	}

	if err := continueAuth(ctx, session.ID); err != nil {
		t.Fatalf("continueAuth() redirect error = %v", err)
	}
	redirect, err := url.Parse(ctx.Response.(*httptest.ResponseRecorder).Header().Get("Location"))
	if err != nil || redirect.Query().Get("error") != string(goidc.ErrorCodeAccessDenied) {
		t.Fatalf("callback failure redirect = %q, parse error = %v", redirect, err)
	}
	persisted, err := ctx.AuthSession(session.ID)
	if err != nil || persisted.Status != goidc.StatusFailure || persisted.Subject != "" ||
		persisted.GrantedScopes != "" || len(persisted.Store) != 0 {
		t.Fatalf("callback failure persisted state = %#v, error = %v", persisted, err)
	}
	if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
		t.Fatalf("callback success plus error issued %d grants", len(grants))
	}
}

func TestHumanConfidentialBFFRequestURIIgnoresLegacyContinuationState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*goidc.AuthnSession)
	}{
		{name: "selected policy", mutate: func(session *goidc.AuthnSession) {
			session.PolicyID = "selected-policy"
		}},
		{name: "subject", mutate: func(session *goidc.AuthnSession) {
			session.Subject = "injected-subject"
		}},
		{name: "username", mutate: func(session *goidc.AuthnSession) {
			session.Username = "injected-username"
		}},
		{name: "granted scopes", mutate: func(session *goidc.AuthnSession) {
			session.GrantedScopes = goidc.ScopeOpenID.ID
		}},
		{name: "granted resources", mutate: func(session *goidc.AuthnSession) {
			session.GrantedResources = goidc.Resources{"https://api.example.invalid/accounting"}
		}},
		{name: "store", mutate: func(session *goidc.AuthnSession) {
			session.Store["injected"] = "state"
		}},
		{name: "missing session ID", mutate: func(session *goidc.AuthnSession) {
			session.ID = ""
		}},
		{name: "reused persistence ID", mutate: func(session *goidc.AuthnSession) {
			session.PersistenceID = session.ID
		}},
		{name: "invalid creation time", mutate: func(session *goidc.AuthnSession) {
			session.CreatedAt = 0
		}},
		{name: "invalid expiry order", mutate: func(session *goidc.AuthnSession) {
			session.ExpiresAt = session.CreatedAt
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, requestURI := newStrictOuterAuthorizationContext(t)
			session := oidctest.AuthnSessions(t, ctx)[0]
			test.mutate(session)
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}
			httpRequest := httptest.NewRequest(
				http.MethodGet,
				"https://example.com/authorize?"+outerAuthorizationValues(session.ClientID, requestURI).Encode(),
				nil,
			)
			ctx.Request = httpRequest

			if err := initAuth(ctx, newRequest(httpRequest)); err != nil {
				t.Fatalf("initAuth() error = %v", err)
			}
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("legacy request_uri state issued %d grants", len(grants))
			}
			location := ctx.Response.(*httptest.ResponseRecorder).Header().Get("Location")
			if location != "https://id.d0.eu/oidc/interaction/identity#"+strictHumanTestEntry {
				t.Fatalf("strict authorization handoff location = %q", location)
			}
		})
	}
}

func TestHumanConfidentialBFFRestoredSessionRebindsCurrentAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*goidc.AuthnSession, *goidc.Client)
	}{
		{
			name: "redirect no longer registered",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.RedirectURI = "https://attacker.example.invalid/callback"
			},
		},
		{
			name: "scope no longer registered",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.Scopes = "email openid"
			},
		},
		{
			name: "client authority revision changed",
			mutate: func(_ *goidc.AuthnSession, client *goidc.Client) {
				client.PrivateKeyJWTAuthority.SnapshotRevision++
			},
		},
		{
			name: "client authority key changed",
			mutate: func(_ *goidc.AuthnSession, client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = "replacement-human-authority-key"
			},
		},
		{
			name: "forbidden restored request parameter",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.LoginHint = "attacker@example.invalid"
			},
		},
		{
			name: "empty restored authorization details",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.AuthDetails = []goidc.AuthDetail{}
			},
		},
		{
			name: "injected DPoP thumbprint",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.JWKThumbprint = "attacker-thumbprint"
			},
		},
		{
			name: "retained successful session",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.Status = goidc.StatusSuccess
			},
		},
		{
			name: "retained failed session",
			mutate: func(session *goidc.AuthnSession, _ *goidc.Client) {
				session.Status = goidc.StatusFailure
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, _ := newStrictOuterAuthorizationContext(t)
			session := oidctest.AuthnSessions(t, ctx)[0]
			test.mutate(session, client)
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			err := continueAuth(ctx, session.ID)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("stale restored authority issued %d grants", len(grants))
			}
		})
	}
}

func TestHumanConfidentialBFFRestoredSessionRebindsCurrentServerAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*oidc.Context, *goidc.AuthnSession)
	}{
		{
			name: "scope removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.Scopes = []goidc.Scope{goidc.NewScope("profile")}
			},
		},
		{
			name: "assurance context removed",
			mutate: func(ctx *oidc.Context, session *goidc.AuthnSession) {
				session.ACRValues = "urn:d0:assurance:passkey"
				ctx.ACRs = nil
			},
		},
		{
			name: "resource removed",
			mutate: func(ctx *oidc.Context, session *goidc.AuthnSession) {
				session.Resources = goidc.Resources{"https://api.example.invalid/accounting"}
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://api.example.invalid/billing"}
			},
		},
		{
			name: "PKCE disabled",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.PKCEEnabled = false
			},
		},
		{
			name: "S256 removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}
			},
		},
		{
			name: "authorization code grant removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
			},
		},
		{
			name: "code response removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeIDToken}
			},
		},
		{
			name: "query response mode removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.ResponseModes = []goidc.ResponseMode{goidc.ResponseModeFragment}
			},
		},
		{
			name: "pairwise subject type removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPublic}
			},
		},
		{
			name: "pairwise subject function removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.PairwiseSubjectFunc = nil
			},
		},
		{
			name: "PS256 ID token signing removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgRS256}
			},
		},
		{
			name: "private key JWT authentication removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.AuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodNone}
			},
		},
		{
			name: "PS256 private key JWT removed",
			mutate: func(ctx *oidc.Context, _ *goidc.AuthnSession) {
				ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgRS256}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, _, _ := newStrictOuterAuthorizationContext(t)
			session := oidctest.AuthnSessions(t, ctx)[0]
			test.mutate(&ctx, session)
			session.PolicyID = ctx.AuthPolicies[0].ID
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			err := continueAuth(ctx, session.ID)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("stale server authority issued %d grants", len(grants))
			}
		})
	}
}

func TestHumanConfidentialBFFContinuationIsolatesResolverClientAndCompletion(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	policy := goidc.NewPolicy(
		"strict-continuation-policy",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
		func(
			_ http.ResponseWriter,
			_ *http.Request,
			session *goidc.AuthnSession,
			callbackClient *goidc.Client,
		) (goidc.Status, error) {
			callbackClient.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			callbackClient.RedirectURIs[0] = "https://attacker.example.invalid/callback"
			callbackClient.GrantTypes[0] = goidc.GrantImplicit
			callbackClient.JARMSigAlg = goidc.SigAlgRS256
			callbackClient.PrivateKeyJWTAuthority.SnapshotRevision++
			callbackClient.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = "attacker-authority"
			callbackClient.PrivateKeyJWTAuthority.Keys[0].Key.KeyID = "attacker-key"
			callbackClient.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey).E = 3
			session.RedirectURI = "https://attacker.example.invalid/callback"
			session.State = "attacker-state-value"
			session.Nonce = "attacker-nonce-value"
			session.ResponseMode = goidc.ResponseModeFragment
			session.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			session.Subject = "human-subject"
			session.GrantedScopes = session.Scopes
			return goidc.StatusSuccess, nil
		},
	)
	ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
	session := oidctest.AuthnSessions(t, ctx)[0]
	session.PolicyID = policy.ID
	if err := ctx.AuthSaveSession(session); err != nil {
		t.Fatalf("AuthSaveSession() error = %v", err)
	}

	if err := continueAuth(ctx, session.ID); err != nil {
		t.Fatalf("continueAuth() error = %v", err)
	}
	if client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		client.RedirectURIs[0] != "https://human-bff.example.invalid/callback" ||
		client.GrantTypes[0] != goidc.GrantAuthorizationCode || client.JARMSigAlg != "" ||
		client.PrivateKeyJWTAuthority.SnapshotRevision != 17 ||
		client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID != "strict-human-authority-key" ||
		client.PrivateKeyJWTAuthority.Keys[0].Key.KeyID != "strict-human-key" ||
		client.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey).E != 65537 {
		t.Fatalf("continuation callback mutated retained strict client: %#v", client)
	}
	location := ctx.Response.(*httptest.ResponseRecorder).Header().Get("Location")
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse continuation redirect %q: %v", location, err)
	}
	if redirect.Scheme != "https" || redirect.Host != "human-bff.example.invalid" ||
		redirect.Query().Get("code") == "" || redirect.Query().Get("response") != "" {
		t.Fatalf("strict continuation used callback-mutated client during completion: %q", location)
	}
}

func TestUnknownAuthorizationRequestProfileFailsClosedAtContinuation(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	client.AuthorizationRequestProfile = goidc.AuthorizationRequestProfile("future-profile")
	session := oidctest.AuthnSessions(t, ctx)[0]
	session.PolicyID = ctx.AuthPolicies[0].ID
	if err := ctx.AuthSaveSession(session); err != nil {
		t.Fatalf("AuthSaveSession() error = %v", err)
	}

	err := continueAuth(ctx, session.ID)
	assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
	if client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfile("future-profile") {
		t.Fatalf("unknown continuation profile mutated to %q", client.AuthorizationRequestProfile)
	}
}

func TestHumanConfidentialBFFPendingContinuationPersistsOnlyPolicyOutputs(t *testing.T) {
	t.Parallel()

	ctx, client, _ := newStrictOuterAuthorizationContext(t)
	policy := goidc.NewPolicy(
		"strict-pending-policy",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
		func(
			_ http.ResponseWriter,
			_ *http.Request,
			callbackSession *goidc.AuthnSession,
			callbackClient *goidc.Client,
		) (goidc.Status, error) {
			callbackClient.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			callbackClient.RedirectURIs[0] = "https://attacker.example.invalid/callback"
			callbackSession.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			callbackSession.RedirectURI = "https://attacker.example.invalid/callback"
			callbackSession.ResponseMode = goidc.ResponseModeFragment
			callbackSession.State = "attacker-state-value"
			callbackSession.Nonce = "attacker-nonce-value"
			callbackSession.Resources[0] = "https://attacker.example.invalid/resource"
			callbackSession.Store["interaction"] = "allowed-output"
			return goidc.StatusPending, nil
		},
	)
	ctx.AuthPolicies = []goidc.AuthnPolicy{policy}
	ctx.ResourceIndicatorsEnabled = true
	ctx.ResourceIndicators = []goidc.ResourceIndicator{"https://api.example.invalid/accounting"}
	session := oidctest.AuthnSessions(t, ctx)[0]
	session.PolicyID = policy.ID
	session.Resources = goidc.Resources{"https://api.example.invalid/accounting"}
	if err := ctx.AuthSaveSession(session); err != nil {
		t.Fatalf("AuthSaveSession() error = %v", err)
	}

	if err := continueAuth(ctx, session.ID); err != nil {
		t.Fatalf("continueAuth() error = %v", err)
	}
	persisted, err := ctx.AuthSession(session.ID)
	if err != nil {
		t.Fatalf("AuthSession() error = %v", err)
	}
	if persisted.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		persisted.RedirectURI != "https://human-bff.example.invalid/callback" ||
		persisted.ResponseMode != goidc.ResponseModeQuery || persisted.State != "opaque-state-1234" ||
		persisted.Nonce != "opaque-nonce-1234" ||
		!cmp.Equal(persisted.Resources, goidc.Resources{"https://api.example.invalid/accounting"}) ||
		persisted.Store["interaction"] != "allowed-output" {
		t.Fatalf("pending strict continuation persisted callback authority mutation: %#v", persisted)
	}
	if client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		client.RedirectURIs[0] != "https://human-bff.example.invalid/callback" {
		t.Fatalf("pending continuation mutated retained strict client: %#v", client)
	}
}

func TestStrictPARNeverCallsLegacyHandlerWithValidatedAuthorizationParameters(t *testing.T) {
	t.Parallel()

	ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	called := false
	ctx.PARHandleSessionFunc = func(_ context.Context, session *goidc.AuthnSession, _ *goidc.Client) error {
		called = true
		session.State = "attacker-state"
		session.Nonce = ""
		session.ResponseMode = goidc.ResponseModeFragment
		session.Resources[0] = "https://attacker.example.invalid"
		*session.MaxAuthnAgeSecs = 0
		return nil
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest

	if _, err := pushAuth(ctx, newFormRequest(httpRequest)); err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if called {
		t.Fatal("strict PAR called the legacy PAR handler")
	}
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("strict PAR persisted %d legacy sessions", len(sessions))
	}
}

func TestStrictPARNeverSharesSessionAuthorityWithLegacyHandler(t *testing.T) {
	t.Parallel()

	ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	var retained *goidc.AuthnSession
	ctx.PARHandleSessionFunc = func(_ context.Context, session *goidc.AuthnSession, _ *goidc.Client) error {
		retained = session
		return nil
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest

	if _, err := pushAuth(ctx, newFormRequest(httpRequest)); err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if retained != nil {
		t.Fatal("strict PAR exposed session authority to the legacy PAR handler")
	}
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("strict PAR persisted %d legacy sessions", len(sessions))
	}
}

func TestStrictAuthorizationNeverSharesAuthorityWithLegacyPolicy(t *testing.T) {
	t.Parallel()

	ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
	policyCalled := false
	ctx.AuthPolicies = []goidc.AuthnPolicy{goidc.NewPolicy(
		"mutating-policy",
		func(_ *http.Request, callbackSession *goidc.AuthnSession, callbackClient *goidc.Client) bool {
			policyCalled = true
			callbackClient.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			callbackClient.RedirectURIs[0] = "https://attacker.example.invalid/callback"
			callbackClient.GrantTypes[0] = goidc.GrantImplicit
			callbackClient.JARMSigAlg = goidc.SigAlgPS256
			callbackSession.RedirectURI = "https://attacker.example.invalid/callback"
			callbackSession.State = "attacker-state-value"
			callbackSession.Nonce = "attacker-nonce-value"
			return true
		},
		func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, callbackClient *goidc.Client) (goidc.Status, error) {
			policyCalled = true
			callbackClient.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileDefault
			callbackClient.JARMSigAlg = goidc.SigAlgPS256
			as.RedirectURI = "https://attacker.example.invalid/callback"
			as.State = "attacker-state-value"
			as.Nonce = "attacker-nonce-value"
			as.Subject = "human-subject"
			as.GrantedScopes = as.Scopes
			return goidc.StatusSuccess, nil
		},
	)}
	httpRequest := httptest.NewRequest(
		http.MethodGet,
		"https://example.com/authorize?"+outerAuthorizationValues(client.ID, requestURI).Encode(),
		nil,
	)
	ctx.Request = httpRequest
	if err := initAuth(ctx, newRequest(httpRequest)); err != nil {
		t.Fatalf("initAuth() error = %v", err)
	}
	if client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		client.RedirectURIs[0] != "https://human-bff.example.invalid/callback" ||
		client.GrantTypes[0] != goidc.GrantAuthorizationCode || client.JARMSigAlg != "" {
		t.Fatalf("authorization policy mutated retained strict client configuration: %#v", client)
	}
	if policyCalled {
		t.Fatal("strict authorization called the legacy authentication policy")
	}
	location := ctx.Response.(*httptest.ResponseRecorder).Header().Get("Location")
	if location != "https://id.d0.eu/oidc/interaction/identity#"+strictHumanTestEntry {
		t.Fatalf("strict authorization handoff location = %q", location)
	}
}

func outerAuthorizationValues(clientID, requestURI string) url.Values {
	return url.Values{
		"client_id":   {clientID},
		"request_uri": {requestURI},
	}
}

func newStrictOuterAuthorizationContext(t *testing.T) (oidc.Context, *goidc.Client, string) {
	t.Helper()
	ctx, _ := setUpAuth(t)
	ctx.AuthPolicies = []goidc.AuthnPolicy{goidc.NewPolicy(
		"strict-human-policy",
		func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool { return true },
		func(
			_ http.ResponseWriter,
			_ *http.Request,
			session *goidc.AuthnSession,
			_ *goidc.Client,
		) (goidc.Status, error) {
			session.Subject = "human-subject"
			session.GrantedScopes = session.Scopes
			return goidc.StatusSuccess, nil
		},
	)}
	signingKey := oidctest.PrivatePS256JWK(t, "strict-human-key", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID:                          "human-confidential-bff",
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 17,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{{
				Key:            signingKey.Public(),
				KeyAuthorityID: "strict-human-authority-key",
			}},
		},
		ClientMeta: goidc.ClientMeta{
			ApplicationType:   goidc.ApplicationTypeWeb,
			SubIdentifierType: goidc.SubIdentifierPairwise,
			IDTokenSigAlg:     goidc.SigAlgPS256,
			TokenAuthnMethod:  goidc.AuthnMethodPrivateKeyJWT,
			TokenAuthnSigAlg:  goidc.SigAlgPS256,
			RedirectURIs:      []string{"https://human-bff.example.invalid/callback"},
			ScopeIDs:          goidc.ScopeOpenID.ID,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			PARRequired:   false, // The authority profile, not mutable metadata, mandates PAR.
		},
	}
	ctx.StaticClients = []*goidc.Client{client}
	ctx.PAREnabled = true
	ctx.PARLifetimeSecs = 60
	ctx.PKCEEnabled = true
	ctx.PKCERequired = true
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	ctx.ResourceIndicatorsEnabled = true
	ctx.ResourceIndicators = []goidc.ResourceIndicator{"https://api.example.invalid/accounting"}
	ctx.PairwiseSubjectFunc = func(_ context.Context, subject string, _ *goidc.Client) string {
		return "pairwise-" + subject
	}
	ctx.HumanConfidentialBFFAuthorizationEnabled = true
	ctx.HumanIdentityInteractionEndpoint = "https://id.d0.eu/oidc/interaction/identity"
	ctx.HumanBrowserBindingCookieName = "__Host-d0-human-oidc"
	ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
		start: func(_ context.Context, _ goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
			entry, err := goidc.NewHumanInteractionEntryCapability(strictHumanTestEntry)
			if err != nil {
				t.Fatalf("NewHumanInteractionEntryCapability() error = %v", err)
			}
			binding, err := goidc.NewHumanBrowserBindingCapability(strictHumanTestBinding)
			if err != nil {
				t.Fatalf("NewHumanBrowserBindingCapability() error = %v", err)
			}
			return mustHumanStartDecision(t, goidc.HumanStartDecisionConfig{
				Outcome:                  goidc.HumanStartOutcomePending,
				EntryCapability:          entry,
				BrowserBindingCapability: binding,
				ExpiresAt:                int64(timeutil.TimestampNow() + 300),
			}), nil
		},
	}
	ctx.PARManager = oidctest.Manager(t, ctx)
	requestURI := strictHumanTestRequestURI
	requestID := strings.TrimPrefix(requestURI, parRequestURIPrefix)
	now := timeutil.TimestampNow()
	if err := ctx.AuthSaveSession(&goidc.AuthnSession{
		ID:                          "strict-human-session",
		PersistenceID:               "strict-human-persistence",
		PushedAuthReqID:             requestID,
		ClientID:                    client.ID,
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		ClientAssertionAuthority: &goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 17,
			KeyAuthorityID:   "strict-human-authority-key",
		},
		Status:    goidc.StatusPending,
		CreatedAt: now,
		ExpiresAt: now + 60,
		Store:     make(map[string]any),
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:         client.RedirectURIs[0],
			ResponseType:        goidc.ResponseTypeCode,
			ResponseMode:        goidc.ResponseModeQuery,
			Scopes:              goidc.ScopeOpenID.ID,
			State:               "opaque-state-1234",
			Nonce:               "opaque-nonce-1234",
			CodeChallenge:       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
			CodeChallengeMethod: goidc.CodeChallengeMethodSHA256,
			Resources:           goidc.Resources{"https://api.example.invalid/accounting"},
		},
	}); err != nil {
		t.Fatalf("AuthSaveSession() error = %v", err)
	}
	return ctx, client, requestURI
}

func newStrictPARContext(
	t *testing.T,
	profile goidc.AuthorizationRequestProfile,
) (oidc.Context, *goidc.Client, url.Values) {
	t.Helper()
	ctx := oidctest.NewContext(t)
	manager := oidctest.Manager(t, ctx)
	ctx.AuthManager = manager
	ctx.PARManager = manager
	ctx.PAREnabled = true
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.JWTLifetimeSecs = 60
	ctx.PARLifetimeSecs = 60
	ctx.PKCEEnabled = true
	ctx.PKCERequired = true
	ctx.PKCEChallengeMethods = []goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	ctx.PairwiseSubjectFunc = func(_ context.Context, subject string, _ *goidc.Client) string {
		return "pairwise-" + subject
	}
	ctx.ACRs = []goidc.ACR{"urn:d0:assurance:passkey"}
	ctx.ResourceIndicatorsEnabled = true
	ctx.ResourceIndicators = []string{
		"https://api.example.invalid/accounting",
		"https://api.example.invalid/billing",
	}
	ctx.AuthSessionIDFunc = func(context.Context) string { return "strict-human-session" }
	ctx.AuthSessionPersistenceIDFunc = func(context.Context) string { return "strict-human-persistence" }
	ctx.PARIDFunc = func(context.Context) string { return "strict-human-par" }

	signingKey := oidctest.PrivatePS256JWK(t, "strict-human-key", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID:                          "human-confidential-bff",
		AuthorizationRequestProfile: profile,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 17,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{{
				Key:            signingKey.Public(),
				KeyAuthorityID: "strict-human-authority-key",
			}},
		},
		ClientMeta: goidc.ClientMeta{
			ApplicationType:   goidc.ApplicationTypeWeb,
			SubIdentifierType: goidc.SubIdentifierPairwise,
			IDTokenSigAlg:     goidc.SigAlgPS256,
			TokenAuthnMethod:  goidc.AuthnMethodPrivateKeyJWT,
			TokenAuthnSigAlg:  goidc.SigAlgPS256,
			RedirectURIs:      []string{"https://human-bff.example.invalid/callback"},
			ScopeIDs:          goidc.ScopeOpenID.ID,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, client)
	if profile == goidc.AuthorizationRequestProfileHumanConfidentialBFF {
		ctx.HumanConfidentialBFFAuthorizationEnabled = true
		ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
			storePAR: func(_ context.Context, _ goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
				requestURI := mustHumanPushedRequestURI(t, strictHumanTestRequestURI)
				receipt, err := goidc.NewHumanPARReceipt(requestURI, 60)
				if err != nil {
					t.Fatalf("NewHumanPARReceipt() error = %v", err)
				}
				return mustHumanPARDecision(t, goidc.HumanPAROutcomeCreated, receipt), nil
			},
		}
	}
	now := timeutil.TimestampNow()
	assertion := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimSubject:  client.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 50,
		goidc.ClaimTokenID:  "strict-human-par-assertion",
	}, signingKey)
	values := url.Values{
		"client_id":             {client.ID},
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
		"redirect_uri":          {client.RedirectURIs[0]},
		"response_type":         {string(goidc.ResponseTypeCode)},
		"response_mode":         {string(goidc.ResponseModeQuery)},
		"scope":                 {goidc.ScopeOpenID.ID},
		"state":                 {"opaque-state-1234"},
		"nonce":                 {"opaque-nonce-1234"},
		"code_challenge":        {"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
		"code_challenge_method": {string(goidc.CodeChallengeMethodSHA256)},
		"prompt":                {string(goidc.PromptTypeLogin)},
		"max_age":               {"300"},
		"acr_values":            {"urn:d0:assurance:passkey"},
		"resource": {
			"https://api.example.invalid/accounting",
			"https://api.example.invalid/billing",
		},
	}
	return ctx, client, values
}

func assertAuthorizationErrorCode(t *testing.T, err error, want goidc.ErrorCode) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error %q", err, want)
	}
	if oidcErr.Code != want {
		t.Fatalf("error code = %q, want %q (error = %v)", oidcErr.Code, want, err)
	}
}
