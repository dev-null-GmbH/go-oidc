package authorize

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/joseutil"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/google/go-cmp/cmp"
)

func TestJARFromRequestObject(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, string, *goidc.Client, request)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
	}{
		{
			name: "signed request object",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:       "https://server.example.com",
						JAREnabled: true,
						JARSigAlgs: []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JWKS: &goidc.JSONWebKeySet{
							Keys: []goidc.JSONWebKey{privateJWK.Public()},
						},
					},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   client.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + 10,
					"client_id":         client.ID,
					"redirect_uri":      "https://example.com",
					"response_type":     goidc.ResponseTypeCode,
					"scope":             "scope scope2",
					"max_age":           600,
					"acr_values":        "0 1",
					"claims": map[string]any{
						"userinfo": map[string]any{
							"acr": map[string]any{
								"value": "0",
							},
						},
					},
				}, privateJWK)

				maxAge := 600
				want := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:     "https://example.com",
						ResponseType:    goidc.ResponseTypeCode,
						Scopes:          "scope scope2",
						MaxAuthnAgeSecs: &maxAge,
						ACRValues:       "0 1",
						Claims: &goidc.ClaimsObject{
							UserInfo: map[string]goidc.ClaimObjectInfo{
								"acr": {Value: "0"},
							},
						},
					},
				}
				return ctx, requestObject, client, want
			},
		},
		{
			name: "unsigned request object allowed",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:       "https://server.example.com",
						JAREnabled: true,
						JARSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgNone},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JARSigAlg: goidc.SigAlgNone,
					},
				}

				requestObject := joseutil.Unsigned(map[string]any{
					"client_id":     client.ID,
					"redirect_uri":  "https://example.com",
					"response_type": goidc.ResponseTypeCode,
					"scope":         "scope scope2",
					"max_age":       600,
					"acr_values":    "0 1",
					"claims": map[string]any{
						"userinfo": map[string]any{
							"acr": map[string]any{
								"value": "0",
							},
						},
					},
				}, nil)

				maxAge := 600
				want := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:     "https://example.com",
						ResponseType:    goidc.ResponseTypeCode,
						Scopes:          "scope scope2",
						MaxAuthnAgeSecs: &maxAge,
						ACRValues:       "0 1",
						Claims: &goidc.ClaimsObject{
							UserInfo: map[string]goidc.ClaimObjectInfo{
								"acr": {Value: "0"},
							},
						},
					},
				}
				return ctx, requestObject, client, want
			},
		},
		{
			name: "unsigned request object denied when none is not allowed",
			setup: func(t *testing.T) (oidc.Context, string, *goidc.Client, request) {
				privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
				ctx := oidc.Context{
					Configuration: &oidc.Configuration{
						Host:       "https://server.example.com",
						JAREnabled: true,
						JARSigAlgs: []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
					},
					Request: &http.Request{Method: http.MethodPost},
				}

				client := &goidc.Client{
					ID: "test_client",
					ClientMeta: goidc.ClientMeta{
						JARSigAlg: goidc.SignatureAlgorithm(privateJWK.Algorithm),
					},
				}

				requestObject := joseutil.Unsigned(map[string]any{
					"client_id":     client.ID,
					"redirect_uri":  "https://example.com",
					"response_type": goidc.ResponseTypeCode,
					"scope":         "scope scope2",
				}, nil)

				return ctx, requestObject, client, request{}
			},
			wantErr:         goidc.ErrorCodeInvalidRequestObject,
			wantDescription: "invalid request object",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, requestObject, c, want := test.setup(t)

			// When.
			jar, err := jarFromRequestObject(ctx, requestObject, c, nil)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(jar, want); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestJARFromRequestObjectConsumesTypedJTIWithoutExpiry(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	var got goidc.JTIUse
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:       "https://server.example.com",
			JAREnabled: true,
			JARSigAlgs: []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
			ConsumeJTIUseFunc: func(_ context.Context, use goidc.JTIUse) error {
				got = use
				return nil
			},
		},
		Request: &http.Request{Method: http.MethodPost},
	}
	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{JWKS: &goidc.JSONWebKeySet{
			Keys: []goidc.JSONWebKey{privateJWK.Public()},
		}},
	}
	requestObject := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimTokenID:  "request-object-id",
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
		"scope":             "scope",
	}, privateJWK)

	if _, err := jarFromRequestObject(ctx, requestObject, client, nil); err != nil {
		t.Fatalf("jarFromRequestObject() error = %v", err)
	}
	want := goidc.JTIUse{
		ID:      "request-object-id",
		Issuer:  client.ID,
		Purpose: goidc.JTIUsePurposeRequestObject,
	}
	if got != want {
		t.Fatalf("JTI use = %#v, want %#v", got, want)
	}
}

func TestJARFromRequestURI(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:                         "https://server.example.com",
			JAREnabled:                   true,
			JARSigAlgs:                   []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
			JARByReferenceEnabled:        true,
			HTTPClientFunc:               func(_ context.Context) *http.Client { return http.DefaultClient },
			JARByReferenceHTTPClientFunc: func(_ context.Context) *http.Client { return http.DefaultClient },
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	now := timeutil.TimestampNow()
	requestObject := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
		"scope":             "scope scope2",
		"max_age":           600,
		"acr_values":        "0 1",
		"claims": map[string]any{
			"userinfo": map[string]any{
				"acr": map[string]any{
					"value": "0",
				},
			},
		},
	}, privateJWK)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(requestObject)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client.RequestURIs = []string{server.URL}
	ctx.JARByReferenceHTTPClientFunc = func(context.Context) *http.Client {
		return trustedJARTestHTTPClient(t, server)
	}

	jar, err := jarFromRequestURIWithNetworkControl(ctx, server.URL, client, allowLoopbackJARNetworkControl())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	maxAge := 600
	want := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:     "https://example.com",
			ResponseType:    goidc.ResponseTypeCode,
			Scopes:          "scope scope2",
			MaxAuthnAgeSecs: &maxAge,
			ACRValues:       "0 1",
			Claims: &goidc.ClaimsObject{
				UserInfo: map[string]goidc.ClaimObjectInfo{
					"acr": {Value: "0"},
				},
			},
		},
	}
	if diff := cmp.Diff(jar, want); diff != "" {
		t.Error(diff)
	}
}

func TestJARFromRequestURIErrors(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	t.Run("non-200 response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()
		client.RequestURIs = []string{server.URL}

		ctx := oidc.Context{
			Configuration: &oidc.Configuration{
				Host:                  "https://server.example.com",
				JAREnabled:            true,
				JARSigAlgs:            []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
				JARByReferenceEnabled: true,
				HTTPClientFunc:        func(_ context.Context) *http.Client { return http.DefaultClient },
				JARByReferenceHTTPClientFunc: func(_ context.Context) *http.Client {
					return trustedJARTestHTTPClient(t, server)
				},
			},
			Request: &http.Request{Method: http.MethodPost},
		}

		_, err := jarFromRequestURIWithNetworkControl(ctx, server.URL, client, allowLoopbackJARNetworkControl())
		if err == nil {
			t.Fatal("expected error")
		}

		var oidcErr goidc.Error
		if !errors.As(err, &oidcErr) {
			t.Fatalf("invalid error type: %T", err)
		}
		if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
			t.Fatalf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
		}
		if oidcErr.Description != "invalid request_uri" {
			t.Fatalf("error description = %q, want %q", oidcErr.Description, "invalid request_uri")
		}
		if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "request_uri returned HTTP status 502" {
			t.Fatalf("wrapped error = %v, want %q", unwrapped, "request_uri returned HTTP status 502")
		}
	})
}

func TestJARFromRequestURIUsesDedicatedClient(t *testing.T) {
	privateJWK := oidctest.PrivateRS256JWK(t, "client_key_id", goidc.KeyUsageSignature)
	client := &goidc.Client{
		ID: "test_client",
		ClientMeta: goidc.ClientMeta{
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.Public()},
			},
		},
	}

	now := timeutil.TimestampNow()
	requestObject := oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: "https://server.example.com",
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 10,
		"client_id":         client.ID,
		"redirect_uri":      "https://example.com",
		"response_type":     goidc.ResponseTypeCode,
	}, privateJWK)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(requestObject)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client.RequestURIs = []string{server.URL}

	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:                  "https://server.example.com",
			JAREnabled:            true,
			JARSigAlgs:            []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(privateJWK.Algorithm)},
			JARByReferenceEnabled: true,
			HTTPClientFunc: func(_ context.Context) *http.Client {
				return &http.Client{
					Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
						return nil, errors.New("wrong client used")
					}),
				}
			},
			JARByReferenceHTTPClientFunc: func(_ context.Context) *http.Client {
				return trustedJARTestHTTPClient(t, server)
			},
		},
		Request: &http.Request{Method: http.MethodPost},
	}

	if _, err := jarFromRequestURIWithNetworkControl(
		ctx,
		server.URL,
		client,
		allowLoopbackJARNetworkControl(),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJARFromRequestURIRejectsUnregisteredAndUnsafeTargetsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name       string
		requestURI string
		registered []string
		client     bool
	}{
		{
			name:       "unregistered HTTPS URI",
			requestURI: "https://attacker.example/request.jwt",
			registered: []string{"https://client.example/request.jwt"},
			client:     true,
		},
		{
			name:       "cleartext registered URI",
			requestURI: "http://client.example/request.jwt",
			registered: []string{"http://client.example/request.jwt"},
			client:     true,
		},
		{
			name:       "registered URI with credentials",
			requestURI: "https://user:password@client.example/request.jwt",
			registered: []string{"https://user:password@client.example/request.jwt"},
			client:     true,
		},
		{
			name:       "registered URI with fragment",
			requestURI: "https://client.example/request.jwt#fragment",
			registered: []string{"https://client.example/request.jwt#fragment"},
			client:     true,
		},
		{
			name:       "registered URI without host",
			requestURI: "https:///request.jwt",
			registered: []string{"https:///request.jwt"},
			client:     true,
		},
		{
			name:       "missing client",
			requestURI: "https://client.example/request.jwt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transportCalls := 0
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					JARByReferenceEnabled: true,
					JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
						return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
							transportCalls++
							return nil, errors.New("unexpected network request")
						})}
					},
				},
				Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
			}
			var c *goidc.Client
			if test.client {
				c = &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: test.registered}}
			}

			_, err := jarFromRequestURI(ctx, test.requestURI, c)
			if err == nil {
				t.Fatal("jarFromRequestURI() error = nil")
			}
			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidRequest ||
				oidcErr.Description != "invalid request_uri" {
				t.Fatalf("jarFromRequestURI() error = %#v", err)
			}
			if transportCalls != 0 {
				t.Fatalf("untrusted request_uri reached transport %d times", transportCalls)
			}
		})
	}
}

func TestJARFromRequestURIDoesNotFollowRedirects(t *testing.T) {
	targetCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/registered.jwt":
			http.Redirect(response, request, "/unregistered.jwt", http.StatusFound)
		case "/unregistered.jwt":
			targetCalls++
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	registeredURI := server.URL + "/registered.jwt"
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			JARByReferenceEnabled: true,
			JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
				return trustedJARTestHTTPClient(t, server)
			},
		},
		Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
	}
	c := &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: []string{registeredURI}}}

	_, err := jarFromRequestURIWithNetworkControl(ctx, registeredURI, c, allowLoopbackJARNetworkControl())
	if err == nil {
		t.Fatal("jarFromRequestURI() error = nil")
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target received %d requests", targetCalls)
	}
}

func TestJARNetworkGuardRejectsNonPublicLiteralAddressesBeforeTransport(t *testing.T) {
	for _, rawURI := range []string{
		"https://127.0.0.1/request.jwt",
		"https://10.0.0.1/request.jwt",
		"https://100.64.0.1/request.jwt",
		"https://169.254.169.254/request.jwt",
		"https://0.0.0.0/request.jwt",
		"https://224.0.0.1/request.jwt",
		"https://[::1]/request.jwt",
		"https://[fc00::1]/request.jwt",
		"https://[fe80::1]/request.jwt",
		"https://[::]/request.jwt",
		"https://[ff02::1]/request.jwt",
		"https://[100:0:0:1::1]/request.jwt",
		"https://[2620:4f:8000::1]/request.jwt",
		"https://[4000::1]/request.jwt",
		"https://[8000::1]/request.jwt",
		"https://[f000::1]/request.jwt",
		"https://[fe00::1]/request.jwt",
		"https://[::ffff:8.8.8.8]/request.jwt",
		"https://[::ffff:127.0.0.1]/request.jwt",
	} {
		t.Run(rawURI, func(t *testing.T) {
			transportCalls := 0
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
						return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
							transportCalls++
							return nil, errors.New("unexpected network request")
						})}
					},
				},
				Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
			}
			client := &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: []string{rawURI}}}

			_, err := jarFromRequestURI(ctx, rawURI, client)
			assertInvalidJARRequestURI(t, err)
			if transportCalls != 0 {
				t.Fatalf("prohibited literal reached transport %d times", transportCalls)
			}
		})
	}
}

func TestJARNetworkGuardRejectsNonPublicAndMixedDNSAnswers(t *testing.T) {
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
	}{
		{name: "private IPv4", addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{name: "CGNAT IPv4", addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
		{name: "loopback IPv6", addresses: []netip.Addr{netip.MustParseAddr("::1")}},
		{name: "unallocated IPv6", addresses: []netip.Addr{netip.MustParseAddr("4000::1")}},
		{name: "IPv4-mapped public", addresses: []netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")}},
		{name: "globally reachable special IPv6", addresses: []netip.Addr{netip.MustParseAddr("2620:4f:8000::1")}},
		{
			name: "mixed public and private",
			addresses: []netip.Addr{
				netip.MustParseAddr("8.8.8.8"),
				netip.MustParseAddr("192.168.1.10"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &sequenceJARResolver{answers: [][]netip.Addr{test.addresses}}
			transportCalls := 0
			rawURI := "https://jar-client.example/request.jwt"
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
						return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
							transportCalls++
							return nil, errors.New("unexpected network request")
						})}
					},
				},
				Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
			}
			client := &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: []string{rawURI}}}

			_, err := jarFromRequestURIWithNetworkControl(
				ctx,
				rawURI,
				client,
				jarNetworkControl{resolver: resolver},
			)
			assertInvalidJARRequestURI(t, err)
			if resolver.callCount() != 1 || transportCalls != 0 {
				t.Fatalf("resolver/transport calls = %d/%d, want 1/0", resolver.callCount(), transportCalls)
			}
		})
	}
}

func TestJARNetworkGuardBoundsDNSResolution(t *testing.T) {
	for _, test := range []struct {
		name          string
		clientTimeout time.Duration
		wantMaximum   time.Duration
	}{
		{name: "guard default", wantMaximum: maxJARNetworkTimeout},
		{name: "shorter client timeout", clientTimeout: 2 * time.Second, wantMaximum: 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			var remaining time.Duration
			resolver := jarResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("DNS resolver context has no deadline")
				}
				remaining = time.Until(deadline)
				return nil, errors.New("resolution stopped by test")
			})
			rawURI := "https://jar-client.example/request.jwt"
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
						return &http.Client{Timeout: test.clientTimeout}
					},
				},
				Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
			}
			client := &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: []string{rawURI}}}

			_, err := jarFromRequestURIWithNetworkControl(
				ctx,
				rawURI,
				client,
				jarNetworkControl{resolver: resolver},
			)
			assertInvalidJARRequestURI(t, err)
			if remaining <= 0 || remaining > test.wantMaximum {
				t.Fatalf("DNS resolution deadline remaining = %v, want (0, %v]", remaining, test.wantMaximum)
			}
		})
	}
}

func TestJARNetworkGuardPinsSingleDNSAnswerAgainstRebinding(t *testing.T) {
	resolver := &sequenceJARResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	rawURI := "https://jar-client.example/request.jwt"
	target, err := resolveJARNetworkTarget(
		context.Background(),
		rawURI,
		jarNetworkControl{resolver: resolver},
	)
	if err != nil {
		t.Fatal(err)
	}

	var dialMutex sync.Mutex
	var dialed []string
	dialStopped := errors.New("dial stopped by test")
	_, err = dialJARNetworkTarget(
		context.Background(),
		"tcp",
		target,
		func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialMutex.Lock()
			dialed = append(dialed, address)
			dialMutex.Unlock()
			return nil, dialStopped
		},
	)
	if !errors.Is(err, dialStopped) {
		t.Fatalf("dial error = %v, want %v", err, dialStopped)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("DNS resolver calls = %d, want 1", resolver.callCount())
	}
	dialMutex.Lock()
	gotDialed := append([]string(nil), dialed...)
	dialMutex.Unlock()
	if !slices.Equal(gotDialed, []string{"8.8.8.8:443"}) {
		t.Fatalf("dialed addresses = %v, want [8.8.8.8:443]", gotDialed)
	}

	request, requestErr := http.NewRequest(http.MethodGet, rawURI, nil)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	baseJar, jarErr := cookiejar.New(nil)
	if jarErr != nil {
		t.Fatal(jarErr)
	}
	proxyCalls := 0
	baseTransport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		proxyCalls++
		return url.Parse("http://127.0.0.1:8080")
	}}
	guardedClient, guardedTransport, guardErr := newGuardedJARHTTPClient(
		&http.Client{Transport: baseTransport, Jar: baseJar},
		target,
	)
	if guardErr != nil {
		t.Fatal(guardErr)
	}
	if guardedClient.Jar != nil {
		t.Fatal("guarded request_uri client retained the configured cookie jar")
	}
	if proxyCalls != 0 {
		t.Fatalf("proxy function called %d times, want 0", proxyCalls)
	}
	if guardedTransport.Proxy != nil {
		t.Fatal("guarded transport retained its configured proxy")
	}
	effectiveHost := request.Host
	if effectiveHost == "" {
		effectiveHost = request.URL.Host
	}
	if request.URL.Host != "jar-client.example" || effectiveHost != "jar-client.example" ||
		guardedTransport.TLSClientConfig.ServerName != "jar-client.example" {
		t.Fatalf(
			"guarded target host/request host/SNI = %q/%q/%q",
			request.URL.Host,
			request.Host,
			guardedTransport.TLSClientConfig.ServerName,
		)
	}
}

func TestJARNetworkGuardRejectsUnsupportedTransportSettings(t *testing.T) {
	rawURI := "https://8.8.8.8/request.jwt"
	client := &goidc.Client{ClientMeta: goidc.ClientMeta{RequestURIs: []string{rawURI}}}
	for _, test := range []struct {
		name      string
		transport http.RoundTripper
	}{
		{
			name: "arbitrary round tripper",
			transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsupported RoundTripper received a request")
				return nil, nil
			}),
		},
		{
			name: "insecure TLS verification",
			// Deliberately insecure to verify that the production guard rejects it.
			transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		{
			name: "custom TLS protocol handler",
			transport: &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
				"custom": func(string, *tls.Conn) http.RoundTripper { return http.DefaultTransport },
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					JARByReferenceHTTPClientFunc: func(context.Context) *http.Client {
						return &http.Client{Transport: test.transport}
					},
				},
				Request: httptest.NewRequest(http.MethodGet, "https://server.example.com/authorize", nil),
			}
			_, err := jarFromRequestURI(ctx, rawURI, client)
			assertInvalidJARRequestURI(t, err)
		})
	}
}

func allowLoopbackJARNetworkControl() jarNetworkControl {
	return jarNetworkControl{allowAddress: func(address netip.Addr) bool {
		return address.IsValid()
	}}
}

func trustedJARTestHTTPClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}}}
}

func assertInvalidJARRequestURI(t *testing.T, err error) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidRequest ||
		oidcErr.Description != "invalid request_uri" {
		t.Fatalf("JAR request_uri error = %#v", err)
	}
}

type sequenceJARResolver struct {
	mutex   sync.Mutex
	answers [][]netip.Addr
	calls   int
}

type jarResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (resolve jarResolverFunc) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	return resolve(ctx, network, host)
}

func (resolver *sequenceJARResolver) LookupNetIP(
	context.Context,
	string,
	string,
) ([]netip.Addr, error) {
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	index := resolver.calls
	resolver.calls++
	if index >= len(resolver.answers) {
		index = len(resolver.answers) - 1
	}
	return append([]netip.Addr(nil), resolver.answers[index]...), nil
}

func (resolver *sequenceJARResolver) callCount() int {
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	return resolver.calls
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
