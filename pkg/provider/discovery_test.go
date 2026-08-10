package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestWithDiscoveryEndpoints(t *testing.T) {
	tests := []struct {
		name               string
		endpoints          []DiscoveryEndpoint
		wantOpenIDDisabled bool
		wantOAuthDisabled  bool
	}{
		{
			name:              "OpenID configuration only",
			endpoints:         []DiscoveryEndpoint{DiscoveryEndpointOpenIDConfiguration},
			wantOAuthDisabled: true,
		},
		{
			name:               "authorization server metadata only",
			endpoints:          []DiscoveryEndpoint{DiscoveryEndpointAuthorizationServerMetadata},
			wantOpenIDDisabled: true,
		},
		{
			name: "both",
			endpoints: []DiscoveryEndpoint{
				DiscoveryEndpointOpenIDConfiguration,
				DiscoveryEndpointAuthorizationServerMetadata,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &Provider{config: oidc.Configuration{}}
			if err := WithDiscoveryEndpoints(test.endpoints...)(provider); err != nil {
				t.Fatalf("WithDiscoveryEndpoints() error = %v", err)
			}
			if provider.config.OpenIDConfigurationDisabled != test.wantOpenIDDisabled {
				t.Errorf(
					"OpenIDConfigurationDisabled = %t, want %t",
					provider.config.OpenIDConfigurationDisabled,
					test.wantOpenIDDisabled,
				)
			}
			if provider.config.AuthorizationServerMetadataDisabled != test.wantOAuthDisabled {
				t.Errorf(
					"AuthorizationServerMetadataDisabled = %t, want %t",
					provider.config.AuthorizationServerMetadataDisabled,
					test.wantOAuthDisabled,
				)
			}
		})
	}
}

func TestWithDiscoveryEndpointsRejectsInvalidSelection(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []DiscoveryEndpoint
	}{
		{name: "empty"},
		{
			name: "duplicate",
			endpoints: []DiscoveryEndpoint{
				DiscoveryEndpointAuthorizationServerMetadata,
				DiscoveryEndpointAuthorizationServerMetadata,
			},
		},
		{name: "unknown", endpoints: []DiscoveryEndpoint{255}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &Provider{config: oidc.Configuration{}}
			if err := WithDiscoveryEndpoints(test.endpoints...)(provider); err == nil {
				t.Fatal("WithDiscoveryEndpoints() error = nil, want non-nil")
			}
			if provider.config.OpenIDConfigurationDisabled ||
				provider.config.AuthorizationServerMetadataDisabled {
				t.Fatal("invalid discovery selection mutated provider configuration")
			}
		})
	}
}

func TestOAuthOnlyProviderPublishesExactAuthorizationServerMetadata(t *testing.T) {
	provider, err := New(
		Config{
			Issuer: "https://auth.d0.eu",
			JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{}, nil
			},
			IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		},
		WithDiscoveryEndpoints(DiscoveryEndpointAuthorizationServerMetadata),
		WithTokenEndpoint("/oauth2/token"),
		WithJWKSEndpoint("/oauth2/jwks"),
		WithoutUserInfo(),
		WithClientCredentialsGrant(),
		WithOAuthScopes(
			goidc.NewScope("einvoice.documents:read"),
			goidc.NewScope("einvoice.documents:write"),
		),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgES256}),
		WithJTIUseConsumer(func(context.Context, goidc.JTIUse) error { return nil }),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	openidResponse := httptest.NewRecorder()
	provider.Handler().ServeHTTP(
		openidResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil),
	)
	if openidResponse.Code != http.StatusNotFound {
		t.Fatalf("OpenID configuration status = %d, want %d", openidResponse.Code, http.StatusNotFound)
	}

	metadataResponse := httptest.NewRecorder()
	provider.Handler().ServeHTTP(
		metadataResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil),
	)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("authorization server metadata status = %d, want %d", metadataResponse.Code, http.StatusOK)
	}

	var got map[string]any
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode authorization server metadata: %v", err)
	}
	want := map[string]any{
		"issuer":                   "https://auth.d0.eu",
		"token_endpoint":           "https://auth.d0.eu/oauth2/token",
		"jwks_uri":                 "https://auth.d0.eu/oauth2/jwks",
		"response_types_supported": []any{},
		"scopes_supported": []any{
			"einvoice.documents:read",
			"einvoice.documents:write",
		},
		"grant_types_supported": []any{"client_credentials"},
		"token_endpoint_auth_methods_supported": []any{
			"private_key_jwt",
		},
		"token_endpoint_auth_signing_alg_values_supported": []any{"PS256"},
		"dpop_signing_alg_values_supported":                []any{"ES256"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authorization server metadata = %#v, want %#v", got, want)
	}
}

func TestWithOAuthScopes(t *testing.T) {
	scopes := []goidc.Scope{
		goidc.NewScope("einvoice.documents:read"),
		goidc.NewScope("einvoice.documents:write"),
	}
	provider := &Provider{config: oidc.Configuration{}}
	if err := WithOAuthScopes(scopes...)(provider); err != nil {
		t.Fatalf("WithOAuthScopes() error = %v", err)
	}
	if len(provider.config.Scopes) != 2 ||
		provider.config.Scopes[0].ID != "einvoice.documents:read" ||
		provider.config.Scopes[1].ID != "einvoice.documents:write" ||
		provider.config.Scopes[0].Matches == nil || provider.config.Scopes[1].Matches == nil {
		t.Fatalf("Scopes = %#v, want %#v", provider.config.Scopes, scopes)
	}
	if !provider.config.OAuthScopesOnly {
		t.Fatal("OAuthScopesOnly = false, want true")
	}

	scopes[0] = goidc.ScopeOpenID
	if provider.config.Scopes[0].ID != "einvoice.documents:read" {
		t.Fatal("configured OAuth scopes retained the caller's slice")
	}
}

func TestNewRejectsOAuthOnlyScopesWithOpenIDDiscovery(t *testing.T) {
	config := Config{
		Issuer: "https://example.com",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
	}
	scopes := WithOAuthScopes(goidc.NewScope("machine.read"))

	if _, err := New(config, scopes); err == nil {
		t.Fatal("New() error = nil, want OpenID discovery incompatibility error")
	}
	if _, err := New(
		config,
		WithDiscoveryEndpoints(DiscoveryEndpointAuthorizationServerMetadata),
		scopes,
	); err != nil {
		t.Fatalf("New() OAuth-only configuration error = %v", err)
	}
}

func TestWithOAuthScopesRejectsInvalidScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []goidc.Scope
	}{
		{name: "empty"},
		{name: "empty identifier", scopes: []goidc.Scope{goidc.NewScope("")}},
		{name: "openid", scopes: []goidc.Scope{goidc.ScopeOpenID}},
		{
			name: "duplicate",
			scopes: []goidc.Scope{
				goidc.NewScope("einvoice.documents:read"),
				goidc.NewScope("einvoice.documents:read"),
			},
		},
		{name: "missing matcher", scopes: []goidc.Scope{{ID: "einvoice.documents:read"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &Provider{config: oidc.Configuration{Scopes: []goidc.Scope{goidc.ScopeEmail}}}
			if err := WithOAuthScopes(test.scopes...)(provider); err == nil {
				t.Fatal("WithOAuthScopes() error = nil, want non-nil")
			}
			if len(provider.config.Scopes) != 1 || provider.config.Scopes[0].ID != goidc.ScopeEmail.ID {
				t.Fatal("invalid OAuth scopes mutated provider configuration")
			}
		})
	}
}
