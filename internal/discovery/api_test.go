package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestRegisterHandlers_AuthorizationServerMetadata(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		paths  []string
	}{
		{
			name:   "issuer without path",
			issuer: "https://example.com",
			paths: []string{
				"/.well-known/oauth-authorization-server",
				"/.well-known/openid-configuration",
			},
		},
		{
			name:   "issuer with path",
			issuer: "https://example.com/tenant/issuer",
			paths: []string{
				"/.well-known/oauth-authorization-server/tenant/issuer",
				"/tenant/issuer/.well-known/openid-configuration",
			},
		},
		{
			name:   "issuer with trailing path slash",
			issuer: "https://example.com/tenant/issuer/",
			paths: []string{
				"/.well-known/oauth-authorization-server/tenant/issuer",
				"/tenant/issuer/.well-known/openid-configuration",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.Host = test.issuer
			ctx.DCREnabled = false
			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			for _, path := range test.paths {
				recorder := httptest.NewRecorder()
				mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

				if recorder.Code != http.StatusOK {
					t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
				}
				var metadata map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
					t.Fatalf("decode metadata from %s: %v", path, err)
				}
				if metadata["issuer"] != test.issuer {
					t.Fatalf("GET %s issuer = %v, want %q", path, metadata["issuer"], test.issuer)
				}
				if _, advertised := metadata["registration_endpoint"]; advertised {
					t.Fatalf("GET %s advertises registration_endpoint while DCR is disabled", path)
				}
			}
		})
	}
}

func TestRegisterHandlersRejectsNonStandardPathBasedOIDCMetadataRoute(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.Host = "https://example.com/tenant/issuer"
	mux := http.NewServeMux()
	RegisterHandlers(mux, ctx.Configuration)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration/tenant/issuer", nil),
	)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("non-standard OIDC metadata route status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestRegisterHandlersCanExposeOnlyAuthorizationServerMetadata(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.OpenIDConfigurationDisabled = true
	mux := http.NewServeMux()
	RegisterHandlers(mux, ctx.Configuration)

	oauthResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		oauthResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil),
	)
	if oauthResponse.Code != http.StatusOK {
		t.Fatalf("authorization server metadata status = %d, want %d", oauthResponse.Code, http.StatusOK)
	}

	openidResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		openidResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil),
	)
	if openidResponse.Code != http.StatusNotFound {
		t.Fatalf("OpenID configuration status = %d, want %d", openidResponse.Code, http.StatusNotFound)
	}
}

func TestRegisterHandlersCanExposeOnlyOpenIDConfiguration(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.AuthorizationServerMetadataDisabled = true
	mux := http.NewServeMux()
	RegisterHandlers(mux, ctx.Configuration)

	openidResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		openidResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil),
	)
	if openidResponse.Code != http.StatusOK {
		t.Fatalf("OpenID configuration status = %d, want %d", openidResponse.Code, http.StatusOK)
	}

	oauthResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		oauthResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil),
	)
	if oauthResponse.Code != http.StatusNotFound {
		t.Fatalf("authorization server metadata status = %d, want %d", oauthResponse.Code, http.StatusNotFound)
	}
}

func TestAuthorizationServerMetadataForMachineOnlyProviderIsExact(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.Host = "https://auth.d0.eu"
	ctx.TokenEndpoint = "/oauth2/token"
	ctx.JWKSEndpoint = "/oauth2/jwks"
	ctx.GrantTypes = []goidc.GrantType{goidc.GrantClientCredentials}
	ctx.ResponseTypes = nil
	ctx.ResponseModes = nil
	ctx.Scopes = []goidc.Scope{
		goidc.NewScope("einvoice.documents:read"),
		goidc.NewScope("einvoice.documents:write"),
	}
	ctx.AuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodPrivateKeyJWT}
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.DPoPEnabled = true
	ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
	ctx.DCREnabled = false
	ctx.PAREnabled = false
	ctx.TokenIntrospectionEnabled = false
	ctx.TokenRevocationEnabled = false
	ctx.MTLSEnabled = false
	ctx.PKCEEnabled = false
	ctx.RAREnabled = false
	ctx.LogoutEnabled = false

	mux := http.NewServeMux()
	RegisterHandlers(mux, ctx.Configuration)
	response := httptest.NewRecorder()
	mux.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("authorization server metadata status = %d, want %d", response.Code, http.StatusOK)
	}

	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
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
		"grant_types_supported": []any{
			"client_credentials",
		},
		"token_endpoint_auth_methods_supported": []any{
			"private_key_jwt",
		},
		"token_endpoint_auth_signing_alg_values_supported": []any{
			"PS256",
		},
		"dpop_signing_alg_values_supported": []any{
			"ES256",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authorization server metadata = %#v, want %#v", got, want)
	}
}

func TestAuthorizationServerMetadataAdvertisesOnlyEnabledEndpoints(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.DCREnabled = true
	ctx.PAREnabled = true
	ctx.TokenIntrospectionEnabled = true
	ctx.TokenRevocationEnabled = true
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantDeviceCode, goidc.GrantCIBA)
	ctx.DeviceAuthEndpoint = "/device"
	ctx.CIBAEndpoint = "/backchannel"

	metadata := NewAuthorizationServerMetadata(ctx)
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal authorization server metadata: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode authorization server metadata: %v", err)
	}

	for key, want := range map[string]string{
		"authorization_endpoint":                "https://example.com/authorize",
		"registration_endpoint":                 "https://example.com/register",
		"pushed_authorization_request_endpoint": "https://example.com/par",
		"introspection_endpoint":                "https://example.com/introspect",
		"revocation_endpoint":                   "https://example.com" + ctx.TokenRevocationEndpoint,
		"device_authorization_endpoint":         "https://example.com/device",
		"backchannel_authentication_endpoint":   "https://example.com/backchannel",
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %q", key, got[key], want)
		}
	}

	for _, key := range []string{
		"userinfo_endpoint",
		"claims_supported",
		"claim_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_signing_alg_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
		"acr_values_supported",
		"display_values_supported",
		"claims_parameter_supported",
		"end_session_endpoint",
	} {
		if _, ok := got[key]; ok {
			t.Errorf("authorization server metadata unexpectedly contains %q", key)
		}
	}
}
