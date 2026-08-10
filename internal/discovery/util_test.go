package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestOIDCConfig(t *testing.T) {
	// Given.
	tokenKey := oidctest.PrivateRS256JWK(t, "token_signature_key", goidc.KeyUsageSignature)
	userKey := oidctest.PrivateRS256JWK(t, "user_signature_key", goidc.KeyUsageSignature)
	config := &oidc.Configuration{
		Host:                       "https://example.com",
		JWKSEndpoint:               "/jwks",
		TokenEndpoint:              "/token",
		AuthorizationEndpoint:      "/authorize",
		DeviceAuthEndpoint:         "/device_authorization",
		PAREndpoint:                "/par",
		DCREndpoint:                "/register",
		UserInfoEndpoint:           "/userinfo",
		TokenIntrospectionEndpoint: "/introspect",
		TokenRevocationEndpoint:    "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantDeviceCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		IssuerRespParamEnabled: true,
		ClaimsParamEnabled:     true,
		ACRs:                   []goidc.ACR{"0"},
		DisplayValues:          []goidc.DisplayValue{goidc.DisplayValuePage},
		UserInfoDefaultSigAlg:  goidc.SignatureAlgorithm(userKey.Algorithm),
		UserInfoSigAlgs:        []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userKey.Algorithm)},
		IDTokenDefaultSigAlg:   goidc.SignatureAlgorithm(userKey.Algorithm),
		IDTokenSigAlgs:         []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userKey.Algorithm)},
		DCREnabled:             true,
		AuthnMethods: []goidc.AuthnMethod{
			goidc.AuthnMethodNone,
			goidc.AuthnMethodPrivateKeyJWT,
			goidc.AuthnMethodSecretJWT,
		},
		AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
		RAREnabled:                      true,
		RARDetailTypes:                  []goidc.AuthDetailType{"detail_type"},
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewConfiguration(ctx)

	// Then.
	want := goidc.Configuration{
		Issuer:                      ctx.Issuer(),
		ClientRegistrationEndpoint:  ctx.Issuer() + ctx.DCREndpoint,
		AuthorizationEndpoint:       ctx.Issuer() + ctx.AuthorizationEndpoint,
		DeviceAuthorizationEndpoint: ctx.Issuer() + ctx.DeviceAuthEndpoint,
		TokenEndpoint:               ctx.Issuer() + ctx.TokenEndpoint,
		UserInfoEndpoint:            ctx.Issuer() + ctx.UserInfoEndpoint,
		JWKSEndpoint:                ctx.Issuer() + ctx.JWKSEndpoint,
		Scopes:                      []string{"openid", "email"},
		TokenAuthnMethods:           ctx.AuthnMethods,
		TokenAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SigAlgPS256, goidc.SigAlgHS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userKey.Algorithm),
		},
		IDTokenSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userKey.Algorithm),
		},
		ResponseTypes:              ctx.ResponseTypes,
		ResponseModes:              ctx.ResponseModes,
		UserClaimsSupported:        ctx.Claims,
		ClaimTypesSupported:        ctx.ClaimTypes,
		SubIdentifierTypes:         ctx.SubIdentifierTypes,
		IssuerResponseParamEnabled: ctx.IssuerRespParamEnabled,
		ClaimsParamEnabled:         ctx.ClaimsParamEnabled,
		AuthDetailsEnabled:         ctx.RAREnabled,
		AuthDetailTypesSupported:   []goidc.AuthDetailType{"detail_type"},
		ACRs:                       []goidc.ACR{"0"},
		DisplayValues: []goidc.DisplayValue{
			goidc.DisplayValuePage,
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}

func TestOIDCConfig_WithVariants(t *testing.T) {
	// Given.
	tokenKey := oidctest.PrivateRS256JWK(t, "token_signature_key",
		goidc.KeyUsageSignature)
	userInfoKey := oidctest.PrivateRS256JWK(t, "user_info_signature_key",
		goidc.KeyUsageSignature)
	jarmKey := oidctest.PrivateRS256JWK(t, "jarm_signature_key",
		goidc.KeyUsageSignature)
	config := &oidc.Configuration{
		Host:                       "https://example.com",
		JWKSEndpoint:               "/jwks",
		TokenEndpoint:              "/token",
		AuthorizationEndpoint:      "/authorize",
		DeviceAuthEndpoint:         "/device_authorization",
		PAREndpoint:                "/par",
		DCREndpoint:                "/register",
		UserInfoEndpoint:           "/userinfo",
		TokenIntrospectionEndpoint: "/introspect",
		TokenRevocationEndpoint:    "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userInfoKey, jarmKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantDeviceCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		IssuerRespParamEnabled: true,
		ClaimsParamEnabled:     true,
		ACRs:                   []goidc.ACR{"0"},
		DisplayValues:          []goidc.DisplayValue{goidc.DisplayValuePage},
		UserInfoDefaultSigAlg:  goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		UserInfoSigAlgs:        []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userInfoKey.Algorithm)},
		IDTokenDefaultSigAlg:   goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		IDTokenSigAlgs:         []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userInfoKey.Algorithm)},
		DCREnabled:             true,
		AuthnMethods: []goidc.AuthnMethod{
			goidc.AuthnMethodNone,
			goidc.AuthnMethodPrivateKeyJWT,
			goidc.AuthnMethodSecretJWT,
		},
		AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgHS256},
		RAREnabled:                      true,
		RARDetailTypes:                  []goidc.AuthDetailType{"detail_type"},
		PAREnabled:                      true,
		JAREnabled:                      true,
		JARRequired:                     true,
		JARSigAlgs:                      []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		JARMEnabled:                     true,
		JARMSigAlgDefault:               goidc.SignatureAlgorithm(jarmKey.Algorithm),
		JARMSigAlgs:                     []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jarmKey.Algorithm)},
		DPoPEnabled:                     true,
		DPoPSigAlgs:                     []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
		TokenIntrospectionEnabled:       true,
		TokenRevocationEnabled:          true,
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewConfiguration(ctx)

	// Then.
	want := goidc.Configuration{
		Issuer:                      ctx.Issuer(),
		ClientRegistrationEndpoint:  ctx.Issuer() + ctx.DCREndpoint,
		AuthorizationEndpoint:       ctx.Issuer() + ctx.AuthorizationEndpoint,
		DeviceAuthorizationEndpoint: ctx.Issuer() + ctx.DeviceAuthEndpoint,
		TokenEndpoint:               ctx.Issuer() + ctx.TokenEndpoint,
		UserInfoEndpoint:            ctx.Issuer() + ctx.UserInfoEndpoint,
		JWKSEndpoint:                ctx.Issuer() + ctx.JWKSEndpoint,
		PAREndpoint:                 ctx.Issuer() + ctx.PAREndpoint,
		TokenIntrospectionEndpoint:  ctx.Issuer() + ctx.TokenIntrospectionEndpoint,
		TokenRevocationEndpoint:     ctx.Issuer() + ctx.TokenRevocationEndpoint,
		Scopes:                      []string{"openid", "email"},
		TokenAuthnMethods:           ctx.AuthnMethods,
		TokenAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SigAlgPS256, goidc.SigAlgHS256,
		},
		TokenIntrospectionAuthnMethods: ctx.AuthnMethods,
		TokenIntrospectionAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SigAlgPS256, goidc.SigAlgHS256,
		},
		TokenRevocationAuthnMethods: ctx.AuthnMethods,
		TokenRevocationAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SigAlgPS256, goidc.SigAlgHS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		IDTokenSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		ResponseTypes:              ctx.ResponseTypes,
		ResponseModes:              ctx.ResponseModes,
		UserClaimsSupported:        ctx.Claims,
		ClaimTypesSupported:        ctx.ClaimTypes,
		SubIdentifierTypes:         ctx.SubIdentifierTypes,
		IssuerResponseParamEnabled: ctx.IssuerRespParamEnabled,
		ClaimsParamEnabled:         ctx.ClaimsParamEnabled,
		AuthDetailsEnabled:         ctx.RAREnabled,
		AuthDetailTypesSupported:   []goidc.AuthDetailType{"detail_type"},
		ACRs:                       []goidc.ACR{"0"},
		DisplayValues: []goidc.DisplayValue{
			goidc.DisplayValuePage,
		},
		JAREnabled:  true,
		JARRequired: true,
		JARAlgs:     ctx.JARSigAlgs,
		JARMAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(jarmKey.Algorithm),
		},
		DPoPSigAlgs: ctx.DPoPSigAlgs,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}

func TestOIDCConfigWithoutUserInfoOmitsEndpointAndCapabilities(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.UserInfoDisabled = true
	ctx.UserInfoEndpoint = "/userinfo"
	ctx.UserInfoSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}
	ctx.UserInfoEncEnabled = true
	ctx.UserInfoKeyEncAlgs = []goidc.KeyEncryptionAlgorithm{goidc.KeyEncRSAOAEP}
	ctx.UserInfoContentEncAlgs = []goidc.ContentEncryptionAlgorithm{goidc.ContentEncAlgA128GCM}
	ctx.MTLSEnabled = true

	got := NewConfiguration(ctx)
	if got.UserInfoEndpoint != "" {
		t.Fatalf("UserInfoEndpoint = %q, want empty", got.UserInfoEndpoint)
	}
	if len(got.UserInfoSigAlgs) != 0 || len(got.UserInfoKeyEncAlgs) != 0 || len(got.UserInfoContentEncAlgs) != 0 {
		t.Fatal("userinfo capabilities were advertised while userinfo is disabled")
	}
	if got.MTLSAliases == nil {
		t.Fatal("MTLSAliases = nil, want token endpoint alias")
	}
	if got.MTLSAliases.UserInfoEndpoint != "" {
		t.Fatalf("MTLS userinfo endpoint = %q, want empty", got.MTLSAliases.UserInfoEndpoint)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, field := range []string{
		`"userinfo_endpoint"`,
		`"userinfo_signing_alg_values_supported"`,
		`"userinfo_encryption_alg_values_supported"`,
		`"userinfo_encryption_enc_values_supported"`,
	} {
		if bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("configuration JSON contains disabled field %s: %s", field, encoded)
		}
	}
}

func TestOIDCConfig_JARByReferenceMetadata(t *testing.T) {
	tests := []struct {
		name                               string
		byReferenceEnabled                 bool
		unregisteredUREnabled              bool
		wantByReferenceEnabled             bool
		wantRegistrationRequiredAdvertised bool
	}{
		{
			name:                               "disabled",
			byReferenceEnabled:                 false,
			unregisteredUREnabled:              false,
			wantByReferenceEnabled:             false,
			wantRegistrationRequiredAdvertised: false,
		},
		{
			name:                               "enabled with registration required",
			byReferenceEnabled:                 true,
			unregisteredUREnabled:              false,
			wantByReferenceEnabled:             true,
			wantRegistrationRequiredAdvertised: true,
		},
		{
			name:                               "enabled with unregistered uris allowed",
			byReferenceEnabled:                 true,
			unregisteredUREnabled:              true,
			wantByReferenceEnabled:             true,
			wantRegistrationRequiredAdvertised: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.JAREnabled = true
			ctx.JARByReferenceEnabled = test.byReferenceEnabled
			ctx.JARByReferenceUnregisteredURIEnabled = test.unregisteredUREnabled

			got := NewConfiguration(ctx)

			if got.JARByReferenceEnabled != test.wantByReferenceEnabled {
				t.Fatalf("JARByReferenceEnabled = %v, want %v", got.JARByReferenceEnabled, test.wantByReferenceEnabled)
			}
			if got.JARRequestURIRegistrationRequired != test.wantRegistrationRequiredAdvertised {
				t.Fatalf("JARRequestURIRegistrationRequired = %v, want %v", got.JARRequestURIRegistrationRequired, test.wantRegistrationRequiredAdvertised)
			}
		})
	}
}
