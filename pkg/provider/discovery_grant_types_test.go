package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestStrictHumanDiscoveryGrantTypesKeepInternalFAPIRefreshCapability(t *testing.T) {
	t.Parallel()
	provider, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationACRs(),
		WithProfile(goidc.ProfileFAPI2, WithProfileValidation()),
		WithClientCredentialsGrant(),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP([]goidc.SignatureAlgorithm{goidc.SigAlgES256}, WithDPoPRequired()),
		WithTokenBindingRequired(),
		WithResourceIndicators([]goidc.ResourceIndicator{"https://api.d0.eu/accounting"}, WithResourceIndicatorsRequired()),
		WithHumanConfidentialBFFAuthorizationAuthority(humanAuthorizationAuthorityProviderStub{}, validHumanAuthorizationProviderOptions()...),
	)
	if err != nil {
		t.Fatalf("construct strict FAPI2 mixed provider: %v", err)
	}
	want := []goidc.GrantType{goidc.GrantClientCredentials, goidc.GrantAuthorizationCode}
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		response := httptest.NewRecorder()
		provider.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		var metadata struct {
			Grants []goidc.GrantType `json:"grant_types_supported"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &metadata) != nil || !slices.Equal(metadata.Grants, want) {
			t.Errorf("%s status=%d grants=%v, want %v", path, response.Code, metadata.Grants, want)
		}
		if !slices.Equal(provider.config.GrantTypes, append(slices.Clone(want), goidc.GrantRefreshToken)) ||
			!provider.config.HumanConfidentialBFFAuthorizationEnabled || provider.config.LegacyRefreshTokenGrantEnabled ||
			provider.config.RefreshTokenManager != nil || provider.config.RefreshTokenFunc != nil {
			t.Fatal("discovery changed strict refresh authority or installed legacy state")
		}
	}
}
