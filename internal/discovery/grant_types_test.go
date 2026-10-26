package discovery

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestDiscoveryGrantTypesReflectExecutableRefreshGrant(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		strict, legacy bool
		grants, want   []goidc.GrantType
	}{
		{"strict human capability only", true, false,
			[]goidc.GrantType{goidc.GrantClientCredentials, goidc.GrantAuthorizationCode, goidc.GrantRefreshToken},
			[]goidc.GrantType{goidc.GrantClientCredentials, goidc.GrantAuthorizationCode}},
		{"strict with explicit legacy support", true, true,
			[]goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken},
			[]goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken}},
		{"legacy provider", false, true,
			[]goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken},
			[]goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantRefreshToken}},
		{"machine only", false, false,
			[]goidc.GrantType{goidc.GrantClientCredentials},
			[]goidc.GrantType{goidc.GrantClientCredentials}},
		{"strict without refresh capability", true, false,
			[]goidc.GrantType{goidc.GrantAuthorizationCode},
			[]goidc.GrantType{goidc.GrantAuthorizationCode}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := &oidc.Configuration{
				Host: "https://auth.d0.eu", GrantTypes: slices.Clone(test.grants),
				HumanConfidentialBFFAuthorizationEnabled: test.strict,
				LegacyRefreshTokenGrantEnabled:           test.legacy,
			}
			ctx := oidc.Context{Configuration: config}
			for _, document := range []struct {
				name  string
				value any
			}{
				{"openid", NewConfiguration(ctx)},
				{"oauth", NewAuthorizationServerMetadata(ctx)},
			} {
				encoded, err := json.Marshal(document.value)
				if err != nil {
					t.Fatal(err)
				}
				var metadata struct {
					Grants []goidc.GrantType `json:"grant_types_supported"`
				}
				if json.Unmarshal(encoded, &metadata) != nil || !slices.Equal(metadata.Grants, test.want) {
					t.Errorf("%s advertised grants = %v, want %v", document.name, metadata.Grants, test.want)
				}
			}
			if !slices.Equal(config.GrantTypes, test.grants) ||
				config.HumanConfidentialBFFAuthorizationEnabled != test.strict ||
				config.LegacyRefreshTokenGrantEnabled != test.legacy {
				t.Fatal("discovery changed executable grant capabilities")
			}
		})
	}
}
