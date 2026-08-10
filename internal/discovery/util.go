package discovery

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func NewConfiguration(ctx oidc.Context) goidc.Configuration {
	scopes := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopes[i] = scope.ID
	}

	config := goidc.Configuration{
		Issuer:                     ctx.Issuer(),
		AuthorizationEndpoint:      ctx.BaseURL() + ctx.AuthorizationEndpoint,
		TokenEndpoint:              ctx.BaseURL() + ctx.TokenEndpoint,
		JWKSEndpoint:               ctx.BaseURL() + ctx.JWKSEndpoint,
		ResponseTypes:              ctx.ResponseTypes,
		ResponseModes:              ctx.ResponseModes,
		GrantTypes:                 ctx.GrantTypes,
		UserClaimsSupported:        ctx.Claims,
		ClaimTypesSupported:        ctx.ClaimTypes,
		SubIdentifierTypes:         ctx.SubIdentifierTypes,
		IDTokenSigAlgs:             ctx.IDTokenSigAlgs,
		Scopes:                     scopes,
		TokenAuthnMethods:          ctx.AuthnMethods,
		TokenAuthnSigAlgs:          ctx.TokenAuthnSigAlgs(),
		IssuerResponseParamEnabled: ctx.IssuerRespParamEnabled,
		ClaimsParamEnabled:         ctx.ClaimsParamEnabled,
		AuthDetailsEnabled:         ctx.RAREnabled,
		AuthDetailTypesSupported:   ctx.RARDetailTypes,
		ACRs:                       ctx.ACRs,
		DisplayValues:              ctx.DisplayValues,
	}
	if !ctx.UserInfoDisabled {
		config.UserInfoEndpoint = ctx.BaseURL() + ctx.UserInfoEndpoint
		config.UserInfoSigAlgs = ctx.UserInfoSigAlgs
	}

	if ctx.PAREnabled {
		config.PARRequired = ctx.PARRequired
		config.PAREndpoint = ctx.BaseURL() + ctx.PAREndpoint
	}

	if ctx.DCREnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.DCREndpoint
	}

	if ctx.JAREnabled {
		config.JAREnabled = ctx.JAREnabled
		config.JARRequired = ctx.JARRequired
		config.JARAlgs = ctx.JARSigAlgs
		if ctx.JARByReferenceEnabled {
			config.JARByReferenceEnabled = ctx.JARByReferenceEnabled
			config.JARRequestURIRegistrationRequired = !ctx.JARByReferenceUnregisteredURIEnabled
		}
		if ctx.JAREncEnabled {
			config.JARKeyEncAlgs = ctx.JARKeyEncAlgs
			config.JARContentEncAlgs = ctx.JARContentEncAlgs
		}
	}

	if ctx.JARMEnabled {
		config.JARMAlgs = ctx.JARMSigAlgs
		if ctx.JARMEncEnabled {
			config.JARMKeyEncAlgs = ctx.JARMKeyEncAlgs
			config.JARMContentEncAlgs = ctx.JARMContentEncAlgs
		}
	}

	if ctx.DPoPEnabled {
		config.DPoPSigAlgs = ctx.DPoPSigAlgs
	}

	if ctx.TokenIntrospectionEnabled {
		config.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.TokenIntrospectionEndpoint
		config.TokenIntrospectionAuthnMethods = ctx.AuthnMethods
		config.TokenIntrospectionAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.TokenRevocationEnabled {
		config.TokenRevocationEndpoint = ctx.BaseURL() + ctx.TokenRevocationEndpoint
		config.TokenRevocationAuthnMethods = ctx.AuthnMethods
		config.TokenRevocationAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.MTLSEnabled {
		config.TLSBoundTokensEnabled = ctx.MTLSTokenBindingEnabled

		config.MTLSAliases = &struct {
			TokenEndpoint              string `json:"token_endpoint"`
			ParEndpoint                string `json:"pushed_authorization_request_endpoint,omitempty"`
			UserInfoEndpoint           string `json:"userinfo_endpoint,omitempty"`
			ClientRegistrationEndpoint string `json:"registration_endpoint,omitempty"`
			TokenIntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
			TokenRevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
			CIBAEndpoint               string `json:"backchannel_authentication_endpoint,omitempty"`
		}{
			TokenEndpoint: ctx.MTLSBaseURL() + ctx.TokenEndpoint,
		}
		if !ctx.UserInfoDisabled {
			config.MTLSAliases.UserInfoEndpoint = ctx.MTLSBaseURL() + ctx.UserInfoEndpoint
		}

		if ctx.PAREnabled {
			config.MTLSAliases.ParEndpoint = ctx.MTLSBaseURL() + ctx.PAREndpoint
		}

		if ctx.DCREnabled {
			config.MTLSAliases.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.DCREndpoint
		}

		if ctx.TokenIntrospectionEnabled {
			config.MTLSAliases.TokenIntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.TokenIntrospectionEndpoint
		}

		if ctx.TokenRevocationEnabled {
			config.MTLSAliases.TokenRevocationEndpoint = ctx.MTLSBaseURL() + ctx.TokenRevocationEndpoint
		}

		if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
			config.MTLSAliases.CIBAEndpoint = ctx.MTLSBaseURL() + ctx.CIBAEndpoint
		}
	}

	if !ctx.UserInfoDisabled && ctx.UserInfoEncEnabled {
		config.UserInfoKeyEncAlgs = ctx.UserInfoKeyEncAlgs
		config.UserInfoContentEncAlgs = ctx.UserInfoContentEncAlgs
	}

	if ctx.IDTokenEncEnabled {
		config.IDTokenKeyEncAlgs = ctx.IDTokenKeyEncAlgs
		config.IDTokenContentEncAlgs = ctx.IDTokenContentEncAlgs
	}

	if ctx.PKCEEnabled {
		config.CodeChallengeMethods = ctx.PKCEChallengeMethods
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
		config.CIBAEndpoint = ctx.BaseURL() + ctx.CIBAEndpoint
		config.CIBATokenDeliveryModes = ctx.CIBATokenDeliveryModes
		config.CIBAUserCodeEnabled = ctx.CIBAUserCodeEnabled

		if ctx.CIBAJAREnabled {
			config.CIBAJARSigAlgs = ctx.CIBAJARSigAlgs
		}
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantDeviceCode) {
		config.DeviceAuthorizationEndpoint = ctx.BaseURL() + ctx.DeviceAuthEndpoint
	}

	if ctx.LogoutEnabled {
		config.EndSessionEndpoint = ctx.BaseURL() + ctx.LogoutEndpoint
	}

	return config
}

func NewAuthorizationServerMetadata(ctx oidc.Context) authorizationServerMetadata {
	scopes := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopes[i] = scope.ID
	}

	metadata := authorizationServerMetadata{
		Issuer:                     ctx.Issuer(),
		TokenEndpoint:              ctx.BaseURL() + ctx.TokenEndpoint,
		JWKSEndpoint:               ctx.BaseURL() + ctx.JWKSEndpoint,
		Scopes:                     scopes,
		ResponseTypes:              append([]goidc.ResponseType{}, ctx.ResponseTypes...),
		ResponseModes:              ctx.ResponseModes,
		GrantTypes:                 ctx.GrantTypes,
		TokenAuthnMethods:          ctx.AuthnMethods,
		TokenAuthnSigAlgs:          ctx.TokenAuthnSigAlgs(),
		IssuerResponseParamEnabled: ctx.IssuerRespParamEnabled,
	}
	if ctx.RAREnabled {
		metadata.AuthDetailTypesSupported = ctx.RARDetailTypes
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) ||
		slices.Contains(ctx.GrantTypes, goidc.GrantImplicit) {
		metadata.AuthorizationEndpoint = ctx.BaseURL() + ctx.AuthorizationEndpoint
	}
	if ctx.DCREnabled {
		metadata.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.DCREndpoint
	}
	if ctx.PAREnabled {
		metadata.PARRequired = ctx.PARRequired
		metadata.PAREndpoint = ctx.BaseURL() + ctx.PAREndpoint
	}
	if ctx.JAREnabled {
		metadata.JAREnabled = true
		metadata.JARRequired = ctx.JARRequired
		metadata.JARAlgs = ctx.JARSigAlgs
		if ctx.JARByReferenceEnabled {
			metadata.JARByReferenceEnabled = true
			metadata.JARRequestURIRegistrationRequired = !ctx.JARByReferenceUnregisteredURIEnabled
		}
		if ctx.JAREncEnabled {
			metadata.JARKeyEncAlgs = ctx.JARKeyEncAlgs
			metadata.JARContentEncAlgs = ctx.JARContentEncAlgs
		}
	}
	if ctx.JARMEnabled {
		metadata.JARMAlgs = ctx.JARMSigAlgs
		if ctx.JARMEncEnabled {
			metadata.JARMKeyEncAlgs = ctx.JARMKeyEncAlgs
			metadata.JARMContentEncAlgs = ctx.JARMContentEncAlgs
		}
	}
	if ctx.DPoPEnabled {
		metadata.DPoPSigAlgs = ctx.DPoPSigAlgs
	}
	if ctx.TokenIntrospectionEnabled {
		metadata.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.TokenIntrospectionEndpoint
		metadata.TokenIntrospectionAuthnMethods = ctx.AuthnMethods
		metadata.TokenIntrospectionAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}
	if ctx.TokenRevocationEnabled {
		metadata.TokenRevocationEndpoint = ctx.BaseURL() + ctx.TokenRevocationEndpoint
		metadata.TokenRevocationAuthnMethods = ctx.AuthnMethods
		metadata.TokenRevocationAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}
	if slices.Contains(ctx.GrantTypes, goidc.GrantDeviceCode) {
		metadata.DeviceAuthorizationEndpoint = ctx.BaseURL() + ctx.DeviceAuthEndpoint
	}
	if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
		metadata.CIBAEndpoint = ctx.BaseURL() + ctx.CIBAEndpoint
		metadata.CIBATokenDeliveryModes = ctx.CIBATokenDeliveryModes
		metadata.CIBAUserCodeEnabled = ctx.CIBAUserCodeEnabled
		if ctx.CIBAJAREnabled {
			metadata.CIBAJARSigAlgs = ctx.CIBAJARSigAlgs
		}
	}
	if ctx.MTLSEnabled {
		metadata.TLSBoundTokensEnabled = ctx.MTLSTokenBindingEnabled
		metadata.MTLSAliases = &authorizationServerMTLSAliases{
			TokenEndpoint: ctx.MTLSBaseURL() + ctx.TokenEndpoint,
		}
		if ctx.PAREnabled {
			metadata.MTLSAliases.PAREndpoint = ctx.MTLSBaseURL() + ctx.PAREndpoint
		}
		if ctx.DCREnabled {
			metadata.MTLSAliases.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.DCREndpoint
		}
		if ctx.TokenIntrospectionEnabled {
			metadata.MTLSAliases.TokenIntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.TokenIntrospectionEndpoint
		}
		if ctx.TokenRevocationEnabled {
			metadata.MTLSAliases.TokenRevocationEndpoint = ctx.MTLSBaseURL() + ctx.TokenRevocationEndpoint
		}
		if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
			metadata.MTLSAliases.CIBAEndpoint = ctx.MTLSBaseURL() + ctx.CIBAEndpoint
		}
	}
	if ctx.PKCEEnabled {
		metadata.CodeChallengeMethods = ctx.PKCEChallengeMethods
	}

	return metadata
}
