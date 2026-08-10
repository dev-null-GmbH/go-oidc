package provider

import (
	"errors"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

// DiscoveryEndpoint identifies one standards-defined discovery document.
type DiscoveryEndpoint uint8

const (
	// DiscoveryEndpointOpenIDConfiguration exposes OpenID Provider
	// Configuration at /.well-known/openid-configuration.
	DiscoveryEndpointOpenIDConfiguration DiscoveryEndpoint = iota + 1
	// DiscoveryEndpointAuthorizationServerMetadata exposes OAuth 2.0
	// Authorization Server Metadata at /.well-known/oauth-authorization-server.
	DiscoveryEndpointAuthorizationServerMetadata
)

// WithDiscoveryEndpoints selects the discovery documents exposed by the
// provider. By default both standards-defined endpoints are enabled. At least
// one unique, known endpoint must be selected.
func WithDiscoveryEndpoints(endpoints ...DiscoveryEndpoint) Option {
	return func(provider *Provider) error {
		if len(endpoints) == 0 {
			return errors.New("at least one discovery endpoint is required")
		}

		var openIDEnabled bool
		var authorizationServerEnabled bool
		for _, endpoint := range endpoints {
			switch endpoint {
			case DiscoveryEndpointOpenIDConfiguration:
				if openIDEnabled {
					return errors.New("OpenID configuration discovery endpoint is duplicated")
				}
				openIDEnabled = true
			case DiscoveryEndpointAuthorizationServerMetadata:
				if authorizationServerEnabled {
					return errors.New("authorization server metadata discovery endpoint is duplicated")
				}
				authorizationServerEnabled = true
			default:
				return errors.New("unknown discovery endpoint")
			}
		}

		provider.config.OpenIDConfigurationDisabled = !openIDEnabled
		provider.config.AuthorizationServerMetadataDisabled = !authorizationServerEnabled
		return nil
	}
}

// WithOAuthScopes defines the scopes accepted by an OAuth-only provider
// without implicitly enabling the OpenID scope. The selection must be
// non-empty, contain unique non-empty identifiers, and provide a matcher for
// every scope.
func WithOAuthScopes(scopes ...goidc.Scope) Option {
	return func(provider *Provider) error {
		if len(scopes) == 0 {
			return errors.New("at least one oauth scope is required")
		}

		seen := make(map[string]struct{}, len(scopes))
		for _, scope := range scopes {
			if scope.ID == "" {
				return errors.New("oauth scope identifier cannot be empty")
			}
			if scope.ID == goidc.ScopeOpenID.ID {
				return errors.New("openid scope is not allowed in an oauth-only scope selection")
			}
			if scope.Matches == nil {
				return errors.New("oauth scope matcher cannot be nil")
			}
			if _, ok := seen[scope.ID]; ok {
				return errors.New("oauth scope identifier is duplicated")
			}
			seen[scope.ID] = struct{}{}
		}

		provider.config.Scopes = append([]goidc.Scope(nil), scopes...)
		provider.config.OAuthScopesOnly = true
		return nil
	}
}
