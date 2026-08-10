package discovery

import "github.com/luikyv/go-oidc/pkg/goidc"

// authorizationServerMetadata is the OAuth-focused metadata document exposed
// at the RFC 8414 well-known location. It does not inherit unrelated OpenID
// Provider fields merely because the OpenID document also publishes them.
type authorizationServerMetadata struct {
	Issuer                            string                             `json:"issuer"`
	AuthorizationEndpoint             string                             `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string                             `json:"token_endpoint,omitempty"`
	JWKSEndpoint                      string                             `json:"jwks_uri,omitempty"`
	ClientRegistrationEndpoint        string                             `json:"registration_endpoint,omitempty"`
	Scopes                            []string                           `json:"scopes_supported,omitempty"`
	ResponseTypes                     []goidc.ResponseType               `json:"response_types_supported"`
	ResponseModes                     []goidc.ResponseMode               `json:"response_modes_supported,omitempty"`
	GrantTypes                        []goidc.GrantType                  `json:"grant_types_supported,omitempty"`
	TokenAuthnMethods                 []goidc.AuthnMethod                `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenAuthnSigAlgs                 []goidc.SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	PAREndpoint                       string                             `json:"pushed_authorization_request_endpoint,omitempty"`
	PARRequired                       bool                               `json:"require_pushed_authorization_requests,omitempty"`
	JAREnabled                        bool                               `json:"request_parameter_supported,omitempty"`
	JARRequired                       bool                               `json:"require_signed_request_object,omitempty"`
	JARAlgs                           []goidc.SignatureAlgorithm         `json:"request_object_signing_alg_values_supported,omitempty"`
	JARKeyEncAlgs                     []goidc.KeyEncryptionAlgorithm     `json:"request_object_encryption_alg_values_supported,omitempty"`
	JARContentEncAlgs                 []goidc.ContentEncryptionAlgorithm `json:"request_object_encryption_enc_values_supported,omitempty"`
	JARByReferenceEnabled             bool                               `json:"request_uri_parameter_supported,omitempty"`
	JARRequestURIRegistrationRequired bool                               `json:"require_request_uri_registration,omitempty"`
	JARMAlgs                          []goidc.SignatureAlgorithm         `json:"authorization_signing_alg_values_supported,omitempty"`
	JARMKeyEncAlgs                    []goidc.KeyEncryptionAlgorithm     `json:"authorization_encryption_alg_values_supported,omitempty"`
	JARMContentEncAlgs                []goidc.ContentEncryptionAlgorithm `json:"authorization_encryption_enc_values_supported,omitempty"`
	IssuerResponseParamEnabled        bool                               `json:"authorization_response_iss_parameter_supported,omitempty"`
	AuthDetailTypesSupported          []goidc.AuthDetailType             `json:"authorization_details_types_supported,omitempty"`
	DPoPSigAlgs                       []goidc.SignatureAlgorithm         `json:"dpop_signing_alg_values_supported,omitempty"`
	TokenIntrospectionEndpoint        string                             `json:"introspection_endpoint,omitempty"`
	TokenIntrospectionAuthnMethods    []goidc.AuthnMethod                `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	TokenIntrospectionAuthnSigAlgs    []goidc.SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	TokenRevocationEndpoint           string                             `json:"revocation_endpoint,omitempty"`
	TokenRevocationAuthnMethods       []goidc.AuthnMethod                `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	TokenRevocationAuthnSigAlgs       []goidc.SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	DeviceAuthorizationEndpoint       string                             `json:"device_authorization_endpoint,omitempty"`
	CIBATokenDeliveryModes            []goidc.CIBATokenDeliveryMode      `json:"backchannel_token_delivery_modes_supported,omitempty"`
	CIBAEndpoint                      string                             `json:"backchannel_authentication_endpoint,omitempty"`
	CIBAJARSigAlgs                    []goidc.SignatureAlgorithm         `json:"backchannel_authentication_request_signing_alg_values_supported,omitempty"`
	CIBAUserCodeEnabled               bool                               `json:"backchannel_user_code_parameter_supported,omitempty"`
	MTLSAliases                       *authorizationServerMTLSAliases    `json:"mtls_endpoint_aliases,omitempty"`
	TLSBoundTokensEnabled             bool                               `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	CodeChallengeMethods              []goidc.CodeChallengeMethod        `json:"code_challenge_methods_supported,omitempty"`
}

type authorizationServerMTLSAliases struct {
	TokenEndpoint              string `json:"token_endpoint,omitempty"`
	PAREndpoint                string `json:"pushed_authorization_request_endpoint,omitempty"`
	ClientRegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	TokenIntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	TokenRevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	CIBAEndpoint               string `json:"backchannel_authentication_endpoint,omitempty"`
}
