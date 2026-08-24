package goidc

// AuthnSession is a short lived session that holds information about
// authorization requests.
// It can be interacted with so to implement more sophisticated user
// authentication flows.
type AuthnSession struct {
	ID string `json:"id"`
	// PersistenceID is the stable operation identifier assigned when the
	// authentication session is first created. Persistence adapters can use it
	// to correlate retries without overloading ID or Store.
	PersistenceID string `json:"persistence_id,omitempty"`
	Status        Status `json:"status"`
	// Subject is the user identifier.
	//
	// This value must be informed during the authentication flow.
	Subject string `json:"sub"`
	// [RFC 7662 §2.2] Username is a human-readable identifier for the resource owner.
	// When set during the authentication flow, it is propagated to the resulting
	// grant and returned in the introspection response.
	Username string `json:"username,omitempty"`
	ClientID string `json:"client_id"`
	// ClientAssertionAuthority is server-authenticated evidence identifying the
	// authority snapshot and exact public key that authenticated a private_key_jwt
	// assertion for this PAR session. Its values are opaque server metadata and
	// never come from JWT claims or JOSE headers. It is excluded from JSON to
	// prevent protocol disclosure and client-controlled deserialization.
	ClientAssertionAuthority *VerifiedClientAssertionAuthority `json:"-"`
	// PushedAuthReqID is populated when the session is created from a pushed
	// authorization request (PAR). It is the handle returned as request_uri.
	PushedAuthReqID string `json:"pushed_auth_req_id,omitempty"`
	// AuthReqID is populated when the session is created for a CIBA request.
	// It is the handle returned to the client for later token polling or
	// notification correlation.
	AuthReqID string `json:"auth_req_id,omitempty"`
	// DeviceCode is populated when the session is created by the device
	// authorization endpoint. It is later redeemed at the token endpoint.
	DeviceCode string `json:"device_code,omitempty"`
	// UserCode is populated for device authorization flows when a user-facing
	// verification code is issued for manual entry at the verification endpoint.
	UserCode string `json:"user_code,omitempty"`
	// PolicyID is the id of the authentication policy used to authenticate
	// the user.
	PolicyID string `json:"policy_id,omitempty"`

	// GrantedScopes is the scopes the client will be granted access once the
	// access token is generated.
	GrantedScopes string `json:"granted_scopes,omitempty"`
	// GrantedAuthDetails is the authorization details the client will be granted
	// access once the access token is generated.
	GrantedAuthDetails []AuthDetail `json:"granted_authorization_details,omitempty"`
	GrantedResources   Resources    `json:"granted_resources,omitempty"`

	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`
	// ClientCertThumbprint contains the thumbprint of the certificate used by
	// the client to generate the token.
	ClientCertThumbprint string `json:"client_cert_thumbprint,omitempty"`

	// Store allows storing additional information between interactions.
	Store             map[string]any `json:"store,omitempty"`
	ExpiresAt         int            `json:"expires_at"`
	CreatedAt         int            `json:"created_at"`
	IDTokenHintClaims *IDToken       `json:"id_token_hint_claims,omitempty"`
	VCInfo            *struct {
		Issuer           string              `json:"issuer"`
		ConfigurationIDs []VCConfigurationID `json:"configuration_ids"`
	} `json:"vc_info,omitempty"`
	AuthorizationParameters
}
