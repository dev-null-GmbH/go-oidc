package goidc

type Client struct {
	ID              string `json:"id"`
	Secret          string `json:"secret,omitempty"`
	SecretExpiresAt int    `json:"secret_expires_at,omitempty"`
	// AuthorizationRequestProfile is a server-owned admission profile for
	// authorization and PAR requests. The zero value preserves the standard
	// protocol behavior. It is deliberately excluded from client metadata JSON
	// so a client cannot opt itself into or out of an authority-selected parser.
	AuthorizationRequestProfile AuthorizationRequestProfile `json:"-"`
	// PrivateKeyJWTAuthority is a server-authority snapshot that binds each
	// private_key_jwt verification key to an opaque, authority-owned identity.
	//
	// When non-nil, its keys are the exclusive source for private_key_jwt
	// verification. An empty or invalid snapshot fails authentication and never
	// falls back to the client JWKS. It is deliberately excluded from client
	// metadata JSON so an OAuth client cannot supply its own authority binding.
	PrivateKeyJWTAuthority *PrivateKeyJWTAuthority `json:"-"`
	// RegistrationToken is the plain text registration access token generated during
	// dynamic client registration.
	// Note: For security reasons, it is strongly recommended to encrypt this value before storing it in a database.
	RegistrationToken string `json:"registration_token,omitempty"`
	CreatedAt         int    `json:"created_at,omitempty"`
	ExpiresAt         int    `json:"expires_at,omitempty"`
	Federation        *struct {
		TrustAnchor string   `json:"trust_anchor"`
		TrustMarks  []string `json:"trust_marks,omitempty"`
	} `json:"federation,omitempty"`
	cachedJWKS *JSONWebKeySet
	ClientMeta
}

// AuthorizationRequestProfile selects server-owned, client-qualified request
// admission behavior. Unknown nonzero values must fail closed at authorization
// and PAR endpoints.
type AuthorizationRequestProfile string

const (
	// AuthorizationRequestProfileDefault preserves the standard authorization
	// and PAR request behavior.
	AuthorizationRequestProfileDefault AuthorizationRequestProfile = ""
	// AuthorizationRequestProfileHumanConfidentialBFF selects the closed
	// human confidential-BFF surface: mandatory simple PAR and an outer
	// authorization request containing only client_id and request_uri.
	AuthorizationRequestProfileHumanConfidentialBFF AuthorizationRequestProfile = "human_confidential_bff"
)

// PrivateKeyJWTAuthority is an immutable snapshot selected by the server's
// client authority. SnapshotRevision must be positive. Keys must contain only
// valid asymmetric public signature keys and must be safe for concurrent reads
// for the duration of a request.
type PrivateKeyJWTAuthority struct {
	SnapshotRevision int64
	Keys             []PrivateKeyJWTAuthorityKey
}

// PrivateKeyJWTAuthorityKey binds an exact public verification key to the
// server authority's opaque identity for that key. KeyAuthorityID is not the
// JOSE kid and is never derived or interpreted by this library. Key must have
// a nonempty, snapshot-unique JOSE kid even though an assertion may omit its
// kid when exactly one authority key matches the asserted algorithm. Public
// key material must also be unique across the authority snapshot.
type PrivateKeyJWTAuthorityKey struct {
	Key            JSONWebKey
	KeyAuthorityID string
}

func (c *Client) IsPublic() bool {
	return c.TokenAuthnMethod == AuthnMethodNone
}

func (c *Client) CachedJWKS() *JSONWebKeySet {
	return c.cachedJWKS
}

func (c *Client) CacheJWKS(jwks *JSONWebKeySet) {
	c.cachedJWKS = jwks
}

type ClientMeta struct {
	Name              string          `json:"client_name,omitempty"`
	ApplicationType   ApplicationType `json:"application_type,omitempty"`
	LogoURI           string          `json:"logo_uri,omitempty"`
	Contacts          []string        `json:"contacts,omitempty"`
	PolicyURI         string          `json:"policy_uri,omitempty"`
	TermsOfServiceURI string          `json:"tos_uri,omitempty"`
	RedirectURIs      []string        `json:"redirect_uris,omitempty"`
	RequestURIs       []string        `json:"request_uris,omitempty"`
	GrantTypes        []GrantType     `json:"grant_types"`
	ResponseTypes     []ResponseType  `json:"response_types"`
	JWKSURI           string          `json:"jwks_uri,omitempty"`
	JWKS              *JSONWebKeySet  `json:"jwks,omitempty"`
	SignedJWKSURI     string          `json:"signed_jwks_uri,omitempty"`
	// ScopeIDs contains the scopes available to the client separated by spaces.
	ScopeIDs                      string                     `json:"scope,omitempty"`
	SubIdentifierType             SubIdentifierType          `json:"subject_type,omitempty"`
	SectorIdentifierURI           string                     `json:"sector_identifier_uri,omitempty"`
	IDTokenSigAlg                 SignatureAlgorithm         `json:"id_token_signed_response_alg,omitempty"`
	IDTokenKeyEncAlg              KeyEncryptionAlgorithm     `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenContentEncAlg          ContentEncryptionAlgorithm `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSigAlg                SignatureAlgorithm         `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoKeyEncAlg             KeyEncryptionAlgorithm     `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoContentEncAlg         ContentEncryptionAlgorithm `json:"userinfo_encrypted_response_enc,omitempty"`
	JARRequired                   bool                       `json:"require_signed_request_object,omitempty"`
	JARSigAlg                     SignatureAlgorithm         `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  KeyEncryptionAlgorithm     `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              ContentEncryptionAlgorithm `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    SignatureAlgorithm         `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 KeyEncryptionAlgorithm     `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             ContentEncryptionAlgorithm `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              AuthnMethod                `json:"token_endpoint_auth_method"`
	TokenAuthnSigAlg              SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg,omitempty"`
	TokenIntrospectionAuthnMethod AuthnMethod                `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    AuthnMethod                `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingRequired      bool                       `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubjectDistinguishedName   string                     `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubjectAlternativeName represents a DNS name.
	TLSSubjectAlternativeName   string                   `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubjectAlternativeNameIP string                   `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingRequired     bool                     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthDetailTypes             []AuthDetailType         `json:"authorization_details_types,omitempty"`
	DefaultMaxAgeSecs           *int                     `json:"default_max_age,omitempty"`
	DefaultACRValues            string                   `json:"default_acr_values,omitempty"`
	PARRequired                 bool                     `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode       CIBATokenDeliveryMode    `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint    string                   `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg               SignatureAlgorithm       `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeEnabled         bool                     `json:"backchannel_user_code_parameter,omitempty"`
	OrganizationName            string                   `json:"organization_name,omitempty"`
	PostLogoutRedirectURIs      []string                 `json:"post_logout_redirect_uris,omitempty"`
	ClientRegistrationTypes     []ClientRegistrationType `json:"client_registration_types,omitempty"`
	DisplayName                 string                   `json:"display_name,omitempty"`
	Description                 string                   `json:"description,omitempty"`
	Keywords                    []string                 `json:"keywords,omitempty"`
	InformationURI              string                   `json:"information_uri,omitempty"`
	OrganizationURI             string                   `json:"organization_uri,omitempty"`
	CredentialOfferEndpoint     string                   `json:"credential_offer_endpoint,omitempty"`
	// CustomAttributes holds any additional dynamic attributes a client may
	// provide during registration.
	// These attributes allow clients to extend their metadata beyond the
	// predefined fields (e.g., client_name, logo_uri).
	// During DCR, any attributes that are not explicitly defined in the struct
	// will be captured here.
	// These additional fields are flattened in the DCR response, meaning
	// they are merged directly into the JSON response alongside standard fields.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}
