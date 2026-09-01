package token

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
)

const (
	humanAuthorizationCodePrefix = "d0_hac_1_"
	humanRefreshCapabilityPrefix = "d0_hrt_1_"

	humanOrganizationIDClaim     = "https://d0.eu/claims/organization_id"
	humanMembershipIDClaim       = "https://d0.eu/claims/membership_id"
	humanMembershipRevisionClaim = "https://d0.eu/claims/membership_revision"

	humanTokenFormParameterCount = 7
	humanTokenMaximumClientName  = 128
	humanTokenMaximumRedirects   = 16
	humanTokenMaximumScopes      = 32
	humanTokenMaximumKeys        = 16
	humanTokenMaximumRSABits     = 4096
	humanTokenMaximumIDLifetime  = 600
	humanTokenMaximumRefreshLife = 24 * 60 * 60
)

var (
	humanTokenClientIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanTokenScopePattern       = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
	humanTokenJWKKeyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	humanTokenAuthorityIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanTokenHostPattern        = regexp.MustCompile(
		`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`,
	)
	humanTokenPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

type humanTokenIssuancePolicy struct {
	issuer                     string
	accessTokenLifetimeSeconds int
	idTokenLifetimeSeconds     int
	authorityClockSkewSeconds  int64
	scopeIDs                   []string
	authenticationContexts     []string
	resourceIndicatorsEnabled  bool
	resourceIndicators         []string
}

// generateHumanAuthorizationCodeToken keeps the strict human flow entirely
// outside the mutable Grant and Token issuance paths. RedeemAuthorizationCode
// atomically consumes the code before either signature is attempted.
func generateHumanAuthorizationCodeToken(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) (resp response, err error) {
	defer func() {
		if recover() != nil {
			resp = response{}
			err = humanAuthorizationServerError()
		}
	}()

	policy, err := humanTokenPolicy(ctx, client)
	if err != nil {
		return response{}, humanAuthorizationServerError()
	}
	if !validHumanTokenForm(ctx.Request, req, client.ID) {
		return response{}, humanAuthorizationInvalidRequest()
	}

	authority, err := ctx.ClientAssertionAuthority(client)
	if err != nil || !humanTokenAuthorityMatchesClient(authority, client) {
		return response{}, humanAuthorizationServerError()
	}
	authorizationCode, err := goidc.NewHumanAuthorizationCode(req.code)
	if err != nil {
		return response{}, humanAuthorizationInvalidGrant()
	}
	input, err := goidc.NewHumanCodeRedemptionInput(goidc.HumanCodeRedemptionInputConfig{
		AuthorizationCode:        authorizationCode,
		CodeVerifier:             req.codeVerifier,
		RedirectURI:              req.redirectURI,
		ClientID:                 client.ID,
		ClientAssertionAuthority: *authority,
	})
	if err != nil {
		return response{}, humanAuthorizationInvalidGrant()
	}

	decision, err := ctx.HumanRedeemAuthorizationCode(input)
	if err != nil {
		return response{}, humanAuthorizationServerError()
	}
	if decision.Outcome() == goidc.HumanCodeRedemptionOutcomeRejected {
		return response{}, humanAuthorizationInvalidGrant()
	}
	if !slices.Contains(client.RedirectURIs, req.redirectURI) {
		return response{}, humanAuthorizationInvalidGrant()
	}
	now := timeutil.TimestampNow()
	if !validRedeemedHumanAuthorization(decision, client, policy, int64(now)) {
		return response{}, humanAuthorizationServerError()
	}

	scopes := decision.Scopes()
	resources := decision.Resources()
	scope := strings.Join(scopes, " ")
	accessToken, err := issueHumanAccessToken(ctx, policy, humanAccessTokenFacts{
		grantID: decision.GrantID(), subject: decision.Subject(),
		organizationID: decision.OrganizationID(), membershipID: decision.MembershipID(),
		membershipRevision: decision.MembershipRevision(), clientID: decision.ClientID(),
		scopes: scopes, resources: resources,
	}, now)
	if err != nil {
		return response{}, humanAuthorizationServerError()
	}
	refreshCapability, hasRefreshCapability := decision.RefreshToken()
	refreshToken, refreshTokenExpiresIn, err := humanRefreshTokenResponse(
		refreshCapability,
		hasRefreshCapability,
		decision.RefreshTokenExpiresAt(),
		int64(now),
		policy.authorityClockSkewSeconds,
	)
	if err != nil {
		return response{}, humanAuthorizationServerError()
	}

	idClaims := map[string]any{
		goidc.ClaimIssuer:            policy.issuer,
		goidc.ClaimSubject:           decision.Subject(),
		goidc.ClaimAudience:          decision.ClientID(),
		goidc.ClaimIssuedAt:          now,
		goidc.ClaimExpiry:            now + policy.idTokenLifetimeSeconds,
		goidc.ClaimAuthTime:          decision.AuthenticationTime(),
		goidc.ClaimACR:               decision.AuthenticationContext(),
		goidc.ClaimAMR:               decision.AuthenticationMethods(),
		humanOrganizationIDClaim:     decision.OrganizationID(),
		humanMembershipIDClaim:       decision.MembershipID(),
		humanMembershipRevisionClaim: decision.MembershipRevision(),
	}
	addHumanIDTokenNonce(idClaims, decision.Nonce())
	idToken, err := ctx.Sign(
		idClaims,
		goidc.SigAlgPS256,
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil || ctx.Err() != nil {
		return response{}, humanAuthorizationServerError()
	}

	return response{
		AccessToken:           accessToken,
		IDToken:               idToken,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresIn: refreshTokenExpiresIn,
		ExpiresIn:             policy.accessTokenLifetimeSeconds,
		TokenType:             goidc.TokenTypeBearer,
		Scopes:                scope,
		Resources:             goidc.Resources(resources),
		noStore:               true,
	}, nil
}

type humanAccessTokenFacts struct {
	grantID            string
	subject            string
	organizationID     string
	membershipID       string
	membershipRevision int64
	clientID           string
	scopes             []string
	resources          []string
}

func issueHumanAccessToken(
	ctx oidc.Context,
	policy humanTokenIssuancePolicy,
	facts humanAccessTokenFacts,
	now int,
) (string, error) {
	accessTokenID, err := newHumanJWTID()
	if err != nil {
		return "", err
	}
	accessClaims := map[string]any{
		goidc.ClaimTokenID:           accessTokenID,
		goidc.ClaimIssuer:            policy.issuer,
		goidc.ClaimSubject:           facts.subject,
		goidc.ClaimAudience:          facts.resources,
		goidc.ClaimClientID:          facts.clientID,
		goidc.ClaimScope:             strings.Join(facts.scopes, " "),
		goidc.ClaimGrantID:           facts.grantID,
		goidc.ClaimIssuedAt:          now,
		goidc.ClaimExpiry:            now + policy.accessTokenLifetimeSeconds,
		humanOrganizationIDClaim:     facts.organizationID,
		humanMembershipIDClaim:       facts.membershipID,
		humanMembershipRevisionClaim: facts.membershipRevision,
	}
	accessToken, err := ctx.Sign(
		accessClaims,
		goidc.SigAlgPS256,
		(&jose.SignerOptions{}).WithType("at+jwt"),
	)
	if err != nil || ctx.Err() != nil {
		return "", errors.New("strict human access-token signing failed")
	}
	return accessToken, nil
}

func humanRefreshTokenResponse(
	capability goidc.HumanRefreshToken,
	present bool,
	expiresAt int64,
	now int64,
	skew int64,
) (string, int, error) {
	if !validHumanAuthorityClockSkew(skew) {
		return "", 0, errors.New("invalid strict human authority clock skew")
	}
	if !present {
		if capability.Valid() || expiresAt != 0 {
			return "", 0, errors.New("incoherent strict human refresh capability")
		}
		return "", 0, nil
	}
	remaining, validLifetime := humanRefreshTokenRemainingLifetime(expiresAt, now, skew)
	if !capability.Valid() || !validLifetime {
		return "", 0, errors.New("invalid strict human refresh expiry")
	}
	rendered, err := capability.Render()
	if err != nil {
		return "", 0, errors.New("strict human refresh rendering failed")
	}
	return rendered, remaining, nil
}

func humanRefreshTokenRemainingLifetime(expiresAt, now, skew int64) (int, bool) {
	if !validHumanAuthorityClockSkew(skew) || expiresAt < 1 || now < 1 {
		return 0, false
	}
	if expiresAt <= now {
		if skew == 0 || now-expiresAt > skew {
			return 0, false
		}
		return 1, true
	}
	remaining := expiresAt - now
	// Successful decisions already bind the absolute family lifetime to their
	// authority-owned creation time. Clamp only the wire-relative view so a
	// database clock ahead of this process cannot inflate expires_in.
	if remaining > humanTokenMaximumRefreshLife {
		remaining = humanTokenMaximumRefreshLife
	}
	return int(remaining), true
}

func isHumanAuthorizationCode(value string) bool {
	return strings.HasPrefix(value, humanAuthorizationCodePrefix)
}

func isHumanRefreshToken(value string) bool {
	return strings.HasPrefix(value, humanRefreshCapabilityPrefix)
}

func isolateHumanTokenClient(source *goidc.Client) (clone *goidc.Client, returnedErr error) {
	defer func() {
		if recover() != nil {
			clone = nil
			returnedErr = errors.New("strict human client isolation failed")
		}
	}()
	if !validHumanTokenClient(source) {
		return nil, errors.New("strict human client is not qualified")
	}

	detached := *source
	detached.RedirectURIs = slices.Clone(source.RedirectURIs)
	detached.GrantTypes = slices.Clone(source.GrantTypes)
	detached.ResponseTypes = slices.Clone(source.ResponseTypes)
	authority := *source.PrivateKeyJWTAuthority
	authority.Keys = slices.Clone(source.PrivateKeyJWTAuthority.Keys)
	detached.PrivateKeyJWTAuthority = &authority
	if !validHumanTokenClient(&detached) {
		return nil, errors.New("strict human client snapshot is invalid")
	}
	return &detached, nil
}

func validHumanTokenClient(client *goidc.Client) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if client == nil ||
		client.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		!humanTokenClientIDPattern.MatchString(client.ID) || !validHumanTokenClientName(client.Name) ||
		client.ApplicationType != goidc.ApplicationTypeWeb ||
		client.SubIdentifierType != goidc.SubIdentifierPairwise ||
		client.IDTokenSigAlg != goidc.SigAlgPS256 ||
		client.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT ||
		client.TokenAuthnSigAlg != goidc.SigAlgPS256 || !humanTokenClientMetadataIsClosed(client) ||
		len(client.GrantTypes) != 2 || client.GrantTypes[0] != goidc.GrantAuthorizationCode ||
		client.GrantTypes[1] != goidc.GrantRefreshToken ||
		len(client.ResponseTypes) != 1 || client.ResponseTypes[0] != goidc.ResponseTypeCode ||
		!validHumanTokenRedirects(client.RedirectURIs) ||
		!validHumanTokenScopeSet(client.ScopeIDs) {
		return false
	}
	return validHumanTokenPrivateKeyAuthority(client.PrivateKeyJWTAuthority)
}

func validHumanTokenClientName(value string) bool {
	return value == "" || len(value) <= humanTokenMaximumClientName && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func humanTokenClientMetadataIsClosed(client *goidc.Client) bool {
	return client.Secret == "" && client.SecretExpiresAt == 0 && client.RegistrationToken == "" &&
		client.CreatedAt == 0 && client.ExpiresAt == 0 && client.Federation == nil &&
		client.LogoURI == "" && len(client.Contacts) == 0 && client.PolicyURI == "" &&
		client.TermsOfServiceURI == "" && len(client.RequestURIs) == 0 && client.JWKSURI == "" &&
		client.JWKS == nil && client.SignedJWKSURI == "" && client.CachedJWKS() == nil &&
		client.SectorIdentifierURI == "" && client.IDTokenKeyEncAlg == "" &&
		client.IDTokenContentEncAlg == "" && client.UserInfoSigAlg == "" &&
		client.UserInfoKeyEncAlg == "" && client.UserInfoContentEncAlg == "" &&
		!client.JARRequired && client.JARSigAlg == "" && client.JARKeyEncAlg == "" &&
		client.JARContentEncAlg == "" && client.JARMSigAlg == "" && client.JARMKeyEncAlg == "" &&
		client.JARMContentEncAlg == "" && client.TokenIntrospectionAuthnMethod == "" &&
		client.TokenIntrospectionAuthnSigAlg == "" && client.TokenRevocationAuthnMethod == "" &&
		client.TokenRevocationAuthnSigAlg == "" && !client.DPoPTokenBindingRequired &&
		client.TLSSubjectDistinguishedName == "" && client.TLSSubjectAlternativeName == "" &&
		client.TLSSubjectAlternativeNameIP == "" && !client.TLSTokenBindingRequired &&
		len(client.AuthDetailTypes) == 0 && client.DefaultMaxAgeSecs == nil &&
		client.DefaultACRValues == "" && client.CIBATokenDeliveryMode == "" &&
		client.CIBANotificationEndpoint == "" && client.CIBAJARSigAlg == "" &&
		!client.CIBAUserCodeEnabled && len(client.PostLogoutRedirectURIs) == 0 &&
		len(client.ClientRegistrationTypes) == 0 && client.OrganizationName == "" &&
		client.DisplayName == "" && client.Description == "" && len(client.Keywords) == 0 &&
		client.InformationURI == "" && client.OrganizationURI == "" &&
		client.CredentialOfferEndpoint == "" && client.CustomAttributes == nil
}

func validHumanTokenRedirects(redirects []string) bool {
	if len(redirects) < 1 || len(redirects) > humanTokenMaximumRedirects {
		return false
	}
	previous := ""
	var hostname string
	for index, redirect := range redirects {
		if !validHumanTokenAbsoluteHTTPSURI(redirect) || index > 0 && previous >= redirect {
			return false
		}
		parsed, err := url.Parse(redirect)
		if err != nil {
			return false
		}
		if index == 0 {
			hostname = parsed.Hostname()
		} else if parsed.Hostname() != hostname {
			return false
		}
		previous = redirect
	}
	return true
}

func validHumanTokenScopeSet(value string) bool {
	values := strings.Split(value, " ")
	if value == "" || len(values) < 1 || len(values) > humanTokenMaximumScopes {
		return false
	}
	previous := ""
	for index, scope := range values {
		if !humanTokenScopePattern.MatchString(scope) || index > 0 && previous >= scope {
			return false
		}
		previous = scope
	}
	return slices.Contains(values, goidc.ScopeOpenID.ID)
}

func validHumanTokenPrivateKeyAuthority(authority *goidc.PrivateKeyJWTAuthority) bool {
	if authority == nil || authority.SnapshotRevision < 1 || len(authority.Keys) < 1 ||
		len(authority.Keys) > humanTokenMaximumKeys {
		return false
	}
	seenKeyIDs := make(map[string]struct{}, len(authority.Keys))
	seenAuthorityIDs := make(map[string]struct{}, len(authority.Keys))
	seenThumbprints := make(map[string]struct{}, len(authority.Keys))
	previousKeyID := ""
	for index, authorityKey := range authority.Keys {
		key := authorityKey.Key
		publicKey, isRSA := key.Key.(*rsa.PublicKey)
		if !humanTokenAuthorityIDPattern.MatchString(authorityKey.KeyAuthorityID) ||
			!humanTokenJWKKeyIDPattern.MatchString(key.KeyID) ||
			key.Algorithm != string(goidc.SigAlgPS256) || key.Use != string(goidc.KeyUsageSignature) ||
			!key.Valid() || !key.IsPublic() || !isRSA || publicKey == nil || publicKey.N == nil ||
			publicKey.N.Sign() <= 0 || publicKey.N.BitLen() < 2048 ||
			publicKey.N.BitLen() > humanTokenMaximumRSABits || publicKey.N.Bit(0) != 1 ||
			publicKey.E != 65537 || len(key.Certificates) != 0 || key.CertificatesURL != nil ||
			len(key.CertificateThumbprintSHA1) != 0 || len(key.CertificateThumbprintSHA256) != 0 ||
			index > 0 && previousKeyID >= key.KeyID {
			return false
		}
		previousKeyID = key.KeyID
		if _, duplicate := seenKeyIDs[key.KeyID]; duplicate {
			return false
		}
		seenKeyIDs[key.KeyID] = struct{}{}
		if _, duplicate := seenAuthorityIDs[authorityKey.KeyAuthorityID]; duplicate {
			return false
		}
		seenAuthorityIDs[authorityKey.KeyAuthorityID] = struct{}{}
		thumbprint, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return false
		}
		if _, duplicate := seenThumbprints[string(thumbprint)]; duplicate {
			return false
		}
		seenThumbprints[string(thumbprint)] = struct{}{}
	}
	return true
}

func validHumanTokenAbsoluteHTTPSURI(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "*") || !humanTokenASCII(value) {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.String() != value ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() != "" ||
		net.ParseIP(parsed.Hostname()) != nil || !humanTokenHostPattern.MatchString(parsed.Hostname()) ||
		parsed.Hostname() != parsed.Host || !humanTokenPathPattern.MatchString(parsed.Path) ||
		strings.Contains(parsed.Path, "//") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func humanTokenASCII(value string) bool {
	for index := range len(value) {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func humanTokenPolicy(ctx oidc.Context, client *goidc.Client) (humanTokenIssuancePolicy, error) {
	if ctx.Configuration == nil {
		return humanTokenIssuancePolicy{}, errors.New("invalid strict human token configuration")
	}
	authorityClockSkew, validAuthorityClockSkew := oidc.HumanAuthorizationClockSkewSeconds(
		ctx.JWTLeewayTimeSecs,
	)
	if !ctx.HumanConfidentialBFFAuthorizationEnabled ||
		ctx.HumanAuthorizationAuthority == nil || ctx.HumanAccessTokenLifetimeSecs < 1 ||
		ctx.HumanAccessTokenLifetimeSecs > 600 || ctx.IDTokenLifetimeSecs < 1 ||
		ctx.IDTokenLifetimeSecs > humanTokenMaximumIDLifetime || ctx.Issuer() == "" ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) ||
		!slices.Contains(ctx.ResponseTypes, goidc.ResponseTypeCode) ||
		!slices.Contains(ctx.SubIdentifierTypes, goidc.SubIdentifierPairwise) ||
		!slices.Contains(ctx.IDTokenSigAlgs, goidc.SigAlgPS256) ||
		!slices.Contains(ctx.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) ||
		!slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, goidc.SigAlgPS256) ||
		!validAuthorityClockSkew || !validHumanTokenClient(client) {
		return humanTokenIssuancePolicy{}, errors.New("invalid strict human token configuration")
	}

	clientScopeIDs := strings.Split(client.ScopeIDs, " ")
	serverScopeIDs := make([]string, 0, len(clientScopeIDs))
	for _, scopeID := range clientScopeIDs {
		scope, exists := ctx.Scope(scopeID)
		if !exists || scope.ID != scopeID {
			return humanTokenIssuancePolicy{}, errors.New("strict human client scope is unavailable")
		}
		serverScopeIDs = append(serverScopeIDs, scopeID)
	}
	resourceIndicators := make([]string, len(ctx.ResourceIndicators))
	copy(resourceIndicators, ctx.ResourceIndicators)
	authenticationContexts := make([]string, len(ctx.ACRs))
	for index, authenticationContext := range ctx.ACRs {
		authenticationContexts[index] = string(authenticationContext)
	}
	return humanTokenIssuancePolicy{
		issuer:                     ctx.Issuer(),
		accessTokenLifetimeSeconds: ctx.HumanAccessTokenLifetimeSecs,
		idTokenLifetimeSeconds:     ctx.IDTokenLifetimeSecs,
		authorityClockSkewSeconds:  authorityClockSkew,
		scopeIDs:                   serverScopeIDs,
		authenticationContexts:     authenticationContexts,
		resourceIndicatorsEnabled:  ctx.ResourceIndicatorsEnabled,
		resourceIndicators:         resourceIndicators,
	}, nil
}

func humanTokenAuthorityMatchesClient(
	authority *goidc.VerifiedClientAssertionAuthority,
	client *goidc.Client,
) bool {
	if authority == nil || client == nil || client.PrivateKeyJWTAuthority == nil ||
		authority.SnapshotRevision != client.PrivateKeyJWTAuthority.SnapshotRevision ||
		!humanTokenAuthorityIDPattern.MatchString(authority.KeyAuthorityID) {
		return false
	}
	return slices.ContainsFunc(client.PrivateKeyJWTAuthority.Keys, func(key goidc.PrivateKeyJWTAuthorityKey) bool {
		return key.KeyAuthorityID == authority.KeyAuthorityID
	})
}

func validHumanTokenForm(request *http.Request, req request, clientID string) bool {
	if request == nil || request.URL == nil || req.parseErr != nil || request.Method != http.MethodPost ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.TLS != nil && len(request.TLS.PeerCertificates) != 0 ||
		len(request.PostForm) != humanTokenFormParameterCount {
		return false
	}
	for _, header := range []string{
		"Authorization",
		goidc.HeaderDPoP,
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if len(request.Header.Values(header)) != 0 {
			return false
		}
	}
	for name := range request.PostForm {
		if !humanTokenFormParameter(name) || len(request.PostForm[name]) != 1 {
			return false
		}
	}
	return req.grantType == goidc.GrantAuthorizationCode &&
		string(req.grantType) == request.PostFormValue("grant_type") &&
		req.code != "" && req.code == request.PostFormValue("code") &&
		req.redirectURI != "" && req.redirectURI == request.PostFormValue("redirect_uri") &&
		req.codeVerifier != "" && req.codeVerifier == request.PostFormValue("code_verifier") &&
		request.PostFormValue("client_id") == clientID &&
		request.PostFormValue("client_assertion") != "" &&
		request.PostFormValue("client_assertion_type") == string(goidc.AssertionTypeJWTBearer)
}

func humanTokenFormParameter(name string) bool {
	switch name {
	case "grant_type", "code", "redirect_uri", "code_verifier", "client_id",
		"client_assertion", "client_assertion_type":
		return true
	default:
		return false
	}
}

func validHumanRefreshTokenForm(request *http.Request, req request, clientID string) bool {
	const parameterCount = 5
	if request == nil || request.URL == nil || req.parseErr != nil || request.Method != http.MethodPost ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.TLS != nil && len(request.TLS.PeerCertificates) != 0 ||
		len(request.PostForm) != parameterCount {
		return false
	}
	for _, header := range []string{
		"Authorization",
		goidc.HeaderDPoP,
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if len(request.Header.Values(header)) != 0 {
			return false
		}
	}
	for name := range request.PostForm {
		if !humanRefreshTokenFormParameter(name) || len(request.PostForm[name]) != 1 {
			return false
		}
	}
	return req.grantType == goidc.GrantRefreshToken &&
		string(req.grantType) == request.PostFormValue("grant_type") &&
		req.refreshToken != "" && req.refreshToken == request.PostFormValue("refresh_token") &&
		request.PostFormValue("client_id") == clientID &&
		request.PostFormValue("client_assertion") != "" &&
		request.PostFormValue("client_assertion_type") == string(goidc.AssertionTypeJWTBearer)
}

func humanRefreshTokenFormParameter(name string) bool {
	switch name {
	case "grant_type", "refresh_token", "client_id", "client_assertion", "client_assertion_type":
		return true
	default:
		return false
	}
}

func validHumanRefreshRevocationForm(
	request *http.Request,
	req queryRequest,
	clientID string,
) bool {
	const parameterCount = 5
	if request == nil || request.URL == nil || req.parseErr != nil || request.Method != http.MethodPost ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.TLS != nil && len(request.TLS.PeerCertificates) != 0 ||
		len(request.PostForm) != parameterCount {
		return false
	}
	for _, header := range []string{
		"Authorization",
		goidc.HeaderDPoP,
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if len(request.Header.Values(header)) != 0 {
			return false
		}
	}
	for name := range request.PostForm {
		if !humanRefreshRevocationFormParameter(name) || len(request.PostForm[name]) != 1 {
			return false
		}
	}
	return req.token != "" && req.token == request.PostFormValue("token") &&
		req.tokenTypeHint == goidc.TokenHintRefresh &&
		string(req.tokenTypeHint) == request.PostFormValue("token_type_hint") &&
		request.PostFormValue("client_id") == clientID &&
		request.PostFormValue("client_assertion") != "" &&
		request.PostFormValue("client_assertion_type") == string(goidc.AssertionTypeJWTBearer)
}

func humanRefreshRevocationFormParameter(name string) bool {
	switch name {
	case "token", "token_type_hint", "client_id", "client_assertion", "client_assertion_type":
		return true
	default:
		return false
	}
}

func validRedeemedHumanAuthorization(
	decision goidc.HumanCodeRedemptionDecision,
	client *goidc.Client,
	policy humanTokenIssuancePolicy,
	now int64,
) bool {
	if !decision.Valid() || decision.Outcome() != goidc.HumanCodeRedemptionOutcomeRedeemed {
		return false
	}
	scopes := decision.Scopes()
	resources := decision.Resources()
	refreshToken, hasRefreshToken := decision.RefreshToken()
	hasOfflineAccess := slices.Contains(scopes, goidc.ScopeOfflineAccess.ID)
	validRefreshFacts := hasOfflineAccess && hasRefreshToken && refreshToken.Valid() &&
		humanAuthorityTimestampNotExpired(
			decision.RefreshTokenExpiresAt(),
			now,
			policy.authorityClockSkewSeconds,
		) ||
		!hasOfflineAccess && !hasRefreshToken && !refreshToken.Valid() && decision.RefreshTokenExpiresAt() == 0
	return client != nil && decision.ClientID() == client.ID && validRefreshFacts &&
		humanTokenSortedSubset(scopes, strings.Split(client.ScopeIDs, " ")) &&
		humanTokenSortedSubset(scopes, policy.scopeIDs) &&
		len(resources) != 0 && policy.resourceIndicatorsEnabled &&
		humanTokenSortedSubset(resources, policy.resourceIndicators) &&
		slices.Contains(policy.authenticationContexts, decision.AuthenticationContext()) &&
		validHumanAuthorityDecisionWindow(
			decision.CreatedAt(),
			decision.ExpiresAt(),
			now,
			policy.authorityClockSkewSeconds,
		)
}

func validHumanAuthorityDecisionWindow(createdAt, expiresAt, now, skew int64) bool {
	if !validHumanAuthorityClockSkew(skew) || createdAt < 1 || expiresAt <= createdAt || now < 1 {
		return false
	}
	if createdAt > now && createdAt-now > skew {
		return false
	}
	return humanAuthorityTimestampNotExpired(expiresAt, now, skew)
}

func humanAuthorityTimestampNotExpired(expiresAt, now, skew int64) bool {
	if !validHumanAuthorityClockSkew(skew) || expiresAt < 1 || now < 1 {
		return false
	}
	return expiresAt > now || skew > 0 && now-expiresAt <= skew
}

func validHumanAuthorityClockSkew(skew int64) bool {
	return skew >= 0 && skew <= int64(oidc.HumanAuthorizationMaximumClockSkewSeconds)
}

func humanTokenSortedSubset(values, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func addHumanIDTokenNonce(claims map[string]any, nonce string) {
	if nonce != "" {
		claims[goidc.ClaimNonce] = nonce
	}
}

func newHumanJWTID() (string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

func humanAuthorizationInvalidRequest() error {
	return goidc.WrapError(
		goidc.ErrorCodeInvalidRequest,
		"invalid request",
		errors.New("strict human token request is not admitted"),
	)
}

func humanAuthorizationInvalidGrant() error {
	return goidc.WrapError(
		goidc.ErrorCodeInvalidGrant,
		"invalid grant",
		errors.New("human authorization code was not redeemed"),
	)
}

func humanRefreshInvalidGrant() error {
	return goidc.WrapError(
		goidc.ErrorCodeInvalidGrant,
		"invalid grant",
		errors.New("human refresh token was not rotated"),
	)
}

func humanAuthorizationServerError() error {
	return goidc.WrapError(
		goidc.ErrorCodeServerError,
		"server error",
		errors.New("human authorization token issuance failed"),
	)
}
