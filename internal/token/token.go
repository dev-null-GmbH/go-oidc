package token

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/hashutil"
	"github.com/dev-null-GmbH/go-oidc/internal/joseutil"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
)

type IssuanceOptions struct {
	Scopes                    string
	AuthDetails               []goidc.AuthDetail
	Resources                 goidc.Resources
	grantType                 goidc.GrantType
	authenticatedClientID     string
	persistGrantBeforeSigning bool
}

// Issue creates a new access token for the grant and returns the token and its
// serialized value. Newly created client_credentials grants are persisted
// after fallible claim projection and before signing. Opaque tokens are also
// persisted through their configured manager.
func Issue(ctx oidc.Context, grant *goidc.Grant, c *goidc.Client, opts *IssuanceOptions) (*goidc.Token, string, error) {
	if opts == nil {
		opts = &IssuanceOptions{}
	}
	var safeGrantSnapshot accessTokenGrantSnapshot
	if ctx.UsesAccessTokenClaims() {
		if opts.grantType != goidc.GrantClientCredentials || opts.authenticatedClientID == "" ||
			grant == nil || c == nil {
			return nil, "", accessTokenClaimsValidationError(errors.New("invalid access token claims issuance context"))
		}
		safeGrantSnapshot = snapshotAccessTokenGrant(grant)
		if safeGrantSnapshot.clientID != opts.authenticatedClientID ||
			safeGrantSnapshot.subject != opts.authenticatedClientID || c.ID != opts.authenticatedClientID {
			return nil, "", accessTokenClaimsValidationError(errors.New("incoherent authenticated client identity"))
		}
	}

	tknOpts := ctx.TokenOptions(grant, c)
	if ctx.UsesAccessTokenClaims() &&
		(!safeGrantSnapshot.matches(grant) || c.ID != opts.authenticatedClientID) {
		return nil, "", accessTokenClaimsValidationError(errors.New("issuance callback mutated authenticated grant facts"))
	}
	if ctx.UsesAccessTokenClaims() && tknOpts.Format != goidc.TokenFormatJWT {
		return nil, "", accessTokenClaimsValidationError(errors.New("fallible access token claims require JWT tokens"))
	}
	subType := ctx.SubIdentifierTypeDefault
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}

	if !ctx.OpaqueTokenEnabled && tknOpts.Format == goidc.TokenFormatOpaque {
		return nil, "", errors.New("opaque tokens are not enabled")
	}

	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		GrantID:        grant.ID,
		Subject:        grant.Subject,
		ClientID:       grant.ClientID,
		Scopes:         grant.Scopes,
		AuthDetails:    grant.AuthDetails,
		Resources:      grant.Resources,
		JWKThumbprint:  grant.JWKThumbprint,
		CertThumbprint: grant.CertThumbprint,
		Actor:          grant.Actor,
		CreatedAt:      now,
		ExpiresAt:      now + tknOpts.LifetimeSecs,
		Format:         tknOpts.Format,
		SigAlg:         tknOpts.JWTSigAlg,
	}
	if tkn.JWKThumbprint != "" {
		tkn.Type = goidc.TokenTypeDPoP
	} else {
		tkn.Type = goidc.TokenTypeBearer
	}
	if opts.Scopes != "" {
		tkn.Scopes = opts.Scopes
	}
	if ctx.RAREnabled && opts.AuthDetails != nil {
		tkn.AuthDetails = opts.AuthDetails
	}
	if ctx.ResourceIndicatorsEnabled && opts.Resources != nil {
		tkn.Resources = opts.Resources
	}

	var (
		tokenValue string
		claims     map[string]any
	)
	switch tknOpts.Format {
	case goidc.TokenFormatOpaque:
		tkn.ID = ctx.OpaqueTokenValue(grant)
		tokenValue = tkn.ID
	case goidc.TokenFormatJWT:
		tkn.ID = ctx.JWTID()

		sub := tkn.Subject
		if subType == goidc.SubIdentifierPairwise && grant.Subject != grant.ClientID {
			sub = ctx.PairwiseSubject(grant.Subject, c)
		}

		claims = map[string]any{
			goidc.ClaimTokenID:  tkn.ID,
			goidc.ClaimIssuer:   ctx.Issuer(),
			goidc.ClaimSubject:  sub,
			goidc.ClaimScope:    tkn.Scopes,
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   tkn.ExpiresAt,
		}
		if !ctx.AccessTokenGrantIDClaimDisabled {
			claims[goidc.ClaimGrantID] = grant.ID
		}

		if tkn.ClientID != "" {
			claims[goidc.ClaimClientID] = tkn.ClientID
		}

		if tkn.AuthDetails != nil {
			claims[goidc.ClaimAuthDetails] = tkn.AuthDetails
		}

		if tkn.Resources != nil {
			claims[goidc.ClaimAudience] = tkn.Resources
		}

		if tkn.Actor != nil {
			claims[goidc.ClaimAct] = tkn.Actor
		}

		confirmation := make(map[string]string)
		if tkn.JWKThumbprint != "" {
			confirmation["jkt"] = tkn.JWKThumbprint
		}
		if tkn.CertThumbprint != "" {
			confirmation["x5t#S256"] = tkn.CertThumbprint
		}
		if len(confirmation) != 0 {
			claims["cnf"] = confirmation
		}

		if ctx.UsesAccessTokenClaims() {
			additionalClaims, err := projectAccessTokenClaims(
				ctx,
				opts.grantType,
				opts.authenticatedClientID,
				c,
				tkn,
				grant,
				sub,
				claims,
			)
			if err != nil {
				return nil, "", err
			}
			maps.Copy(claims, additionalClaims)
		} else {
			maps.Copy(claims, ctx.TokenClaims(tkn, grant))
			if ctx.AccessTokenGrantIDClaimDisabled {
				delete(claims, goidc.ClaimGrantID)
			}
		}
	}

	if opts.persistGrantBeforeSigning {
		if err := ctx.SaveGrant(grant); err != nil {
			return nil, "", err
		}
	}

	if tkn.Format == goidc.TokenFormatJWT {
		signed, err := ctx.Sign(claims, tkn.SigAlg, (&jose.SignerOptions{}).WithType("at+jwt"))
		if err != nil {
			return nil, "", fmt.Errorf("could not sign the access token: %w", err)
		}
		tokenValue = signed
	}

	if err := ctx.HandleToken(tkn, grant); err != nil {
		return nil, "", err
	}
	if tkn.Format == goidc.TokenFormatOpaque {
		if err := ctx.SaveOpaqueToken(tkn); err != nil {
			return nil, "", err
		}
	}

	return tkn, tokenValue, nil
}

type accessTokenGrantSnapshot struct {
	clientID       string
	subject        string
	scopes         string
	resources      goidc.Resources
	jwkThumbprint  string
	certThumbprint string
}

func snapshotAccessTokenGrant(grant *goidc.Grant) accessTokenGrantSnapshot {
	return accessTokenGrantSnapshot{
		clientID:       grant.ClientID,
		subject:        grant.Subject,
		scopes:         grant.Scopes,
		resources:      slices.Clone(grant.Resources),
		jwkThumbprint:  grant.JWKThumbprint,
		certThumbprint: grant.CertThumbprint,
	}
}

func (snapshot accessTokenGrantSnapshot) matches(grant *goidc.Grant) bool {
	return grant != nil && snapshot.clientID == grant.ClientID && snapshot.subject == grant.Subject &&
		snapshot.scopes == grant.Scopes && slices.Equal(snapshot.resources, grant.Resources) &&
		snapshot.jwkThumbprint == grant.JWKThumbprint && snapshot.certThumbprint == grant.CertThumbprint
}

var accessTokenEngineOwnedClaims = map[string]struct{}{
	goidc.ClaimIssuer:      {},
	goidc.ClaimSubject:     {},
	goidc.ClaimAudience:    {},
	goidc.ClaimExpiry:      {},
	goidc.ClaimNotBefore:   {},
	goidc.ClaimIssuedAt:    {},
	goidc.ClaimTokenID:     {},
	goidc.ClaimClientID:    {},
	goidc.ClaimScope:       {},
	"cnf":                  {},
	goidc.ClaimAct:         {},
	goidc.ClaimAuthDetails: {},
	goidc.ClaimGrantID:     {},
}

func projectAccessTokenClaims(
	ctx oidc.Context,
	grantType goidc.GrantType,
	authenticatedClientID string,
	client *goidc.Client,
	tkn *goidc.Token,
	grant *goidc.Grant,
	serializedSubject string,
	core map[string]any,
) (claims map[string]any, err error) {
	defer func() {
		if recover() != nil {
			claims = nil
			err = accessTokenClaimsValidationError(errors.New("access token claims serialization panicked"))
		}
	}()
	if grantType != goidc.GrantClientCredentials || authenticatedClientID == "" || client == nil ||
		tkn == nil || grant == nil || client.ID != authenticatedClientID ||
		grant.ClientID != authenticatedClientID || tkn.ClientID != authenticatedClientID ||
		grant.Subject != authenticatedClientID || tkn.Subject != authenticatedClientID ||
		serializedSubject != authenticatedClientID || grant.Scopes != tkn.Scopes ||
		!slices.Equal(grant.Resources, tkn.Resources) || grant.JWKThumbprint != tkn.JWKThumbprint ||
		grant.CertThumbprint != tkn.CertThumbprint {
		return nil, accessTokenClaimsValidationError(errors.New("incoherent access token claim input"))
	}
	additional, err := ctx.AccessTokenClaims(goidc.AccessTokenClaimsInput{
		GrantType:                   grantType,
		AuthenticatedClientID:       authenticatedClientID,
		ClientID:                    tkn.ClientID,
		Subject:                     serializedSubject,
		Scopes:                      tkn.Scopes,
		Resources:                   slices.Clone(tkn.Resources),
		Format:                      tkn.Format,
		Type:                        tkn.Type,
		SignatureAlgorithm:          tkn.SigAlg,
		IssuedAt:                    tkn.CreatedAt,
		ExpiresAt:                   tkn.ExpiresAt,
		DPoPJWKThumbprint:           tkn.JWKThumbprint,
		CertificateThumbprint:       tkn.CertThumbprint,
		AuthorizationDetailsPresent: tkn.AuthDetails != nil,
		ActorPresent:                tkn.Actor != nil,
	})
	if err != nil {
		return nil, err
	}
	return validatedAccessTokenClaims(ctx, additional, core)
}

func validatedAccessTokenClaims(
	ctx context.Context,
	additional,
	core map[string]any,
) (cloned map[string]any, err error) {
	defer func() {
		if recover() != nil {
			cloned = nil
			err = accessTokenClaimsValidationError(errors.New("access token claims serialization panicked"))
		}
	}()
	encoded, err := json.Marshal(additional)
	if err != nil {
		return nil, accessTokenClaimsValidationError(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&cloned); err != nil {
		return nil, accessTokenClaimsValidationError(err)
	}
	for claim := range cloned {
		if _, reserved := accessTokenEngineOwnedClaims[claim]; reserved {
			return nil, accessTokenClaimsValidationError(errors.New("access token claim collides with an engine-owned claim"))
		}
		if _, exists := core[claim]; exists {
			return nil, accessTokenClaimsValidationError(errors.New("access token claim collides with a core claim"))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, accessTokenClaimsValidationError(err)
	}
	return cloned, nil
}

func accessTokenClaimsValidationError(cause error) error {
	return goidc.WrapError(
		goidc.ErrorCodeServerError,
		"server error",
		accessTokenClaimsProjectionError{cause: cause},
	)
}

type accessTokenClaimsProjectionError struct {
	cause error
}

func (accessTokenClaimsProjectionError) Error() string { return "access token claims unavailable" }

func (err accessTokenClaimsProjectionError) Unwrap() error { return err.cause }

func MakeIDToken(ctx oidc.Context, c *goidc.Client, opts IDTokenOptions) (string, error) {
	alg := ctx.IDTokenDefaultSigAlg
	if c.IDTokenSigAlg != "" && slices.Contains(ctx.IDTokenSigAlgs, c.IDTokenSigAlg) {
		alg = c.IDTokenSigAlg
	}

	subType := ctx.SubIdentifierTypeDefault
	if c.SubIdentifierType != "" && slices.Contains(ctx.SubIdentifierTypes, c.SubIdentifierType) {
		subType = c.SubIdentifierType
	}

	sub := opts.Subject
	if subType == goidc.SubIdentifierPairwise {
		sub = ctx.PairwiseSubject(opts.Subject, c)
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimSubject:  sub,
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.IDTokenLifetimeSecs,
	}

	// Avoid an empty client ID claim for anonymous clients.
	if c.ID != "" {
		claims[goidc.ClaimAudience] = c.ID
	}

	if alg != goidc.SigAlgNone {
		if opts.AccessToken != "" {
			claims[goidc.ClaimAccessTokenHash] = hashutil.HalfHash(opts.AccessToken, alg)
		}

		if opts.AuthorizationCode != "" {
			claims[goidc.ClaimAuthzCodeHash] = hashutil.HalfHash(opts.AuthorizationCode, alg)
		}

		if opts.State != "" {
			claims[goidc.ClaimStateHash] = hashutil.HalfHash(opts.State, alg)
		}

		if opts.RefreshToken != "" {
			claims[goidc.ClaimRefreshTokenHash] = hashutil.HalfHash(opts.RefreshToken, alg)
		}
	}

	if opts.Nonce != "" {
		claims[goidc.ClaimNonce] = opts.Nonce
	}

	if opts.AuthReqID != "" {
		claims[goidc.ClaimAuthReqID] = opts.AuthReqID
	}

	maps.Copy(claims, opts.Claims)

	idToken, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the id token: %w", err)
	}

	// If encryption is disabled, just return the signed ID token.
	if !ctx.IDTokenEncEnabled || c.IDTokenKeyEncAlg == "" {
		return idToken, nil
	}

	jwk, err := client.JWKByAlg(ctx, c, string(c.IDTokenKeyEncAlg))
	if err != nil {
		return "", fmt.Errorf("could not resolve an encryption key for the id token: %w", err)
	}

	contentEncAlg := ctx.IDTokenContentEncAlgs[0]
	if c.IDTokenContentEncAlg != "" && slices.Contains(ctx.IDTokenContentEncAlgs, c.IDTokenContentEncAlg) {
		contentEncAlg = c.IDTokenContentEncAlg
	}

	encIDToken, err := joseutil.Encrypt(idToken, jwk, contentEncAlg, nil)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the id token: %w", err)
	}
	return encIDToken, nil
}

func generateToken(ctx oidc.Context, req request) (response, error) {
	if !slices.Contains(ctx.GrantTypes, req.grantType) {
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	switch req.grantType {
	case goidc.GrantClientCredentials:
		return generateClientCredentialsToken(ctx, req)
	case goidc.GrantAuthorizationCode:
		return generateAuthCodeToken(ctx, req)
	case goidc.GrantRefreshToken:
		return generateRefreshToken(ctx, req)
	case goidc.GrantJWTBearer:
		return generateJWTBearerToken(ctx, req)
	case goidc.GrantCIBA:
		return generateCIBAToken(ctx, req)
	case goidc.GrantPreAuthorizedCode:
		return generatePreAuthCodeToken(ctx, req)
	case goidc.GrantDeviceCode:
		return generateDeviceCodeToken(ctx, req)
	case goidc.GrantTokenExchange:
		return generateExchangeToken(ctx, req)
	default:
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}
}
