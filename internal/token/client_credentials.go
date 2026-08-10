package token

import (
	"errors"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateClientCredentialsToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}
	authenticatedClientID := c.ID

	if !slices.Contains(c.GrantTypes, goidc.GrantClientCredentials) {
		return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the client is not allowed to use the client_credentials grant type"))
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	if ctx.ResourceIndicatorsEnabled && ctx.ResourceIndicatorsRequired && req.resources == nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidTarget, "invalid target",
			errors.New("the resource parameter is required"))
	}

	if err := validateResources(ctx, req, nil); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	scopes := []string{}
	for s := range strings.SplitSeq(req.scopes, " ") {
		if s != goidc.ScopeOpenID.ID {
			scopes = append(scopes, s)
		}
	}

	grantOptions := GrantOptions{
		Type:                 goidc.GrantClientCredentials,
		Subject:              c.ID,
		ClientID:             c.ID,
		Scopes:               strings.Join(scopes, " "),
		AuthDetails:          req.authDetails,
		Resources:            req.resources,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}
	var grant *goidc.Grant
	if ctx.UsesAccessTokenClaims() {
		grant, err = newGrant(ctx, c, grantOptions)
	} else {
		grant, err = NewGrant(ctx, c, grantOptions)
	}
	if err != nil {
		return response{}, err
	}

	var issuanceOptions *IssuanceOptions
	if ctx.UsesAccessTokenClaims() {
		issuanceOptions = &IssuanceOptions{
			grantType:                 goidc.GrantClientCredentials,
			authenticatedClientID:     authenticatedClientID,
			persistGrantBeforeSigning: true,
		}
	}
	tkn, tokenValue, err := Issue(ctx, grant, c, issuanceOptions)
	if err != nil {
		return response{}, err
	}

	return response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
		Scopes:               tkn.Scopes,
	}, nil
}
