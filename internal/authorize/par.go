package authorize

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/dpop"
	"github.com/dev-null-GmbH/go-oidc/internal/federation"
	"github.com/dev-null-GmbH/go-oidc/internal/hashutil"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/strutil"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func pushAuth(ctx oidc.Context, req request) (parResponse, error) {
	ctx = ctx.BeginPARClientAuthentication()
	var shouldRegisterFedClient bool
	c, err := func() (*goidc.Client, error) {
		if !ctx.OpenIDFedEnabled {
			return client.Authenticated(ctx, client.AuthnContextPAR)
		}

		if !slices.Contains(ctx.OpenIDFedClientRegTypes, goidc.ClientRegistrationTypeAutomatic) {
			return client.Authenticated(ctx, client.AuthnContextPAR)
		}

		id, err := client.ExtractID(ctx)
		if err != nil {
			return nil, err
		}

		if !strutil.IsURL(id) {
			return client.Authenticated(ctx, client.AuthnContextPAR)
		}

		c, err := client.Authenticated(ctx, client.AuthnContextPAR)
		if err != nil {
			if !errors.Is(err, goidc.ErrNotFound) {
				return nil, err
			}
			shouldRegisterFedClient = true
			return federationClientForPAR(ctx, id, req)
		}

		if c.ExpiresAt != 0 && timeutil.TimestampNow() >= c.ExpiresAt {
			shouldRegisterFedClient = true
			return federationClientForPAR(ctx, id, req)
		}

		return c, nil
	}()
	if err != nil {
		return parResponse{}, err
	}
	if err := parRequestContextError(ctx); err != nil {
		return parResponse{}, err
	}
	c, strictHumanAdmission, err := authorizationAdmissionClient(c)
	if err != nil {
		return parResponse{}, err
	}
	if strictHumanAdmission {
		if err := validateHumanConfidentialBFFPushedRequest(ctx, req); err != nil {
			return parResponse{}, err
		}
	}
	clientAssertionAuthority, err := ctx.PARClientAssertionAuthority(c)
	if err != nil {
		return parResponse{}, goidc.WrapError(goidc.ErrorCodeServerError, "server error", err)
	}
	if strictHumanAdmission {
		return pushHumanConfidentialBFFAuthorization(ctx, req, c, clientAssertionAuthority)
	}
	if !ctx.LegacyPAREnabled {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("legacy pushed-request persistence is unavailable"),
		)
	}

	as, err := func() (*goidc.AuthnSession, error) {
		jar := ctx.JAREnabled && (ctx.JARRequired || c.JARRequired || req.RequestObject != "")
		if jar {
			if req.RequestObject == "" {
				return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("request object is required"))
			}

			jar, err := jarFromRequestObject(ctx, req.RequestObject, c, &jarOptions{
				federation: shouldRegisterFedClient,
			})
			if err != nil {
				return nil, err
			}

			if err := validatePushedRequestWithJAR(ctx, req, jar, c); err != nil {
				return nil, err
			}

			return &goidc.AuthnSession{
				ID:                          ctx.AuthnSessionID(),
				PersistenceID:               ctx.AuthnSessionPersistenceID(),
				Status:                      goidc.StatusPending,
				PushedAuthReqID:             ctx.PARID(),
				ClientID:                    c.ID,
				AuthorizationRequestProfile: c.AuthorizationRequestProfile,
				ClientAssertionAuthority:    cloneClientAssertionAuthority(clientAssertionAuthority),
				AuthorizationParameters:     jar.AuthorizationParameters,
				CreatedAt:                   timeutil.TimestampNow(),
				ExpiresAt:                   timeutil.TimestampNow() + ctx.PARLifetimeSecs,
				JWKThumbprint:               dpopThumbprintForPAR(ctx, req),
				ClientCertThumbprint:        tlsThumbprint(ctx),
				Store:                       make(map[string]any),
			}, nil
		}

		if err := validateSimplePushedRequest(ctx, req, c); err != nil {
			return nil, err
		}
		// The exact outer human request admits only client_id and request_uri,
		// so every required authorization parameter must be complete at PAR.
		if strictHumanAdmission {
			if err := validateParams(ctx, req.AuthorizationParameters, c); err != nil {
				return nil, err
			}
		}

		createdAt := timeutil.TimestampNow()
		return &goidc.AuthnSession{
			ID:                          ctx.AuthnSessionID(),
			PersistenceID:               ctx.AuthnSessionPersistenceID(),
			Status:                      goidc.StatusPending,
			PushedAuthReqID:             ctx.PARID(),
			ClientID:                    c.ID,
			AuthorizationRequestProfile: c.AuthorizationRequestProfile,
			ClientAssertionAuthority:    cloneClientAssertionAuthority(clientAssertionAuthority),
			AuthorizationParameters:     req.AuthorizationParameters,
			CreatedAt:                   createdAt,
			ExpiresAt:                   createdAt + ctx.PARLifetimeSecs,
			JWKThumbprint:               dpopThumbprintForPAR(ctx, req),
			ClientCertThumbprint:        tlsThumbprint(ctx),
			Store:                       make(map[string]any),
		}, nil
	}()
	if err != nil {
		return parResponse{}, err
	}
	if strictHumanAdmission {
		if err := validateAuthorizationRequestProfileBinding(ctx, as, c); err != nil {
			return parResponse{}, err
		}
	}
	if err := parRequestContextError(ctx); err != nil {
		return parResponse{}, err
	}
	var strictAuthorizationParameters *goidc.AuthorizationParameters
	if strictHumanAdmission {
		snapshot := cloneHumanConfidentialBFFAuthorizationParameters(as.AuthorizationParameters)
		strictAuthorizationParameters = &snapshot
	}

	callbackClient := c
	callbackSession := as
	if strictHumanAdmission {
		callbackClient, err = isolatedHumanConfidentialBFFCallbackClient(c)
		if err != nil {
			return parResponse{}, err
		}
		callbackSession, err = cloneHumanConfidentialBFFAuthenticationSession(as)
		if err != nil {
			return parResponse{}, goidc.WrapError(goidc.ErrorCodeServerError, "server error", err)
		}
	}
	if err := ctx.PARHandleSession(callbackSession, callbackClient); err != nil {
		var oidcErr goidc.Error
		if errors.As(err, &oidcErr) {
			return parResponse{}, oidcErr
		}
		return parResponse{}, fmt.Errorf("could not handle the pushed authorization request session: %w", err)
	}
	if strictHumanAdmission && !humanConfidentialBFFAuthenticationSessionsEqual(callbackSession, as) {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the PAR session handler modified the strictly admitted session"),
		)
	}
	if strictHumanAdmission && !humanConfidentialBFFAuthorizationParametersEqual(
		as.AuthorizationParameters,
		*strictAuthorizationParameters,
	) {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the PAR session handler modified strictly admitted authorization parameters"),
		)
	}
	if strictHumanAdmission &&
		as.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the PAR session handler modified the authorization request profile binding"),
		)
	}
	if !clientAssertionAuthoritiesEqual(as.ClientAssertionAuthority, clientAssertionAuthority) {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the PAR session handler modified authenticated client assertion authority evidence"),
		)
	}
	// Replace the handler-visible pointer so a retained authority pointer cannot
	// mutate the evidence subsequently passed to persistence.
	as.ClientAssertionAuthority = cloneClientAssertionAuthority(clientAssertionAuthority)
	if strictHumanAdmission {
		as.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileHumanConfidentialBFF
		as.AuthorizationParameters = cloneHumanConfidentialBFFAuthorizationParameters(
			*strictAuthorizationParameters,
		)
	}
	persistedSession := *as
	persistedSession.ClientAssertionAuthority = cloneClientAssertionAuthority(clientAssertionAuthority)
	if strictHumanAdmission {
		persistedSession.AuthorizationRequestProfile = goidc.AuthorizationRequestProfileHumanConfidentialBFF
		persistedSession.AuthorizationParameters = cloneHumanConfidentialBFFAuthorizationParameters(
			*strictAuthorizationParameters,
		)
	}
	if err := parRequestContextError(ctx); err != nil {
		return parResponse{}, err
	}

	if shouldRegisterFedClient {
		if err := ctx.OpenIDFedSaveClient(c); err != nil {
			return parResponse{}, fmt.Errorf("could not save the federated client for the pushed authorization request: %w", err)
		}
	}
	if err := parRequestContextError(ctx); err != nil {
		return parResponse{}, err
	}

	if err := ctx.AuthSaveSession(&persistedSession); err != nil {
		return parResponse{}, fmt.Errorf("could not save the pushed authorization request session: %w", err)
	}

	return parResponse{
		RequestURI: parRequestURIPrefix + persistedSession.PushedAuthReqID,
		ExpiresIn:  ctx.PARLifetimeSecs,
	}, nil
}

func pushHumanConfidentialBFFAuthorization(
	ctx oidc.Context,
	req request,
	c *goidc.Client,
	clientAssertionAuthority *goidc.VerifiedClientAssertionAuthority,
) (parResponse, error) {
	if err := validateSimplePushedRequest(ctx, req, c); err != nil {
		return parResponse{}, err
	}
	if err := validateParams(ctx, req.AuthorizationParameters, c); err != nil {
		return parResponse{}, err
	}
	if !humanConfidentialBFFAtomicPARMatchesCurrentAuthority(
		ctx,
		req.AuthorizationParameters,
		c,
		clientAssertionAuthority,
	) {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the strict pushed request is outside current authorization authority"),
		)
	}

	acrValues := make([]goidc.ACR, 0, 1)
	for value := range strings.FieldsSeq(req.ACRValues) {
		acrValues = append(acrValues, goidc.ACR(value))
	}
	input, err := goidc.NewHumanPARInput(goidc.HumanPARInputConfig{
		ClientID:                 c.ID,
		ClientAssertionAuthority: *clientAssertionAuthority,
		RedirectURI:              req.RedirectURI,
		Scopes:                   strings.Fields(req.Scopes),
		Resources:                slices.Clone(req.Resources),
		State:                    req.State,
		Nonce:                    req.Nonce,
		CodeChallenge:            req.CodeChallenge,
		Prompt:                   req.Prompt,
		MaxAuthenticationAge:     req.MaxAuthnAgeSecs,
		ACRValues:                acrValues,
	})
	if err != nil {
		return parResponse{}, goidc.WrapError(goidc.ErrorCodeServerError, "server error", err)
	}
	if err := parRequestContextError(ctx); err != nil {
		return parResponse{}, err
	}
	decision, err := ctx.HumanStorePAR(input)
	if err != nil {
		return parResponse{}, err
	}
	if !decision.Valid() {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the strict pushed-request authority returned a malformed decision"),
		)
	}
	if decision.Outcome() == goidc.HumanPAROutcomeRejected {
		return parResponse{}, invalidHumanConfidentialBFFRequest("the pushed authorization request was rejected")
	}
	receipt, ok := decision.Receipt()
	if !ok {
		return parResponse{}, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the strict pushed-request authority omitted its committed receipt"),
		)
	}
	requestURI, err := receipt.RequestURI().Render()
	if err != nil {
		return parResponse{}, goidc.WrapError(goidc.ErrorCodeServerError, "server error", err)
	}
	return parResponse{RequestURI: requestURI, ExpiresIn: receipt.ExpiresInSeconds()}, nil
}

func parRequestContextError(ctx oidc.Context) error {
	if err := ctx.Err(); err != nil {
		return goidc.WrapError(goidc.ErrorCodeServerError, "server error", err)
	}
	return nil
}

func cloneClientAssertionAuthority(
	authority *goidc.VerifiedClientAssertionAuthority,
) *goidc.VerifiedClientAssertionAuthority {
	if authority == nil {
		return nil
	}
	clone := *authority
	return &clone
}

func clientAssertionAuthoritiesEqual(
	left *goidc.VerifiedClientAssertionAuthority,
	right *goidc.VerifiedClientAssertionAuthority,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// dpopThumbprintForPAR extracts the DPoP JWK thumbprint from the request.
// The DPoP proof is expected to have been validated before this point.
func dpopThumbprintForPAR(ctx oidc.Context, req request) string {
	if !ctx.DPoPEnabled {
		return ""
	}
	if dpopJWT, ok := dpop.JWT(ctx); ok {
		return dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}
	return req.DPoPJKT
}

func tlsThumbprint(ctx oidc.Context) string {
	if !ctx.MTLSTokenBindingEnabled {
		return ""
	}
	clientCert, err := ctx.ClientCert()
	if err != nil {
		return ""
	}
	return hashutil.Thumbprint(string(clientCert.Raw))
}

func federationClientForPAR(ctx oidc.Context, id string, req request) (*goidc.Client, error) {
	var opts *federation.Options
	if ctx.JAREnabled && req.RequestObject != "" {
		opts = &federation.Options{
			TrustChain: jarTrustChain(req.RequestObject, ctx.JARSigAlgs),
		}
	}

	c, err := federation.Client(ctx, id, opts)
	if err != nil {
		return nil, err
	}

	jwksIsUsed := ctx.JAREnabled && req.RequestObject != ""
	jwksIsUsed = jwksIsUsed || c.TokenAuthnMethod == goidc.AuthnMethodPrivateKeyJWT
	jwksIsUsed = jwksIsUsed || c.TokenAuthnMethod == goidc.AuthnMethodSelfSignedTLS
	if !jwksIsUsed {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied",
			errors.New("automatic federation registration during PAR requires asymmetric client authentication or a signed request object"))
	}

	if !slices.Contains(c.ClientRegistrationTypes, goidc.ClientRegistrationTypeAutomatic) {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("the client is not registered for automatic federation registration"))
	}

	if err := client.Authenticate(ctx, c, client.AuthnContextPAR); err != nil {
		return nil, err
	}

	return c, nil
}
