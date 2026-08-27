package authorize

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/joseutil"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/strutil"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func redirectError(ctx oidc.Context, err error, c *goidc.Client) error {
	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		return err
	}

	ctx.HandleError(err)

	redirectParams := response{
		errorCode:        redirectErr.Code(),
		errorDescription: redirectErr.Description(),
		state:            redirectErr.State,
		errorURI:         ctx.ErrorURI,
	}
	return redirectResponse(
		ctx,
		c,
		redirectErr.AuthorizationParameters,
		redirectParams,
	)
}

func redirectResponse(ctx oidc.Context, c *goidc.Client, params goidc.AuthorizationParameters, redirectParams response) error {
	redirectURI, err := currentAuthorizationRedirectURI(c, params.RedirectURI)
	if err != nil {
		return err
	}

	if ctx.IssuerRespParamEnabled {
		redirectParams.issuer = ctx.Issuer()
	}

	// [OAuth 2.0 Multiple Response Type Encoding Practices §5] Find the response mode based on the response type.
	responseMode := func() goidc.ResponseMode {
		if params.ResponseMode == "" {
			if params.ResponseType.IsImplicit() {
				return goidc.ResponseModeFragment
			}
			return goidc.ResponseModeQuery
		}
		if params.ResponseMode == goidc.ResponseModeJWT {
			if params.ResponseType.IsImplicit() {
				return goidc.ResponseModeFragmentJWT
			}
			return goidc.ResponseModeQueryJWT
		}
		return params.ResponseMode
	}()
	if responseMode.IsJARM() || c.JARMSigAlg != "" {
		responseJWT, err := createJARMResponse(ctx, c, redirectParams)
		if err != nil {
			return err
		}
		redirectParams.response = responseJWT
	}

	redirectParamsMap := redirectParams.parameters()
	switch responseMode {
	case goidc.ResponseModeFragment, goidc.ResponseModeFragmentJWT:
		redirectURL := strutil.URLWithFragmentParams(redirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	case goidc.ResponseModeFormPost, goidc.ResponseModeFormPostJWT:
		redirectParamsMap["redirect_uri"] = redirectURI
		if err := ctx.WriteHTML(formPostResponseTemplate, redirectParamsMap); err != nil {
			return fmt.Errorf("could not render the html for the form_post response mode: %w", err)
		}
	case goidc.ResponseModeJSON, goidc.ResponseModeJSONJWT:
		if err := ctx.Write(redirectParamsMap, http.StatusOK); err != nil {
			return fmt.Errorf("could not write the json response: %w", err)
		}
	default:
		redirectURL := strutil.URLWithQueryParams(redirectURI, redirectParamsMap)
		ctx.Redirect(redirectURL)
	}

	return nil
}

// currentAuthorizationRedirectURI selects the redirect destination from the
// current server-owned client registration. Native loopback redirects are
// reconstructed from the registered URI and the request's validated numeric
// port, as required by RFC 8252, rather than returning the request value.
func currentAuthorizationRedirectURI(c *goidc.Client, requested string) (string, error) {
	if c == nil || requested == "" {
		return "", invalidCurrentAuthorizationRedirectURI()
	}

	for _, registered := range c.RedirectURIs {
		if registered == requested {
			return registered, nil
		}
	}

	if c.ApplicationType != goidc.ApplicationTypeNative {
		return "", invalidCurrentAuthorizationRedirectURI()
	}

	requestedURL, err := url.ParseRequestURI(requested)
	if err != nil || requestedURL.Scheme == "" || requestedURL.Host == "" {
		return "", invalidCurrentAuthorizationRedirectURI()
	}
	requestedIP := net.ParseIP(requestedURL.Hostname())
	if requestedIP == nil || !requestedIP.IsLoopback() {
		return "", invalidCurrentAuthorizationRedirectURI()
	}
	port, err := strconv.ParseUint(requestedURL.Port(), 10, 16)
	if err != nil {
		return "", invalidCurrentAuthorizationRedirectURI()
	}

	normalizedRequestedURL := *requestedURL
	normalizedRequestedURL.Host = requestedURL.Hostname()
	if requestedURL.Hostname() == "::1" {
		normalizedRequestedURL.Host = "[::1]"
	}

	for _, registered := range c.RedirectURIs {
		if registered != normalizedRequestedURL.String() {
			continue
		}

		registeredURL, parseErr := url.ParseRequestURI(registered)
		if parseErr != nil || registeredURL.Host == "" {
			return "", invalidCurrentAuthorizationRedirectURI()
		}
		registeredURL.Host = net.JoinHostPort(registeredURL.Hostname(), strconv.FormatUint(port, 10))
		return registeredURL.String(), nil
	}

	return "", invalidCurrentAuthorizationRedirectURI()
}

func invalidCurrentAuthorizationRedirectURI() error {
	return goidc.WrapError(
		goidc.ErrorCodeServerError,
		"server error",
		errors.New("redirect_uri is not registered for the current client"),
	)
}

func createJARMResponse(ctx oidc.Context, c *goidc.Client, redirectParams response) (string, error) {
	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: c.ID,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.JARMLifetimeSecs,
	}
	for k, v := range redirectParams.parameters() {
		claims[k] = v
	}

	alg := ctx.JARMSigAlgDefault
	if slices.Contains(ctx.JARMSigAlgs, c.JARMSigAlg) && c.JARMSigAlg != "" {
		alg = c.JARMSigAlg
	}
	responseJWT, err := ctx.Sign(claims, alg, nil)
	if err != nil {
		return "", fmt.Errorf("could not sign the response object: %w", err)
	}

	if !ctx.JARMEncEnabled || c.JARMKeyEncAlg == "" || !slices.Contains(ctx.JARMKeyEncAlgs, c.JARMKeyEncAlg) {
		return responseJWT, nil
	}

	jwk, err := client.JWKByAlg(ctx, c, string(c.JARMKeyEncAlg))
	if err != nil {
		return "", goidc.WrapError(goidc.ErrorCodeInvalidRequest,
			"could not fetch the client encryption jwk for jarm", err)
	}

	contentEncAlg := ctx.JARMContentEncAlgs[0]
	if slices.Contains(ctx.JARMContentEncAlgs, c.JARMContentEncAlg) && c.JARMContentEncAlg != "" {
		contentEncAlg = c.JARMContentEncAlg
	}
	responseJWE, err := joseutil.Encrypt(responseJWT, jwk, contentEncAlg, nil)
	if err != nil {
		return "", fmt.Errorf("could not encrypt the response object: %w", err)
	}

	return responseJWE, nil
}
