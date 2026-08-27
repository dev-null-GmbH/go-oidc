package authorize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/joseutil"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	maxJARResponseByteSize int64 = 1_000_000 // 1 MB.
	maxJARNetworkTimeout         = 30 * time.Second
)

type jarOptions struct {
	federation bool
}

func jarFromRequestURI(ctx oidc.Context, reqURI string, client *goidc.Client) (request, error) {
	return jarFromRequestURIWithNetworkControl(ctx, reqURI, client, jarNetworkControl{})
}

func jarFromRequestURIWithNetworkControl(
	ctx oidc.Context,
	reqURI string,
	client *goidc.Client,
	networkControl jarNetworkControl,
) (request, error) {
	registeredURI, err := registeredJARRequestURI(reqURI, client)
	if err != nil {
		return request{}, err
	}
	httpClient := ctx.JARHTTPClient()
	if httpClient == nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			errors.New("the request_uri HTTP client is not configured"))
	}
	networkTimeout := maxJARNetworkTimeout
	if httpClient.Timeout > 0 && httpClient.Timeout < networkTimeout {
		networkTimeout = httpClient.Timeout
	}
	networkContext, cancelNetwork := context.WithTimeout(ctx, networkTimeout)
	defer cancelNetwork()
	target, err := resolveJARNetworkTarget(networkContext, registeredURI, networkControl)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri", err)
	}

	outboundRequest, err := http.NewRequestWithContext(networkContext, http.MethodGet, registeredURI, nil)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("could not create the request_uri request: %w", err))
	}
	jarHTTPClient, jarTransport, err := newGuardedJARHTTPClient(httpClient, target)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri", err)
	}
	defer jarTransport.CloseIdleConnections()
	resp, err := jarHTTPClient.Do(outboundRequest)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("could not fetch the request object from request_uri: %w", err))
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("request_uri returned HTTP status %d", resp.StatusCode))
	}

	if resp.ContentLength > maxJARResponseByteSize {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("request object exceeds max size of %d bytes", maxJARResponseByteSize),
		)
	}

	reqObject, err := io.ReadAll(io.LimitReader(resp.Body, maxJARResponseByteSize+1))
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("could not read the request object from request_uri: %w", err))
	}

	if int64(len(reqObject)) > maxJARResponseByteSize {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
			fmt.Errorf("request object exceeds max size of %d bytes", maxJARResponseByteSize),
		)
	}

	return jarFromRequestObject(ctx, string(reqObject), client, nil)
}

func registeredJARRequestURI(reqURI string, client *goidc.Client) (string, error) {
	if client == nil {
		return "", invalidJARRequestURI()
	}

	// Select the outbound target from resolved server-side client metadata, not
	// from the authorization request. Exact pre-registration is the allowlist
	// boundary required before an authorization endpoint can make a network call.
	for _, registeredURI := range client.RequestURIs {
		if registeredURI != reqURI {
			continue
		}
		parsed, err := url.Parse(registeredURI)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
			parsed.User != nil || parsed.Opaque != "" {
			return "", invalidJARRequestURI()
		}
		// A fragment may distinguish an exact registered request_uri, but URI
		// fragments are client-side identifiers and must never reach the HTTP
		// request target used to fetch the request object.
		parsed.Fragment = ""
		parsed.RawFragment = ""
		return parsed.String(), nil
	}

	return "", invalidJARRequestURI()
}

func invalidJARRequestURI() error {
	return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request_uri",
		errors.New("request_uri must be an exact pre-registered HTTPS URI without credentials"))
}

func jarFromRequestObject(ctx oidc.Context, reqObject string, c *goidc.Client, opts *jarOptions) (request, error) {
	if opts == nil {
		opts = &jarOptions{}
	}

	if ctx.JAREncEnabled && joseutil.IsJWE(reqObject) {
		contentEncAlgs := ctx.JARContentEncAlgs
		if c.JARContentEncAlg != "" && slices.Contains(ctx.JARContentEncAlgs, c.JARContentEncAlg) {
			contentEncAlgs = []goidc.ContentEncryptionAlgorithm{c.JARContentEncAlg}
		}
		jws, err := ctx.Decrypt(reqObject, ctx.JARKeyEncAlgs, contentEncAlgs)
		if err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject,
				"invalid request object", fmt.Errorf("could not decrypt the encrypted request object: %w", err))
		}
		reqObject = jws
	}

	jarAlgorithms := ctx.JARSigAlgs
	if c.JARSigAlg != "" && slices.Contains(ctx.JARSigAlgs, c.JARSigAlg) {
		jarAlgorithms = []goidc.SignatureAlgorithm{c.JARSigAlg}
	}

	if slices.Contains(ctx.JARSigAlgs, goidc.SigAlgNone) && joseutil.IsUnsignedJWT(reqObject) {
		parsedJWT, err := jwt.ParseSigned(reqObject, jarAlgorithms)
		if err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				fmt.Errorf("could not parse the unsigned request object: %w", err))
		}

		var jarReq request
		if err := parsedJWT.UnsafeClaimsWithoutVerification(&jarReq); err != nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				fmt.Errorf("could not extract claims from the unsigned request object: %w", err))
		}

		return jarReq, nil
	}

	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object", fmt.Errorf("could not parse the request object: %w", err))
	}

	if len(parsedToken.Headers) != 1 {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
			errors.New("the request object must contain exactly one JOSE header"))
	}

	// Verify that the key ID belongs to the client.
	jwk, err := client.JWKMatchingHeader(ctx, c, parsedToken.Headers[0])
	if err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject,
			"invalid request object", fmt.Errorf("could not resolve the client public key for the request object header: %w", err))
	}

	var claims jwt.Claims
	var jarReq request
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject,
			"invalid request object", fmt.Errorf("could not extract claims from the request object: %w", err))
	}

	if ctx.Profile.IsFAPI() {
		if claims.NotBefore == nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'nbf' is required in the request object"))
		}

		if claims.NotBefore.Time().Before(timeutil.Now().Add(-1 * time.Hour)) {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'nbf' is too far in the past"))
		}

		if claims.Expiry == nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'exp' is required in the request object"))
		}

		if claims.Expiry.Time().After(timeutil.Now().Add(1 * time.Hour)) {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'exp' is too far in the future"))
		}
	}

	if opts.federation {
		// [OpenID Fed Connect 1.1 §12.1.1.1] exp and jti are required in
		// request objects for automatic client registration.
		if claims.Expiry == nil {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'exp' is required in the request object"))
		}

		if claims.ID == "" {
			return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
				errors.New("claim 'jti' is missing in the request object"))
		}
	}

	if claims.Subject != "" {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "invalid request object",
			errors.New("claim 'sub' is not allowed in the request object"))
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      c.ID,
		AnyAudience: []string{ctx.Issuer()},
	}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return request{}, goidc.WrapError(goidc.ErrorCodeInvalidRequestObject, "the request object contains invalid claims", err)
	}

	if claims.ID != "" {
		var expiresAt time.Time
		if claims.Expiry != nil {
			expiresAt = claims.Expiry.Time().Add(time.Duration(ctx.JWTLeewayTimeSecs) * time.Second)
		}
		if err := ctx.ReserveJTI(goidc.JTIUse{
			ID:        claims.ID,
			Issuer:    claims.Issuer,
			Purpose:   goidc.JTIUsePurposeRequestObject,
			ExpiresAt: expiresAt,
		}, goidc.ErrorCodeInvalidRequestObject, "invalid request object"); err != nil {
			return request{}, err
		}
	}

	return jarReq, nil
}

// jarTrustChain extracts the trust_chain header or claim from a JAR request object.
// Returns nil if parsing fails or the value is absent/malformed.
func jarTrustChain(reqObject string, sigAlgs []goidc.SignatureAlgorithm) []string {
	parsed, err := jwt.ParseSigned(reqObject, sigAlgs)
	if err != nil || len(parsed.Headers) == 0 {
		return nil
	}

	raw, ok := parsed.Headers[0].ExtraHeaders["trust_chain"]
	if !ok {
		var claims struct {
			TrustChain []string `json:"trust_chain"`
		}
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return nil
		}
		return claims.TrustChain
	}

	items, ok := raw.([]any)
	if !ok {
		return nil
	}

	chain := make([]string, 0, len(items))
	for _, v := range items {
		s, ok := v.(string)
		if !ok {
			return nil
		}
		chain = append(chain, s)
	}

	return chain
}
