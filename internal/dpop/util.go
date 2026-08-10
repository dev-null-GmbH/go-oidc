package dpop

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type ValidationOptions struct {
	// AccessToken should be filled when the DPoP "ath" claim is expected and should be validated.
	AccessToken   string
	JWKThumbprint string
	NonceScope    goidc.DPoPNonceScope
	TokenEndpoint bool
}

type Claims struct {
	HTTPMethod      string `json:"htm"`
	HTTPURI         string `json:"htu"`
	AccessTokenHash string `json:"ath"`
	Nonce           string `json:"nonce"`
}

type rawClaims struct {
	IssuedAt json.RawMessage `json:"iat"`
	ID       json.RawMessage `json:"jti"`
}

const (
	maxDPoPJWTIDBytes  = 512
	maxDPoPNonceBytes  = 512
	maxJSONSafeInteger = int64(1<<53 - 1)
)

// JWKThumbprint generates a JWK thumbprint for a valid DPoP JWT.
func JWKThumbprint(dpopJWT string, algs []goidc.SignatureAlgorithm) string {
	// TODO: handle the error
	parsedDPoPJWT, err := jwt.ParseSigned(dpopJWT, algs)
	if err != nil {
		return ""
	}
	jkt, err := parsedDPoPJWT.Headers[0].JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(jkt)
}

// JWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func JWT(ctx oidc.Context) (string, bool) {
	// To access the dpop jwts from the field Header, we need to use the
	// canonical version of the header "DPoP" which is "Dpop".
	dpopJWTs := ctx.Request.Header[http.CanonicalHeaderKey(goidc.HeaderDPoP)]
	if len(dpopJWTs) != 1 {
		return "", false
	}
	return dpopJWTs[0], true
}

// HasJWT reports whether at least one DPoP header field value was supplied. It
// allows callers to distinguish an absent optional proof from an invalid
// multiple-header request.
func HasJWT(ctx oidc.Context) bool {
	return len(ctx.Request.Header[http.CanonicalHeaderKey(goidc.HeaderDPoP)]) != 0
}

func ValidateJWT(ctx oidc.Context, dpopJWT string, opts ValidationOptions) error {
	parsed, err := jwt.ParseSigned(dpopJWT, ctx.DPoPSigAlgs)
	if err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	if len(parsed.Headers) != 1 {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the DPoP proof must contain exactly one JOSE header"))
	}

	if parsed.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the typ header must be dpop+jwt"))
	}

	jwk := parsed.Headers[0].JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the jwk header must contain a valid public key"))
	}

	var claims jwt.Claims
	var dpopClaims Claims
	var raw rawClaims
	if err := parsed.Claims(jwk.Key, &claims, &dpopClaims, &raw); err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	issuedAt, jti, err := validateRawClaims(dpopJWT, raw)
	if err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}
	acceptedUntil, err := reservationExpiry(ctx, issuedAt)
	if err != nil {
		return dpopServerError(err)
	}
	now := timeutil.Now()
	if !now.Before(acceptedUntil) {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeUnauthorizedClient, "unauthorized client",
			errors.New("the DPoP proof issuance time is invalid"))
	}

	if dpopClaims.HTTPMethod != ctx.RequestMethod() {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the htm claim does not match the request method"))
	}

	httpURI, err := normalizeProofHTU(dpopClaims.HTTPURI)
	if err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}
	auds := []string{ctx.BaseURL() + ctx.Request.RequestURI}
	if ctx.MTLSEnabled {
		auds = append(auds, ctx.MTLSBaseURL()+ctx.Request.RequestURI)
	}
	for i, audience := range auds {
		auds[i], err = normalizeRequestHTU(audience)
		if err != nil {
			return dpopServerError(errors.New("the configured DPoP request URI is invalid"))
		}
	}
	if !slices.Contains(auds, httpURI) {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the htu claim does not match the request URI"))
	}

	if opts.AccessToken != "" && dpopClaims.AccessTokenHash != hashutil.Thumbprint(opts.AccessToken) {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the ath claim does not match the access token"))
	}

	if opts.JWKThumbprint != "" && JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs) != opts.JWKThumbprint {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof",
			errors.New("the DPoP key thumbprint does not match the expected binding"))
	}

	if err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(ctx.JWTLeewayTimeSecs)*time.Second); err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}

	var nextNonce string
	if ctx.DPoPNonceManager != nil {
		if opts.NonceScope == "" {
			return dpopServerError(errors.New("a DPoP nonce scope is required when nonce validation is enabled"))
		}
		nextNonce, err = validateNonce(ctx, opts.NonceScope, dpopClaims.Nonce)
		if err != nil {
			return err
		}
	}

	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return invalidProofError(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof", err)
	}
	replayCode, replayDescription := invalidProofCode(opts.TokenEndpoint, goidc.ErrorCodeInvalidRequest, "invalid DPoP proof")
	err = ctx.ReserveJTI(goidc.JTIUse{
		ID:        jti,
		Issuer:    base64.RawURLEncoding.EncodeToString(thumbprint),
		Purpose:   goidc.JTIUsePurposeDPoPProof,
		ExpiresAt: acceptedUntil,
	}, replayCode, replayDescription)
	if err != nil {
		return err
	}
	if nextNonce != "" {
		if err := setNonceHeader(ctx, nextNonce); err != nil {
			return dpopServerError(err)
		}
	}

	return nil
}

func validateRawClaims(dpopJWT string, raw rawClaims) (int64, string, error) {
	parts := strings.Split(dpopJWT, ".")
	if len(parts) != 3 {
		return 0, "", errors.New("the DPoP proof must use compact JWS serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !utf8.Valid(payload) {
		return 0, "", errors.New("the DPoP proof claims must be valid UTF-8 JSON")
	}

	issuedAt, err := integerJSONNumber(raw.IssuedAt)
	if err != nil {
		return 0, "", errors.New("the DPoP proof iat claim must be an integer NumericDate")
	}
	if len(raw.ID) == 0 || !utf8.Valid(raw.ID) || !hasWellFormedJSONSurrogates(raw.ID) {
		return 0, "", errors.New("the DPoP proof jti claim must be a valid UTF-8 string")
	}
	var jti string
	if err := json.Unmarshal(raw.ID, &jti); err != nil || jti == "" {
		return 0, "", errors.New("the DPoP proof jti claim is required and must be a string")
	}
	if !utf8.ValidString(jti) || len(jti) > maxDPoPJWTIDBytes {
		return 0, "", fmt.Errorf("the DPoP proof jti claim must be valid UTF-8 and at most %d bytes", maxDPoPJWTIDBytes)
	}
	return issuedAt, jti, nil
}

func integerJSONNumber(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, errors.New("missing number")
	}
	start := 0
	if raw[0] == '-' {
		start = 1
	}
	if start == len(raw) {
		return 0, errors.New("invalid integer")
	}
	for _, char := range raw[start:] {
		if char < '0' || char > '9' {
			return 0, errors.New("non-integer number")
		}
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || value < -maxJSONSafeInteger || value > maxJSONSafeInteger {
		return 0, errors.New("number is outside the JSON safe integer range")
	}
	return value, nil
}

func hasWellFormedJSONSurrogates(raw json.RawMessage) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	end := len(raw) - 1
	for i := 1; i < end; i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= end {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= end {
			return false
		}
		codeUnit, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		switch {
		case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
			if i+6 >= end || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			lowSurrogate, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || lowSurrogate < 0xdc00 || lowSurrogate > 0xdfff {
				return false
			}
			i += 6
		case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
			return false
		}
	}
	return true
}

func reservationExpiry(ctx oidc.Context, issuedAt int64) (time.Time, error) {
	lifetime := int64(ctx.JWTLifetimeSecs)
	leeway := int64(ctx.JWTLeewayTimeSecs)
	if lifetime < 0 || leeway < 0 || lifetime > math.MaxInt64-leeway {
		return time.Time{}, errors.New("invalid DPoP lifetime configuration")
	}
	validity := lifetime + leeway
	if issuedAt > math.MaxInt64-validity {
		return time.Time{}, errors.New("DPoP reservation expiry overflows NumericDate")
	}
	return time.Unix(issuedAt+validity, 0).UTC(), nil
}

// normalizeProofHTU applies the syntax- and scheme-based URI normalization
// advised by RFC 9449 without accepting a query or fragment in the signed htu
// claim. In particular, /oauth2/token and /oauth2/token/ remain different DPoP
// targets.
func normalizeProofHTU(raw string) (string, error) {
	if strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", errors.New("the DPoP htu claim must not contain a query or fragment")
	}
	return normalizeHTU(raw)
}

// normalizeRequestHTU excludes a request-target query from the URI comparison,
// as required by RFC 9449. Fragments are not sent in HTTP request targets, but
// clearing one here keeps synthetic request contexts deterministic.
func normalizeRequestHTU(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid DPoP target URI")
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return normalizeHTU(parsed.String())
}

func normalizeHTU(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil {
		return "", errors.New("invalid DPoP target URI")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("invalid empty DPoP target URI port")
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", errors.New("invalid DPoP target URI host")
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		parsed.Host = net.JoinHostPort(hostname, port)
	case strings.Contains(hostname, ":"):
		parsed.Host = "[" + hostname + "]"
	default:
		parsed.Host = hostname
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func validateNonce(ctx oidc.Context, scope goidc.DPoPNonceScope, nonce string) (string, error) {
	if scope != goidc.DPoPNonceScopeAuthorizationServer && scope != goidc.DPoPNonceScopeResourceServer {
		return "", dpopServerError(fmt.Errorf("invalid DPoP nonce scope %q", scope))
	}
	if ctx.Response == nil {
		return "", dpopServerError(errors.New("cannot use DPoP nonces without a response writer"))
	}

	if !validNonce(nonce) {
		return "", nonceChallenge(ctx, scope)
	}

	validation, err := ctx.ValidateDPoPNonce(scope, nonce)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return "", nonceChallenge(ctx, scope)
		}
		return "", dpopServerError(err)
	}
	if validation.NextNonce == "" {
		return "", nil
	}
	if !validNonce(validation.NextNonce) {
		return "", dpopServerError(errors.New("DPoP nonce manager returned an invalid next nonce"))
	}
	return validation.NextNonce, nil
}

func nonceChallenge(ctx oidc.Context, scope goidc.DPoPNonceScope) error {
	if _, err := issueNonce(ctx, scope); err != nil {
		return err
	}

	description := "authorization server requires a fresh nonce in the DPoP proof"
	status := http.StatusBadRequest
	if scope == goidc.DPoPNonceScopeResourceServer {
		description = "resource server requires a fresh nonce in the DPoP proof"
		status = http.StatusUnauthorized
		challenge := "DPoP error=" + strconv.Quote(string(goidc.ErrorCodeUseDPoPNonce)) +
			", error_description=" + strconv.Quote(description)
		if len(ctx.DPoPSigAlgs) != 0 {
			algs := make([]string, len(ctx.DPoPSigAlgs))
			for i, alg := range ctx.DPoPSigAlgs {
				algs[i] = string(alg)
			}
			challenge += ", algs=" + strconv.Quote(strings.Join(algs, " "))
		}
		ctx.Response.Header().Add("WWW-Authenticate", challenge)
	}

	return goidc.NewError(goidc.ErrorCodeUseDPoPNonce, description).WithStatusCode(status)
}

func issueNonce(ctx oidc.Context, scope goidc.DPoPNonceScope) (string, error) {
	nonce, err := ctx.IssueDPoPNonce(scope)
	if err != nil {
		return "", dpopServerError(err)
	}
	if err := setNonceHeader(ctx, nonce); err != nil {
		return "", dpopServerError(err)
	}
	return nonce, nil
}

func setNonceHeader(ctx oidc.Context, nonce string) error {
	if !validNonce(nonce) {
		return errors.New("DPoP nonce manager issued an invalid DPoP nonce")
	}
	// Set, rather than Add, guarantees that the response never contains more
	// than one DPoP-Nonce field value as required by RFC 9449 Section 8.
	ctx.Response.Header().Set(goidc.HeaderDPoPNonce, nonce)
	ctx.Response.Header().Set("Cache-Control", "no-store")
	return nil
}

func validNonce(nonce string) bool {
	if nonce == "" || len(nonce) > maxDPoPNonceBytes {
		return false
	}

	for i := range len(nonce) {
		c := nonce[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func invalidProofError(
	tokenEndpoint bool,
	fallbackCode goidc.ErrorCode,
	fallbackDescription string,
	cause error,
) error {
	code, description := invalidProofCode(tokenEndpoint, fallbackCode, fallbackDescription)
	return goidc.WrapError(code, description, cause)
}

func invalidProofCode(
	tokenEndpoint bool,
	fallbackCode goidc.ErrorCode,
	fallbackDescription string,
) (goidc.ErrorCode, string) {
	if tokenEndpoint {
		return goidc.ErrorCodeInvalidDPoPProof, "invalid DPoP proof"
	}
	return fallbackCode, fallbackDescription
}

type dpopInternalError struct {
	cause error
}

func (dpopInternalError) Error() string { return "DPoP state operation failed" }

func (err dpopInternalError) Unwrap() error { return err.cause }

func dpopServerError(cause error) error {
	return goidc.WrapError(
		goidc.ErrorCodeServerError,
		"server error",
		dpopInternalError{cause: cause},
	)
}
