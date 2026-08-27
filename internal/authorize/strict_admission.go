package authorize

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	maxHumanConfidentialBFFClientRedirects = 16
	maxHumanConfidentialBFFClientKeys      = 16
	maxHumanConfidentialBFFScopes          = 32
	maxHumanConfidentialBFFResources       = 8
	maxHumanConfidentialBFFOpaqueBytes     = 512
	maxHumanConfidentialBFFURIBytes        = 512
	maxHumanConfidentialBFFMaxAge          = 86400
	maxHumanConfidentialBFFCloneDepth      = 64
	maxHumanConfidentialBFFCloneNodes      = 16_384
	maxHumanConfidentialBFFCloneElements   = 4_096
	maxHumanConfidentialBFFCloneBytes      = 1 << 20
	maxHumanConfidentialBFFClientNameBytes = 128
	maxHumanConfidentialBFFRSAModulusBits  = 4_096
)

var (
	humanConfidentialBFFClientIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanConfidentialBFFSessionIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$`)
	humanConfidentialBFFPolicyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanConfidentialBFFScopePattern          = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
	humanConfidentialBFFJWKKeyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	humanConfidentialBFFKeyAuthorityIDPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`,
	)
	humanConfidentialBFFAssurancePattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`,
	)
	humanConfidentialBFFHostPattern = regexp.MustCompile(
		`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`,
	)
	humanConfidentialBFFPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	goidcClientReflectType          = reflect.TypeOf(goidc.Client{})
)

// authorizationAdmissionClient captures the server-owned request profile once
// and isolates it from callbacks that receive the client later in the request.
// The default path returns the original pointer to preserve legacy behavior.
func authorizationAdmissionClient(c *goidc.Client) (*goidc.Client, bool, error) {
	if c == nil {
		return nil, false, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("authorization request admission received a nil client"),
		)
	}

	switch c.AuthorizationRequestProfile {
	case goidc.AuthorizationRequestProfileDefault:
		return c, false, nil
	case goidc.AuthorizationRequestProfileHumanConfidentialBFF:
		if !validHumanConfidentialBFFClient(c) {
			return nil, false, goidc.WrapError(
				goidc.ErrorCodeServerError,
				"server error",
				errors.New("the human confidential-BFF client authority is misconfigured"),
			)
		}
		clone, err := cloneHumanConfidentialBFFClient(c)
		if err != nil {
			return nil, false, goidc.WrapError(
				goidc.ErrorCodeServerError,
				"server error",
				errors.New("the human confidential-BFF client authority could not be isolated"),
			)
		}
		return clone, true, nil
	default:
		return nil, false, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the client has an unsupported authorization request profile"),
		)
	}
}

func validateHumanConfidentialBFFOuterRequest(ctx oidc.Context, req request) error {
	if !ctx.PAREnabled {
		return invalidHumanConfidentialBFFRequest("pushed authorization requests are unavailable")
	}
	if ctx.Request == nil {
		return invalidHumanConfidentialBFFRequest("authorization request transport is unavailable")
	}
	switch ctx.Request.Method {
	case http.MethodGet:
		if ctx.Request.ContentLength != 0 || len(ctx.Request.TransferEncoding) != 0 {
			return invalidHumanConfidentialBFFRequest("GET authorization requests must use the query transport only")
		}
	case http.MethodPost:
		if ctx.Request.URL.RawQuery != "" || ctx.MediaType() != "application/x-www-form-urlencoded" ||
			len(ctx.Request.Header.Values("Content-Type")) != 1 {
			return invalidHumanConfidentialBFFRequest("POST authorization requests must use one form transport only")
		}
	default:
		return invalidHumanConfidentialBFFRequest("authorization request method is unsupported")
	}

	transport := req.AdmissionTransport
	if transport == nil || transport.parseErr != nil {
		return invalidHumanConfidentialBFFRequest("the authorization request transport could not be parsed exactly")
	}
	parameters := transport.parameters
	if len(parameters) != 2 ||
		len(parameters["client_id"]) != 1 || len(parameters["request_uri"]) != 1 ||
		parameters["client_id"][0] != req.ClientID || parameters["request_uri"][0] != req.RequestURI {
		return invalidHumanConfidentialBFFRequest("the outer authorization request must contain exactly one client_id and one request_uri")
	}
	if !strings.HasPrefix(req.RequestURI, parRequestURIPrefix) ||
		!humanConfidentialBFFSessionIDPattern.MatchString(
			strings.TrimPrefix(req.RequestURI, parRequestURIPrefix),
		) {
		return invalidHumanConfidentialBFFRequest("request_uri must identify a pushed authorization request")
	}
	return nil
}

func validateHumanConfidentialBFFPushedRequest(ctx oidc.Context, req request) error {
	if !ctx.PAREnabled {
		return invalidHumanConfidentialBFFRequest("pushed authorization requests are unavailable")
	}
	if req.RequestObject != "" {
		return invalidHumanConfidentialBFFRequest("request objects are not admitted during pushed authorization")
	}
	if ctx.Request == nil || ctx.Request.Method != http.MethodPost || ctx.Request.URL.RawQuery != "" ||
		ctx.MediaType() != "application/x-www-form-urlencoded" ||
		len(ctx.Request.Header.Values("Content-Type")) != 1 {
		return invalidHumanConfidentialBFFRequest("pushed authorization requests must use one form body transport")
	}
	for _, header := range []string{
		"Authorization",
		"DPoP",
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if len(ctx.Request.Header.Values(header)) != 0 {
			return invalidHumanConfidentialBFFRequest("alternate client authentication headers are not admitted")
		}
	}

	transport := req.AdmissionTransport
	if transport == nil || transport.parseErr != nil || len(transport.parameters) == 0 {
		return invalidHumanConfidentialBFFRequest("the pushed authorization request form is invalid")
	}
	for name, values := range transport.parameters {
		if !humanConfidentialBFFPARParameter(name) {
			return invalidHumanConfidentialBFFRequest("the pushed authorization request form is not within the closed parameter surface")
		}
		if name == "resource" {
			if !validHumanConfidentialBFFResources(values) {
				return invalidHumanConfidentialBFFRequest("the pushed authorization request resource parameters are invalid")
			}
			continue
		}
		if len(values) != 1 {
			return invalidHumanConfidentialBFFRequest("the pushed authorization request contains a duplicate parameter")
		}
	}
	if !completeHumanConfidentialBFFAuthorizationParameters(req) {
		return invalidHumanConfidentialBFFRequest("the pushed authorization request is not a complete human authorization request")
	}
	if rawMaxAge, present := transport.parameters["max_age"]; present &&
		!validHumanConfidentialBFFMaxAge(rawMaxAge[0], req.MaxAuthnAgeSecs) {
		return invalidHumanConfidentialBFFRequest("the pushed authorization request max_age is invalid")
	}
	return nil
}

func validHumanConfidentialBFFClient(c *goidc.Client) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if c == nil || !humanConfidentialBFFClientIDPattern.MatchString(c.ID) ||
		!validHumanConfidentialBFFClientName(c.Name) ||
		c.ApplicationType != goidc.ApplicationTypeWeb ||
		c.SubIdentifierType != goidc.SubIdentifierPairwise ||
		c.IDTokenSigAlg != goidc.SigAlgPS256 ||
		c.TokenAuthnMethod != goidc.AuthnMethodPrivateKeyJWT ||
		c.TokenAuthnSigAlg != goidc.SigAlgPS256 ||
		!humanConfidentialBFFClientMetadataIsClosed(c) ||
		len(c.GrantTypes) != 2 || c.GrantTypes[0] != goidc.GrantAuthorizationCode ||
		c.GrantTypes[1] != goidc.GrantRefreshToken ||
		len(c.ResponseTypes) != 1 || c.ResponseTypes[0] != goidc.ResponseTypeCode ||
		!validHumanConfidentialBFFSortedSet(
			c.RedirectURIs,
			1,
			maxHumanConfidentialBFFClientRedirects,
			validHumanConfidentialBFFAbsoluteHTTPSURI,
		) || !humanConfidentialBFFRedirectsShareHost(c.RedirectURIs) ||
		!validHumanConfidentialBFFCanonicalSpaceSet(
			c.ScopeIDs,
			1,
			maxHumanConfidentialBFFScopes,
			humanConfidentialBFFScopePattern.MatchString,
		) || !strings.Contains(" "+c.ScopeIDs+" ", " "+goidc.ScopeOpenID.ID+" ") {
		return false
	}
	return validHumanConfidentialBFFPrivateKeyAuthority(c.PrivateKeyJWTAuthority)
}

func validHumanConfidentialBFFClientName(value string) bool {
	return value == "" || len(value) <= maxHumanConfidentialBFFClientNameBytes &&
		utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsRune(value, '\x00')
}

func humanConfidentialBFFClientMetadataIsClosed(c *goidc.Client) bool {
	return c.Secret == "" && c.SecretExpiresAt == 0 && c.RegistrationToken == "" &&
		c.CreatedAt == 0 && c.ExpiresAt == 0 && c.Federation == nil &&
		c.LogoURI == "" && len(c.Contacts) == 0 && c.PolicyURI == "" &&
		c.TermsOfServiceURI == "" && len(c.RequestURIs) == 0 && c.JWKSURI == "" &&
		c.JWKS == nil && c.SignedJWKSURI == "" && c.CachedJWKS() == nil &&
		c.SectorIdentifierURI == "" && c.IDTokenKeyEncAlg == "" &&
		c.IDTokenContentEncAlg == "" && c.UserInfoSigAlg == "" &&
		c.UserInfoKeyEncAlg == "" && c.UserInfoContentEncAlg == "" &&
		!c.JARRequired && c.JARSigAlg == "" && c.JARKeyEncAlg == "" &&
		c.JARContentEncAlg == "" && c.JARMSigAlg == "" && c.JARMKeyEncAlg == "" &&
		c.JARMContentEncAlg == "" && c.TokenIntrospectionAuthnMethod == "" &&
		c.TokenIntrospectionAuthnSigAlg == "" && c.TokenRevocationAuthnMethod == "" &&
		c.TokenRevocationAuthnSigAlg == "" && !c.DPoPTokenBindingRequired &&
		c.TLSSubjectDistinguishedName == "" && c.TLSSubjectAlternativeName == "" &&
		c.TLSSubjectAlternativeNameIP == "" && !c.TLSTokenBindingRequired &&
		len(c.AuthDetailTypes) == 0 && c.DefaultMaxAgeSecs == nil &&
		c.DefaultACRValues == "" && c.CIBATokenDeliveryMode == "" &&
		c.CIBANotificationEndpoint == "" && c.CIBAJARSigAlg == "" &&
		!c.CIBAUserCodeEnabled && len(c.PostLogoutRedirectURIs) == 0 &&
		len(c.ClientRegistrationTypes) == 0 && c.OrganizationName == "" &&
		c.DisplayName == "" && c.Description == "" && len(c.Keywords) == 0 &&
		c.InformationURI == "" && c.OrganizationURI == "" &&
		c.CredentialOfferEndpoint == "" && c.CustomAttributes == nil
}

func humanConfidentialBFFRedirectsShareHost(redirects []string) bool {
	if len(redirects) == 0 {
		return false
	}
	first, err := url.Parse(redirects[0])
	if err != nil {
		return false
	}
	for _, redirect := range redirects[1:] {
		parsed, parseErr := url.Parse(redirect)
		if parseErr != nil || parsed.Hostname() != first.Hostname() {
			return false
		}
	}
	return true
}

func validHumanConfidentialBFFPrivateKeyAuthority(
	authority *goidc.PrivateKeyJWTAuthority,
) bool {
	if authority == nil || authority.SnapshotRevision < 1 || len(authority.Keys) == 0 ||
		len(authority.Keys) > maxHumanConfidentialBFFClientKeys {
		return false
	}
	seenKeyIDs := make(map[string]struct{}, len(authority.Keys))
	seenAuthorityIDs := make(map[string]struct{}, len(authority.Keys))
	seenThumbprints := make(map[string]struct{}, len(authority.Keys))
	previousKeyID := ""
	for index, authorityKey := range authority.Keys {
		key := authorityKey.Key
		publicKey, rsaPublic := key.Key.(*rsa.PublicKey)
		if !humanConfidentialBFFKeyAuthorityIDPattern.MatchString(authorityKey.KeyAuthorityID) ||
			!humanConfidentialBFFJWKKeyIDPattern.MatchString(key.KeyID) ||
			key.Algorithm != string(goidc.SigAlgPS256) ||
			key.Use != string(goidc.KeyUsageSignature) || !key.Valid() || !key.IsPublic() ||
			!rsaPublic || publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 ||
			publicKey.N.BitLen() < 2048 ||
			publicKey.N.BitLen() > maxHumanConfidentialBFFRSAModulusBits ||
			publicKey.N.Bit(0) != 1 || publicKey.E != 65537 ||
			len(key.Certificates) != 0 || key.CertificatesURL != nil ||
			len(key.CertificateThumbprintSHA1) != 0 ||
			len(key.CertificateThumbprintSHA256) != 0 ||
			(index > 0 && previousKeyID >= key.KeyID) {
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

type mutableCloneReference struct {
	typeOf   reflect.Type
	kind     reflect.Kind
	pointer  uintptr
	length   int
	capacity int
}

type mutableCloneMemorySpan struct {
	start uintptr
	end   uintptr
}

type mutableCloneState struct {
	seen            map[mutableCloneReference]reflect.Value
	memorySpans     []mutableCloneMemorySpan
	nodes           int
	allocationBytes uint64
}

func newMutableCloneState() *mutableCloneState {
	return &mutableCloneState{
		seen: make(map[mutableCloneReference]reflect.Value),
	}
}

func (state *mutableCloneState) enter(depth int) {
	if state == nil || depth > maxHumanConfidentialBFFCloneDepth ||
		state.nodes >= maxHumanConfidentialBFFCloneNodes {
		panic("strict client metadata exceeds the clone graph budget")
	}
	state.nodes++
}

func (state *mutableCloneState) reserve(bytes uint64) {
	if bytes > maxHumanConfidentialBFFCloneBytes ||
		state.allocationBytes > maxHumanConfidentialBFFCloneBytes-bytes {
		panic("strict client metadata exceeds the clone allocation budget")
	}
	state.allocationBytes += bytes
}

func (state *mutableCloneState) reserveContainer(elements int, elementSize uintptr) {
	if elements < 0 || elements > maxHumanConfidentialBFFCloneElements {
		panic("strict client metadata exceeds the clone container budget")
	}
	if elements == 0 || elementSize == 0 {
		return
	}
	size := uint64(elementSize)
	if size > maxHumanConfidentialBFFCloneBytes/uint64(elements) {
		panic("strict client metadata exceeds the clone allocation budget")
	}
	state.reserve(uint64(elements) * size)
}

func (state *mutableCloneState) registerMemorySpan(start uintptr, bytes uint64) {
	if start == 0 || bytes == 0 || bytes > uint64(^uintptr(0))-uint64(start) {
		panic("strict client metadata contains an invalid mutable memory span")
	}
	span := mutableCloneMemorySpan{start: start, end: start + uintptr(bytes)}
	for _, existing := range state.memorySpans {
		if span.start < existing.end && existing.start < span.end {
			panic("strict client metadata contains overlapping mutable references")
		}
	}
	state.memorySpans = append(state.memorySpans, span)
}

func (state *mutableCloneState) registerSlice(source reflect.Value) {
	if source.Cap() == 0 || source.Type().Elem().Size() == 0 {
		return
	}
	capacityView := source.Slice(0, source.Cap())
	start := capacityView.Pointer()
	bytes := nonnegativeCloneSize(source.Cap()) * uint64(source.Type().Elem().Size())
	state.registerMemorySpan(start, bytes)
}

func nonnegativeCloneSize(value int) uint64 {
	if value < 0 {
		panic("strict client metadata contains an invalid clone size")
	}
	return uint64(value)
}

func cloneHumanConfidentialBFFClient(source *goidc.Client) (clone *goidc.Client, returnedErr error) {
	// A client can carry application-defined metadata and empty key sets whose
	// exact Go representation is not stable under JSON. Clone the object graph
	// structurally so isolation never invokes metadata marshalers or changes
	// concrete numeric types. Any unexpected reflection failure fails closed.
	defer func() {
		if recover() != nil {
			clone = nil
			returnedErr = errors.New("invalid strict client authority clone")
		}
	}()

	state := newMutableCloneState()
	clonedValue := cloneMutableValue(reflect.ValueOf(source), state, 0)
	if !clonedValue.IsValid() {
		return nil, errors.New("invalid strict client authority clone")
	}
	clone, ok := clonedValue.Interface().(*goidc.Client)
	if !ok || clone == nil {
		return nil, errors.New("invalid strict client authority clone")
	}
	clone.CacheJWKS(cloneJSONWebKeySet(source.CachedJWKS(), state))
	return clone, nil
}

func cloneJSONWebKeySet(
	source *goidc.JSONWebKeySet,
	state *mutableCloneState,
) *goidc.JSONWebKeySet {
	if source == nil {
		return nil
	}
	clone := cloneMutableValue(reflect.ValueOf(source), state, 0)
	return clone.Interface().(*goidc.JSONWebKeySet)
}

func cloneMutableValue(
	source reflect.Value,
	state *mutableCloneState,
	depth int,
) reflect.Value {
	if !source.IsValid() {
		return source
	}
	state.enter(depth)
	if source.CanInterface() {
		switch value := source.Interface().(type) {
		case big.Int:
			byteLength := value.BitLen() / 8
			if value.BitLen()%8 != 0 {
				byteLength++
			}
			state.reserve(nonnegativeCloneSize(byteLength))
			return reflect.ValueOf(*new(big.Int).Set(&value))
		case elliptic.Curve:
			if !standardImmutableEllipticCurve(value) {
				panic("strict client metadata contains an unsupported elliptic curve")
			}
			// Qualified standard curves are immutable singleton implementations.
			return source
		}
	}

	switch source.Kind() {
	case reflect.Interface:
		if source.IsNil() {
			return reflect.Zero(source.Type())
		}
		state.reserve(uint64(source.Type().Size()))
		clone := reflect.New(source.Type()).Elem()
		clone.Set(cloneMutableValue(source.Elem(), state, depth+1))
		return clone
	case reflect.Pointer:
		if source.IsNil() {
			return reflect.Zero(source.Type())
		}
		reference := mutableReference(source)
		if clone, ok := state.seen[reference]; ok {
			return clone
		}
		state.registerMemorySpan(source.Pointer(), uint64(source.Type().Elem().Size()))
		state.reserve(uint64(source.Type().Elem().Size()))
		clone := reflect.New(source.Type().Elem())
		state.seen[reference] = clone
		clone.Elem().Set(cloneMutableValue(source.Elem(), state, depth+1))
		return clone
	case reflect.Map:
		if source.IsNil() {
			return reflect.Zero(source.Type())
		}
		reference := mutableReference(source)
		if clone, ok := state.seen[reference]; ok {
			return clone
		}
		state.reserveContainer(source.Len(), source.Type().Key().Size()+source.Type().Elem().Size())
		clone := reflect.MakeMapWithSize(source.Type(), source.Len())
		state.seen[reference] = clone
		iterator := source.MapRange()
		for iterator.Next() {
			clone.SetMapIndex(
				cloneMutableValue(iterator.Key(), state, depth+1),
				cloneMutableValue(iterator.Value(), state, depth+1),
			)
		}
		return clone
	case reflect.Slice:
		if source.IsNil() {
			return reflect.Zero(source.Type())
		}
		reference := mutableReference(source)
		if clone, ok := state.seen[reference]; ok {
			return clone
		}
		state.reserveContainer(source.Cap(), source.Type().Elem().Size())
		state.registerSlice(source)
		clone := reflect.MakeSlice(source.Type(), source.Len(), source.Cap())
		state.seen[reference] = clone
		sourceCapacity := source.Slice(0, source.Cap())
		cloneCapacity := clone.Slice(0, clone.Cap())
		for index := range source.Cap() {
			cloneCapacity.Index(index).Set(cloneMutableValue(sourceCapacity.Index(index), state, depth+1))
		}
		return clone
	case reflect.Array:
		state.reserve(uint64(source.Type().Size()))
		clone := reflect.New(source.Type()).Elem()
		for index := range source.Len() {
			clone.Index(index).Set(cloneMutableValue(source.Index(index), state, depth+1))
		}
		return clone
	case reflect.Struct:
		state.reserve(uint64(source.Type().Size()))
		clone := reflect.New(source.Type()).Elem()
		clone.Set(source)
		for index := range source.NumField() {
			field := source.Type().Field(index)
			if field.IsExported() {
				clone.Field(index).Set(cloneMutableValue(source.Field(index), state, depth+1))
				continue
			}
			if source.Type() == goidcClientReflectType && field.Name == "cachedJWKS" {
				continue
			}
			if mutableCloneValueIsShared(source.Field(index), state, depth+1) {
				panic("strict client metadata contains unsupported mutable unexported state")
			}
		}
		return clone
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		panic("strict client metadata contains an unsupported reference type")
	case reflect.Uintptr:
		if source.Uint() != 0 {
			panic("strict client metadata contains an unsupported address value")
		}
		return source
	default:
		return source
	}
}

func standardImmutableEllipticCurve(curve elliptic.Curve) bool {
	value := reflect.ValueOf(curve)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	for _, standard := range []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	} {
		standardValue := reflect.ValueOf(standard)
		if value.Type() == standardValue.Type() && value.Pointer() == standardValue.Pointer() {
			return true
		}
	}
	return false
}

func mutableReference(value reflect.Value) mutableCloneReference {
	reference := mutableCloneReference{
		typeOf:  value.Type(),
		kind:    value.Kind(),
		pointer: value.Pointer(),
	}
	if value.Kind() == reflect.Slice {
		reference.length = value.Len()
		reference.capacity = value.Cap()
	}
	return reference
}

func mutableCloneValueIsShared(
	value reflect.Value,
	state *mutableCloneState,
	depth int,
) bool {
	state.enter(depth)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice,
		reflect.UnsafePointer:
		return !value.IsNil()
	case reflect.Interface:
		return !value.IsNil() && mutableCloneValueIsShared(value.Elem(), state, depth+1)
	case reflect.Array:
		state.reserveContainer(value.Len(), 0)
		for index := range value.Len() {
			if mutableCloneValueIsShared(value.Index(index), state, depth+1) {
				return true
			}
		}
		return false
	case reflect.Struct:
		state.reserveContainer(value.NumField(), 0)
		for index := range value.NumField() {
			if mutableCloneValueIsShared(value.Field(index), state, depth+1) {
				return true
			}
		}
		return false
	case reflect.Uintptr:
		return value.Uint() != 0
	default:
		return false
	}
}

func cloneHumanConfidentialBFFAuthenticationSession(
	source *goidc.AuthnSession,
) (clone *goidc.AuthnSession, returnedErr error) {
	defer func() {
		if recover() != nil {
			clone = nil
			returnedErr = errors.New("invalid strict authentication session clone")
		}
	}()
	clonedValue := cloneMutableValue(
		reflect.ValueOf(source),
		newMutableCloneState(),
		0,
	)
	clone, ok := clonedValue.Interface().(*goidc.AuthnSession)
	if !ok || clone == nil {
		return nil, errors.New("invalid strict authentication session clone")
	}
	return clone, nil
}

func applyHumanConfidentialBFFAuthenticationOutputs(
	target *goidc.AuthnSession,
	callbackSession *goidc.AuthnSession,
	status goidc.Status,
) error {
	detached, err := cloneHumanConfidentialBFFAuthenticationSession(callbackSession)
	if err != nil {
		return err
	}
	if !validHumanConfidentialBFFAuthenticationOutputs(target, detached, status) {
		return errors.New("the strict authentication callback returned unauthorized grant outputs")
	}
	target.Subject = detached.Subject
	target.Username = detached.Username
	target.GrantedScopes = detached.GrantedScopes
	target.GrantedAuthDetails = detached.GrantedAuthDetails
	target.GrantedResources = detached.GrantedResources
	target.Store = detached.Store
	return nil
}

func validHumanConfidentialBFFAuthenticationOutputs(
	target *goidc.AuthnSession,
	callback *goidc.AuthnSession,
	status goidc.Status,
) bool {
	if callback.Username != "" || callback.GrantedAuthDetails != nil {
		return false
	}
	if status != goidc.StatusSuccess {
		return callback.Subject == "" && callback.Username == "" &&
			callback.GrantedScopes == "" && callback.GrantedResources == nil
	}
	if !validHumanConfidentialBFFSubject(callback.Subject) {
		return false
	}
	if callback.GrantedScopes == "" {
		return false
	} else if !validHumanConfidentialBFFCanonicalSpaceSet(
		callback.GrantedScopes,
		1,
		maxHumanConfidentialBFFScopes,
		humanConfidentialBFFScopePattern.MatchString,
	) || !humanConfidentialBFFSortedSubset(
		strings.Split(callback.GrantedScopes, " "),
		strings.Split(target.Scopes, " "),
	) || !strings.Contains(" "+callback.GrantedScopes+" ", " "+goidc.ScopeOpenID.ID+" ") {
		return false
	}
	if len(callback.GrantedResources) != 0 &&
		(!validHumanConfidentialBFFResources(callback.GrantedResources) ||
			!humanConfidentialBFFSortedSubset(callback.GrantedResources, target.Resources)) {
		return false
	}
	return true
}

func validHumanConfidentialBFFSubject(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func humanConfidentialBFFAuthenticationSessionsEqual(
	left *goidc.AuthnSession,
	right *goidc.AuthnSession,
) bool {
	return reflect.DeepEqual(left, right)
}

func isolatedHumanConfidentialBFFCallbackClient(c *goidc.Client) (*goidc.Client, error) {
	clone, strict, err := authorizationAdmissionClient(c)
	if err != nil {
		return nil, err
	}
	if !strict {
		return nil, goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("strict callback client lost its authorization request profile"),
		)
	}
	return clone, nil
}

type humanConfidentialBFFSessionPhase uint8

const (
	humanConfidentialBFFSessionPhasePushedRequest humanConfidentialBFFSessionPhase = iota + 1
	humanConfidentialBFFSessionPhaseContinuation
)

func validateAuthorizationRequestProfileBinding(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	c *goidc.Client,
) error {
	return validateAuthorizationProfileBinding(
		ctx,
		session,
		c,
		humanConfidentialBFFSessionPhasePushedRequest,
	)
}

func validateAuthorizationContinuationProfileBinding(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	c *goidc.Client,
) error {
	return validateAuthorizationProfileBinding(
		ctx,
		session,
		c,
		humanConfidentialBFFSessionPhaseContinuation,
	)
}

func validateAuthorizationProfileBinding(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	c *goidc.Client,
	phase humanConfidentialBFFSessionPhase,
) error {
	if session == nil || c == nil ||
		session.AuthorizationRequestProfile != c.AuthorizationRequestProfile {
		return goidc.WrapError(
			goidc.ErrorCodeServerError,
			"server error",
			errors.New("the authorization session admission profile no longer matches client authority"),
		)
	}
	if c.AuthorizationRequestProfile == goidc.AuthorizationRequestProfileHumanConfidentialBFF {
		var cause error
		switch {
		case !completeHumanConfidentialBFFAuthorizationParameters(request{
			AuthorizationParameters: session.AuthorizationParameters,
		}):
			cause = errors.New("the strict authorization parameters are outside the admitted profile")
		case !humanConfidentialBFFSessionMatchesPhase(ctx, session, phase):
			cause = errors.New("the strict authorization session is outside its admitted lifecycle phase")
		case !humanConfidentialBFFSessionMatchesCurrentClient(session, c):
			cause = errors.New("the strict authorization session no longer matches current client authority")
		case !humanConfidentialBFFSessionMatchesCurrentServer(ctx, session):
			cause = errors.New("the strict authorization session no longer matches current server authority")
		}
		if cause != nil {
			return goidc.WrapError(goidc.ErrorCodeServerError, "server error", cause)
		}
	}
	return nil
}

func humanConfidentialBFFSessionMatchesPhase(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	phase humanConfidentialBFFSessionPhase,
) bool {
	if session == nil || !humanConfidentialBFFSessionIDPattern.MatchString(session.ID) ||
		!humanConfidentialBFFSessionIDPattern.MatchString(session.PersistenceID) ||
		!humanConfidentialBFFSessionIDPattern.MatchString(session.PushedAuthReqID) ||
		session.ID == session.PersistenceID || session.ID == session.PushedAuthReqID ||
		session.PersistenceID == session.PushedAuthReqID || session.CreatedAt < 1 ||
		session.ExpiresAt <= session.CreatedAt || session.CreatedAt > timeutil.TimestampNow() ||
		timeutil.TimestampNow() >= session.ExpiresAt || session.Subject != "" ||
		session.Username != "" || session.GrantedScopes != "" ||
		session.GrantedAuthDetails != nil || session.GrantedResources != nil {
		return false
	}
	switch phase {
	case humanConfidentialBFFSessionPhasePushedRequest:
		return session.PolicyID == "" && len(session.Store) == 0 &&
			ctx.PARLifetimeSecs > 0 && session.ExpiresAt-session.CreatedAt == ctx.PARLifetimeSecs
	case humanConfidentialBFFSessionPhaseContinuation:
		return humanConfidentialBFFPolicyIDPattern.MatchString(session.PolicyID) &&
			ctx.AuthTimeoutSecs > 0 && session.ExpiresAt <= timeutil.TimestampNow()+ctx.AuthTimeoutSecs
	default:
		return false
	}
}

func humanConfidentialBFFSessionMatchesCurrentClient(
	session *goidc.AuthnSession,
	c *goidc.Client,
) bool {
	if session.Status != goidc.StatusPending || session.PushedAuthReqID == "" ||
		session.AuthReqID != "" || session.DeviceCode != "" || session.UserCode != "" ||
		session.JWKThumbprint != "" || session.ClientCertThumbprint != "" ||
		session.IDTokenHintClaims != nil || session.VCInfo != nil ||
		session.GrantedAuthDetails != nil || session.ClientID != c.ID ||
		!slices.Contains(c.RedirectURIs, session.RedirectURI) ||
		!humanConfidentialBFFSortedSubset(
			strings.Split(session.Scopes, " "),
			strings.Split(c.ScopeIDs, " "),
		) || session.ClientAssertionAuthority == nil || c.PrivateKeyJWTAuthority == nil ||
		session.ClientAssertionAuthority.SnapshotRevision != c.PrivateKeyJWTAuthority.SnapshotRevision {
		return false
	}
	return slices.ContainsFunc(
		c.PrivateKeyJWTAuthority.Keys,
		func(key goidc.PrivateKeyJWTAuthorityKey) bool {
			return key.KeyAuthorityID == session.ClientAssertionAuthority.KeyAuthorityID
		},
	)
}

func humanConfidentialBFFSessionMatchesCurrentServer(
	ctx oidc.Context,
	session *goidc.AuthnSession,
) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if ctx.Configuration == nil || !ctx.PAREnabled || !ctx.PKCEEnabled ||
		!slices.Contains(ctx.PKCEChallengeMethods, goidc.CodeChallengeMethodSHA256) ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) ||
		!slices.Contains(ctx.ResponseTypes, goidc.ResponseTypeCode) ||
		!slices.Contains(ctx.ResponseModes, goidc.ResponseModeQuery) ||
		!slices.Contains(ctx.SubIdentifierTypes, goidc.SubIdentifierPairwise) ||
		ctx.PairwiseSubjectFunc == nil || !slices.Contains(ctx.IDTokenSigAlgs, goidc.SigAlgPS256) ||
		!slices.Contains(ctx.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) ||
		!slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, goidc.SigAlgPS256) {
		return false
	}
	for scopeID := range strings.FieldsSeq(session.Scopes) {
		scope, exists := ctx.Scope(scopeID)
		if !exists || scope.ID != scopeID {
			return false
		}
	}
	if session.ACRValues != "" && !slices.Contains(ctx.ACRs, goidc.ACR(session.ACRValues)) {
		return false
	}
	if len(session.Resources) == 0 {
		return false
	}
	if !ctx.ResourceIndicatorsEnabled {
		return false
	}
	for _, resource := range session.Resources {
		if !slices.Contains(ctx.ResourceIndicators, resource) {
			return false
		}
	}
	return true
}

func humanConfidentialBFFAtomicPARMatchesCurrentAuthority(
	ctx oidc.Context,
	parameters goidc.AuthorizationParameters,
	c *goidc.Client,
	clientAssertionAuthority *goidc.VerifiedClientAssertionAuthority,
) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if ctx.Configuration == nil || !ctx.HumanConfidentialBFFAuthorizationEnabled ||
		ctx.HumanAuthorizationAuthority == nil || c == nil ||
		clientAssertionAuthority == nil || c.PrivateKeyJWTAuthority == nil ||
		c.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		clientAssertionAuthority.SnapshotRevision != c.PrivateKeyJWTAuthority.SnapshotRevision ||
		!completeHumanConfidentialBFFAuthorizationParameters(request{AuthorizationParameters: parameters}) ||
		!slices.Contains(c.RedirectURIs, parameters.RedirectURI) ||
		!humanConfidentialBFFSortedSubset(strings.Split(parameters.Scopes, " "), strings.Split(c.ScopeIDs, " ")) ||
		!ctx.PAREnabled || ctx.PARLifetimeSecs <= 0 || ctx.PARLifetimeSecs >= 600 ||
		!ctx.PKCEEnabled ||
		!slices.Contains(ctx.PKCEChallengeMethods, goidc.CodeChallengeMethodSHA256) ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantAuthorizationCode) ||
		!slices.Contains(ctx.GrantTypes, goidc.GrantRefreshToken) ||
		!slices.Contains(ctx.ResponseTypes, goidc.ResponseTypeCode) ||
		!slices.Contains(ctx.ResponseModes, goidc.ResponseModeQuery) ||
		!slices.Contains(ctx.SubIdentifierTypes, goidc.SubIdentifierPairwise) ||
		!slices.Contains(ctx.IDTokenSigAlgs, goidc.SigAlgPS256) ||
		!slices.Contains(ctx.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) ||
		!slices.Contains(ctx.AuthnMethodPrivateKeyJWTSigAlgs, goidc.SigAlgPS256) {
		return false
	}
	if !slices.ContainsFunc(c.PrivateKeyJWTAuthority.Keys, func(key goidc.PrivateKeyJWTAuthorityKey) bool {
		return key.KeyAuthorityID == clientAssertionAuthority.KeyAuthorityID
	}) {
		return false
	}
	for scopeID := range strings.FieldsSeq(parameters.Scopes) {
		scope, exists := ctx.Scope(scopeID)
		if !exists || scope.ID != scopeID {
			return false
		}
	}
	if parameters.ACRValues != "" && !slices.Contains(ctx.ACRs, goidc.ACR(parameters.ACRValues)) {
		return false
	}
	if len(parameters.Resources) == 0 {
		return false
	}
	if !ctx.ResourceIndicatorsEnabled {
		return false
	}
	for _, resource := range parameters.Resources {
		if !slices.Contains(ctx.ResourceIndicators, resource) {
			return false
		}
	}
	return true
}

func validHumanConfidentialBFFStartConfiguration(ctx oidc.Context) bool {
	if ctx.Configuration == nil || !ctx.HumanConfidentialBFFAuthorizationEnabled ||
		ctx.HumanAuthorizationAuthority == nil || ctx.Response == nil {
		return false
	}
	if _, validClockSkew := oidc.HumanAuthorizationClockSkewSeconds(ctx.JWTLeewayTimeSecs); !validClockSkew {
		return false
	}
	endpoint, err := url.ParseRequestURI(ctx.HumanIdentityInteractionEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawFragment != "" || endpoint.RawQuery != "" ||
		endpoint.ForceQuery || endpoint.Opaque != "" || endpoint.RawPath != "" || endpoint.Path == "" ||
		endpoint.Port() != "" || endpoint.Host != strings.ToLower(endpoint.Host) ||
		endpoint.String() != ctx.HumanIdentityInteractionEndpoint {
		return false
	}
	name := ctx.HumanBrowserBindingCookieName
	if !strings.HasPrefix(name, "__Host-") || len(name) > 128 {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if character <= 0x20 || character >= 0x7f ||
			strings.ContainsRune("()<>@,;:\"/[]?={}\\", rune(character)) {
			return false
		}
	}
	return true
}

func validHumanConfidentialBFFPairwiseSubject(
	ctx oidc.Context,
	session *goidc.AuthnSession,
	c *goidc.Client,
) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if session == nil || c == nil || !validHumanConfidentialBFFSubject(session.Subject) ||
		ctx.PairwiseSubjectFunc == nil {
		return false
	}
	firstClient, err := cloneHumanConfidentialBFFClient(c)
	if err != nil {
		return false
	}
	secondClient, err := cloneHumanConfidentialBFFClient(c)
	if err != nil {
		return false
	}
	first := ctx.PairwiseSubject(session.Subject, firstClient)
	second := ctx.PairwiseSubject(session.Subject, secondClient)
	return first != session.Subject && first == second && validHumanConfidentialBFFSubject(first)
}

func cloneHumanConfidentialBFFAuthorizationParameters(
	parameters goidc.AuthorizationParameters,
) goidc.AuthorizationParameters {
	clone := parameters
	if parameters.MaxAuthnAgeSecs != nil {
		maxAge := *parameters.MaxAuthnAgeSecs
		clone.MaxAuthnAgeSecs = &maxAge
	}
	clone.Resources = append(goidc.Resources(nil), parameters.Resources...)
	return clone
}

func humanConfidentialBFFAuthorizationParametersEqual(
	left goidc.AuthorizationParameters,
	right goidc.AuthorizationParameters,
) bool {
	return reflect.DeepEqual(left, right)
}

func completeHumanConfidentialBFFAuthorizationParameters(req request) bool {
	if !validHumanConfidentialBFFAbsoluteHTTPSURI(req.RedirectURI) ||
		req.RequestURI != "" || req.RequestObject != "" || req.Display != "" ||
		req.Claims != nil || req.AuthDetails != nil || req.DPoPJKT != "" ||
		req.LoginHint != "" || req.LoginHintToken != "" || req.IDTokenHint != "" ||
		req.ClientNotificationToken != "" || req.BindingMessage != "" || req.UserCode != "" ||
		req.RequestedExpiry != nil || req.IssuerState != "" ||
		req.ResponseType != goidc.ResponseTypeCode || req.ResponseMode != goidc.ResponseModeQuery ||
		!validHumanConfidentialBFFOpaqueParameter(req.State) ||
		!validHumanConfidentialBFFOpaqueParameter(req.Nonce) ||
		req.CodeChallengeMethod != goidc.CodeChallengeMethodSHA256 ||
		!validHumanConfidentialBFFCodeChallenge(req.CodeChallenge) ||
		!validHumanConfidentialBFFCanonicalSpaceSet(
			req.Scopes,
			1,
			maxHumanConfidentialBFFScopes,
			humanConfidentialBFFScopePattern.MatchString,
		) ||
		!strings.Contains(" "+req.Scopes+" ", " "+goidc.ScopeOpenID.ID+" ") ||
		!validHumanConfidentialBFFCanonicalSpaceSet(
			req.ACRValues,
			0,
			1,
			humanConfidentialBFFAssurancePattern.MatchString,
		) ||
		!validHumanConfidentialBFFResources(req.Resources) ||
		(req.Prompt != "" && req.Prompt != goidc.PromptTypeLogin && req.Prompt != goidc.PromptTypeNone) {
		return false
	}
	return req.MaxAuthnAgeSecs == nil ||
		(*req.MaxAuthnAgeSecs >= 0 && *req.MaxAuthnAgeSecs <= maxHumanConfidentialBFFMaxAge)
}

func validHumanConfidentialBFFOpaqueParameter(value string) bool {
	if len(value) < 16 || len(value) > maxHumanConfidentialBFFOpaqueBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validHumanConfidentialBFFCanonicalSpaceSet(
	value string,
	minimum int,
	maximum int,
	validate func(string) bool,
) bool {
	if value == "" {
		return minimum == 0
	}
	return validHumanConfidentialBFFSortedSet(
		strings.Split(value, " "),
		minimum,
		maximum,
		validate,
	)
}

func validHumanConfidentialBFFSortedSet(
	values []string,
	minimum int,
	maximum int,
	validate func(string) bool,
) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	previous := ""
	for index, value := range values {
		if !validate(value) || (index > 0 && previous >= value) {
			return false
		}
		previous = value
	}
	return true
}

func humanConfidentialBFFSortedSubset(candidate []string, admitted []string) bool {
	admittedIndex := 0
	for _, value := range candidate {
		for admittedIndex < len(admitted) && admitted[admittedIndex] < value {
			admittedIndex++
		}
		if admittedIndex == len(admitted) || admitted[admittedIndex] != value {
			return false
		}
		admittedIndex++
	}
	return true
}

func validHumanConfidentialBFFAbsoluteHTTPSURI(value string) bool {
	if value == "" || len(value) > maxHumanConfidentialBFFURIBytes ||
		strings.Contains(value, "*") || !humanConfidentialBFFASCII(value) {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.String() != value ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() != "" ||
		net.ParseIP(parsed.Hostname()) != nil || !humanConfidentialBFFHostPattern.MatchString(parsed.Hostname()) ||
		parsed.Hostname() != parsed.Host || !humanConfidentialBFFPathPattern.MatchString(parsed.Path) ||
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

func humanConfidentialBFFASCII(value string) bool {
	for index := range len(value) {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func validHumanConfidentialBFFCodeChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return false
	}
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	return combined != 0
}

func validHumanConfidentialBFFMaxAge(raw string, parsed *int) bool {
	if parsed == nil || *parsed < 0 || *parsed > maxHumanConfidentialBFFMaxAge {
		return false
	}
	return strconv.Itoa(*parsed) == raw
}

func humanConfidentialBFFPARParameter(name string) bool {
	switch name {
	case "client_id",
		"client_assertion",
		"client_assertion_type",
		"redirect_uri",
		"response_mode",
		"response_type",
		"scope",
		"state",
		"nonce",
		"code_challenge",
		"code_challenge_method",
		"prompt",
		"max_age",
		"acr_values",
		"resource":
		return true
	default:
		return false
	}
}

func validHumanConfidentialBFFResources(values []string) bool {
	return validHumanConfidentialBFFSortedSet(
		values,
		1,
		maxHumanConfidentialBFFResources,
		validHumanConfidentialBFFAbsoluteHTTPSURI,
	)
}

func invalidHumanConfidentialBFFRequest(reason string) error {
	return goidc.WrapError(
		goidc.ErrorCodeInvalidRequest,
		"invalid request",
		errors.New(reason),
	)
}
