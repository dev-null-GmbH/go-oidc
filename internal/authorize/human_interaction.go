package authorize

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	humanBrowserInteractionRoute = "/oidc/interaction/browser"
	humanConsumeInteractionRoute = "/oidc/interaction/consume"

	humanIdentityReturnFormField = "identity_return"
	humanBrowserReturnFormField  = "browser_return"
	humanReadyFormField          = "ready"

	humanInteractionRejectedBody = "invalid interaction\n"
	humanInteractionServerBody   = "interaction unavailable\n"
	humanInteractionMaxFormBytes = 2048

	humanBrowserInteractionScript = `(function(){"use strict";const f=window.location.hash.length>1?window.location.hash.slice(1):"";history.replaceState(null,"",window.location.pathname);const form=document.getElementById("human-interaction");const predecessor=document.getElementById("identity-return");if(f.length<=128){predecessor.value=f;}form.addEventListener("submit",function(event){if(!event.isTrusted||predecessor.value.length===0){event.preventDefault();}});})();`
	humanConsumeInteractionScript = `(function(){"use strict";const f=window.location.hash.length>1?window.location.hash.slice(1):"";history.replaceState(null,"",window.location.pathname);const form=document.getElementById("human-interaction");const predecessor=document.getElementById("ready");if(f.length<=128){predecessor.value=f;}form.addEventListener("submit",function(event){if(!event.isTrusted||predecessor.value.length===0){event.preventDefault();}});})();`
)

func handlerHumanBrowserInteraction(ctx oidc.Context) {
	switch ctx.Request.Method {
	case http.MethodGet:
		handleHumanBrowserInteractionGET(ctx)
	case http.MethodPost:
		handleHumanBrowserInteractionPOST(ctx)
	default:
		writeHumanInteractionError(ctx, http.StatusMethodNotAllowed, humanInteractionRejectedBody)
	}
}

func handlerHumanConsumeInteraction(ctx oidc.Context) {
	switch ctx.Request.Method {
	case http.MethodGet:
		handleHumanConsumeInteractionGET(ctx)
	case http.MethodPost:
		handleHumanConsumeInteractionPOST(ctx)
	default:
		writeHumanInteractionError(ctx, http.StatusMethodNotAllowed, humanInteractionRejectedBody)
	}
}

func handleHumanBrowserInteractionGET(ctx oidc.Context) {
	if !validHumanInteractionConfiguration(ctx) {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	if !validHumanInteractionGETTransport(ctx.Request, humanInteractionRoute(ctx, humanBrowserInteractionRoute)) {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}

	browserReturn, err := mintHumanBrowserReturnCapability()
	if err != nil {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Continue sign-in</title></head><body><main><h1>Continue sign-in</h1><p>Confirm to continue this sign-in in the current browser.</p><form id="human-interaction" method="post" action="` + html.EscapeString(humanInteractionRoute(ctx, humanBrowserInteractionRoute)) + `"><input id="identity-return" type="hidden" name="identity_return" value=""><input type="hidden" name="browser_return" value="` + html.EscapeString(browserReturn) + `"><button type="submit">Continue</button></form></main><script>` + humanBrowserInteractionScript + `</script></body></html>`
	writeHumanInteractionPage(ctx, body, humanBrowserInteractionScript)
}

func handleHumanBrowserInteractionPOST(ctx oidc.Context) {
	if !validHumanInteractionConfiguration(ctx) {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	if !validHumanInteractionPOSTTransport(
		ctx.Request,
		humanInteractionRoute(ctx, humanBrowserInteractionRoute),
		ctx.Host,
	) {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	form, ok := parseExactHumanInteractionForm(ctx, humanIdentityReturnFormField, humanBrowserReturnFormField)
	if !ok {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	browserBinding, ok := humanBrowserBindingCookie(ctx.Request, ctx.HumanBrowserBindingCookieName)
	if !ok {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	identityReturn, identityErr := goidc.NewHumanIdentityReturnCapability(form[humanIdentityReturnFormField][0])
	browserReturn, browserErr := goidc.NewHumanBrowserReturnCapability(form[humanBrowserReturnFormField][0])
	binding, bindingErr := goidc.NewHumanBrowserBindingCapability(browserBinding)
	if identityErr != nil || browserErr != nil || bindingErr != nil {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	input, err := goidc.NewHumanContinuationInput(identityReturn, browserReturn, binding)
	if err != nil {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	decision, err := ctx.HumanConfirmBrowser(input)
	if err != nil {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	switch decision.Outcome() {
	case goidc.HumanContinuationOutcomeConfirmed, goidc.HumanContinuationOutcomeReplayed:
		confirmed, present := decision.BrowserReturnCapability()
		confirmedText, renderErr := confirmed.Render()
		expectedText, expectedErr := browserReturn.Render()
		if !present || renderErr != nil || expectedErr != nil || confirmedText != expectedText {
			writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
			return
		}
		writeHumanInteractionRedirect(ctx, ctx.HumanIdentityReadyEndpoint+"#"+confirmedText)
	case goidc.HumanContinuationOutcomeExpired, goidc.HumanContinuationOutcomeRejected:
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
	default:
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
	}
}

func handleHumanConsumeInteractionGET(ctx oidc.Context) {
	if !validHumanInteractionConfiguration(ctx) {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	if !validHumanInteractionGETTransport(ctx.Request, humanInteractionRoute(ctx, humanConsumeInteractionRoute)) {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Finish sign-in</title></head><body><main><h1>Finish sign-in</h1><p>Confirm to return to the application.</p><form id="human-interaction" method="post" action="` + html.EscapeString(humanInteractionRoute(ctx, humanConsumeInteractionRoute)) + `"><input id="ready" type="hidden" name="ready" value=""><button type="submit">Finish sign-in</button></form></main><script>` + humanConsumeInteractionScript + `</script></body></html>`
	writeHumanInteractionPage(ctx, body, humanConsumeInteractionScript)
}

func handleHumanConsumeInteractionPOST(ctx oidc.Context) {
	if !validHumanInteractionConfiguration(ctx) {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	if !validHumanInteractionPOSTTransport(
		ctx.Request,
		humanInteractionRoute(ctx, humanConsumeInteractionRoute),
		ctx.Host,
	) {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	form, ok := parseExactHumanInteractionForm(ctx, humanReadyFormField)
	if !ok {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	browserBinding, ok := humanBrowserBindingCookie(ctx.Request, ctx.HumanBrowserBindingCookieName)
	if !ok {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	ready, readyErr := goidc.NewHumanReadyCapability(form[humanReadyFormField][0])
	binding, bindingErr := goidc.NewHumanBrowserBindingCapability(browserBinding)
	if readyErr != nil || bindingErr != nil {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}
	input, err := goidc.NewHumanCompletionInput(ready, binding)
	if err != nil {
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
		return
	}

	decision, err := ctx.HumanCompleteAuthorization(input)
	clearHumanBrowserBindingCookie(ctx)
	if err != nil {
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
		return
	}
	switch decision.Outcome() {
	case goidc.HumanCompletionOutcomeCompleted:
		redirectBase, rebound := reboundHumanCompletionRedirect(ctx, decision)
		if !rebound {
			writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
			return
		}
		code, present := decision.AuthorizationCode()
		codeText, renderErr := code.Render()
		if !present || renderErr != nil {
			writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
			return
		}
		writeHumanInteractionRedirect(ctx, humanCompletionRedirect(
			redirectBase,
			url.Values{"code": {codeText}, "state": {decision.State()}, "iss": {ctx.Issuer()}},
		))
	case goidc.HumanCompletionOutcomeFailed:
		redirectBase, rebound := reboundHumanCompletionRedirect(ctx, decision)
		if !rebound {
			writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
			return
		}
		writeHumanInteractionRedirect(ctx, humanCompletionRedirect(
			redirectBase,
			url.Values{"error": {string(decision.Failure())}, "state": {decision.State()}, "iss": {ctx.Issuer()}},
		))
	case goidc.HumanCompletionOutcomeReplayed,
		goidc.HumanCompletionOutcomeExpired,
		goidc.HumanCompletionOutcomeRejected:
		writeHumanInteractionError(ctx, http.StatusBadRequest, humanInteractionRejectedBody)
	default:
		writeHumanInteractionError(ctx, http.StatusInternalServerError, humanInteractionServerBody)
	}
}

func humanInteractionRoute(ctx oidc.Context, route string) string {
	return ctx.EndpointPrefix + route
}

func validHumanInteractionGETTransport(request *http.Request, path string) bool {
	return request != nil && request.Method == http.MethodGet && request.URL != nil &&
		request.URL.Path == path && request.URL.RawPath == "" && request.URL.RawQuery == "" &&
		!request.URL.ForceQuery && request.URL.Fragment == "" && request.URL.RawFragment == "" &&
		request.ContentLength == 0 && len(request.TransferEncoding) == 0
}

func validHumanInteractionPOSTTransport(request *http.Request, path, issuer string) bool {
	if request == nil || request.Method != http.MethodPost || request.URL == nil ||
		request.URL.Path != path || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.ForceQuery || request.URL.Fragment != "" || request.URL.RawFragment != "" ||
		request.ContentLength < 1 || request.ContentLength > humanInteractionMaxFormBytes ||
		len(request.TransferEncoding) != 0 {
		return false
	}
	issuerURL, err := canonicalHumanInteractionIssuer(issuer)
	if err != nil || request.Host != issuerURL.Host {
		return false
	}
	for _, name := range []string{
		"Authorization",
		"Proxy-Authorization",
		"DPoP",
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if _, present := humanInteractionHeaderValues(request.Header, name); present {
			return false
		}
	}
	contentTypes, contentTypePresent := humanInteractionHeaderValues(request.Header, "Content-Type")
	if !contentTypePresent || len(contentTypes) != 1 ||
		contentTypes[0] != "application/x-www-form-urlencoded" {
		return false
	}
	wantOrigin := issuerURL.Scheme + "://" + issuerURL.Host
	origins, originPresent := humanInteractionHeaderValues(request.Header, "Origin")
	if !originPresent || len(origins) != 1 || origins[0] != wantOrigin {
		return false
	}
	return humanFetchMetadataIsSameOriginNavigation(request.Header)
}

func humanFetchMetadataIsSameOriginNavigation(header http.Header) bool {
	checks := map[string]string{
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-User": "?1",
	}
	for name, want := range checks {
		values, present := humanInteractionHeaderValues(header, name)
		if present && (len(values) != 1 || values[0] != want) {
			return false
		}
	}
	return true
}

func humanInteractionHeaderValues(header http.Header, name string) ([]string, bool) {
	values := make([]string, 0, 1)
	present := false
	for candidate, members := range header {
		if !strings.EqualFold(candidate, name) {
			continue
		}
		present = true
		if len(members) == 0 {
			values = append(values, "")
			continue
		}
		values = append(values, members...)
	}
	return values, present
}

func parseExactHumanInteractionForm(ctx oidc.Context, names ...string) (url.Values, bool) {
	if oidc.FormParseFailed(ctx.Request) {
		return nil, false
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Response, ctx.Request.Body, humanInteractionMaxFormBytes)
	if err := ctx.Request.ParseForm(); err != nil || len(ctx.Request.PostForm) != len(names) ||
		len(ctx.Request.Form) != len(names) {
		return nil, false
	}
	for _, name := range names {
		values, present := ctx.Request.PostForm[name]
		if !present || len(values) != 1 || values[0] == "" {
			return nil, false
		}
	}
	return ctx.Request.PostForm, true
}

func humanBrowserBindingCookie(request *http.Request, name string) (string, bool) {
	count := 0
	value := ""
	for _, cookie := range request.Cookies() {
		if cookie.Name != name {
			continue
		}
		count++
		value = cookie.Value
	}
	return value, count == 1 && value != ""
}

func mintHumanBrowserReturnCapability() (string, error) {
	for range 2 {
		entropy := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
			return "", err
		}
		raw := "d0_hio_c1_" + base64.RawURLEncoding.EncodeToString(entropy)
		capability, err := goidc.NewHumanBrowserReturnCapability(raw)
		if err == nil {
			return capability.Render()
		}
	}
	return "", goidc.ErrInvalidHumanAuthorizationValue
}

func reboundHumanCompletionRedirect(ctx oidc.Context, decision goidc.HumanCompletionDecision) (
	redirect string,
	valid bool,
) {
	defer func() {
		if recover() != nil {
			redirect = ""
			valid = false
		}
	}()
	if !decision.Valid() || decision.Profile() != goidc.AuthorizationRequestProfileHumanConfidentialBFF ||
		!validHumanInteractionConfiguration(ctx) {
		return "", false
	}
	resolved, err := client.Client(ctx, decision.ClientID())
	if err != nil {
		return "", false
	}
	isolated, strict, err := authorizationAdmissionClient(resolved)
	if err != nil || !strict || isolated.ID != decision.ClientID() || isolated.PrivateKeyJWTAuthority == nil ||
		isolated.PrivateKeyJWTAuthority.SnapshotRevision != decision.ClientSnapshotRevision() ||
		!slices.ContainsFunc(isolated.PrivateKeyJWTAuthority.Keys, func(key goidc.PrivateKeyJWTAuthorityKey) bool {
			return key.KeyAuthorityID == decision.AdmissionKeyAuthorityID()
		}) || !slices.Contains(isolated.RedirectURIs, decision.RedirectURI()) {
		return "", false
	}
	return decision.RedirectURI(), true
}

func validHumanInteractionConfiguration(ctx oidc.Context) bool {
	if ctx.Configuration == nil || !ctx.HumanConfidentialBFFAuthorizationEnabled ||
		ctx.HumanAuthorizationAuthority == nil || ctx.Response == nil || ctx.Request == nil ||
		!validHumanBrowserBindingCookieName(ctx.HumanBrowserBindingCookieName) ||
		!validHumanConfidentialBFFAbsoluteHTTPSURI(ctx.HumanIdentityInteractionEndpoint) ||
		!validHumanConfidentialBFFAbsoluteHTTPSURI(ctx.HumanIdentityReadyEndpoint) {
		return false
	}
	issuer, err := canonicalHumanInteractionIssuer(ctx.Host)
	interaction, interactionErr := url.ParseRequestURI(ctx.HumanIdentityInteractionEndpoint)
	ready, readyErr := url.ParseRequestURI(ctx.HumanIdentityReadyEndpoint)
	return err == nil && interactionErr == nil && readyErr == nil &&
		interaction.Scheme == ready.Scheme && interaction.Host == ready.Host &&
		interaction.Hostname() != issuer.Hostname() && ready.Hostname() != issuer.Hostname()
}

func canonicalHumanInteractionIssuer(value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || value == "" || len(value) > maxHumanConfidentialBFFURIBytes ||
		!humanConfidentialBFFASCII(value) || strings.Contains(value, "*") ||
		parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Opaque != "" || parsed.RawPath != "" || parsed.Port() != "" ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Hostname() != parsed.Host ||
		net.ParseIP(parsed.Hostname()) != nil || !humanConfidentialBFFHostPattern.MatchString(parsed.Hostname()) ||
		(parsed.Path != "" && (!humanConfidentialBFFPathPattern.MatchString(parsed.Path) || strings.Contains(parsed.Path, "//"))) ||
		parsed.String() != value {
		return nil, goidc.ErrInvalidHumanAuthorizationValue
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, goidc.ErrInvalidHumanAuthorizationValue
		}
	}
	return parsed, nil
}

func validHumanBrowserBindingCookieName(name string) bool {
	if !strings.HasPrefix(name, "__Host-") || len(name) == len("__Host-") || len(name) > 128 {
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

func humanCompletionRedirect(base string, values url.Values) string {
	parsed, err := url.ParseRequestURI(base)
	if err != nil {
		return ""
	}
	parsed.RawQuery = values.Encode()
	parsed.ForceQuery = false
	return parsed.String()
}

func clearHumanBrowserBindingCookie(ctx oidc.Context) {
	http.SetCookie(ctx.Response, &http.Cookie{
		Name:     ctx.HumanBrowserBindingCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func writeHumanInteractionPage(ctx oidc.Context, body, script string) {
	setHumanInteractionSecurityHeaders(ctx.Response.Header(), script)
	ctx.Response.Header().Set("Content-Type", "text/html; charset=utf-8")
	ctx.Response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(ctx.Response, body)
}

func writeHumanInteractionRedirect(ctx oidc.Context, location string) {
	setHumanInteractionSecurityHeaders(ctx.Response.Header(), "")
	ctx.Response.Header().Set("Location", location)
	ctx.Response.WriteHeader(http.StatusSeeOther)
}

func writeHumanInteractionError(ctx oidc.Context, status int, body string) {
	setHumanInteractionSecurityHeaders(ctx.Response.Header(), "")
	ctx.Response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	ctx.Response.WriteHeader(status)
	_, _ = io.WriteString(ctx.Response, body)
}

func setHumanInteractionSecurityHeaders(header http.Header, script string) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	scriptPolicy := "script-src 'none'"
	if script != "" {
		digest := sha256.Sum256([]byte(script))
		scriptPolicy = "script-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	}
	header.Set("Content-Security-Policy", "default-src 'none'; "+scriptPolicy+
		"; style-src 'none'; img-src 'none'; font-src 'none'; media-src 'none'; connect-src 'none'; "+
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}
