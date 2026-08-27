package authorize

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	parRequestURIPrefix string = "urn:ietf:params:oauth:request_uri:"
	// formPostResponseTemplate is a HTML document intended to be used as the
	// response mode "form_post".
	// The parameters that are usually sent to the client via redirect will be
	// sent by posting a form to the client's redirect URI.
	formPostResponseTemplate string = `
	<html>
	<body onload="javascript:document.forms[0].submit()">
	  <form id="auth-response" method="post" action="{{ .redirect_uri }}">
	  	{{ if .iss }}
	    <input type="hidden" name="iss" value="{{ .iss }}"/>
		{{ end }}
	    {{ if .code }}
	    <input type="hidden" name="code" value="{{ .code }}"/>
		{{ end }}
	    {{ if .state }}
		<input type="hidden" name="state" value="{{ .state }}"/>
		{{ end }}
	    {{ if .access_token }}
		<input type="hidden" name="access_token" value="{{ .access_token }}"/>
		{{ end }}
	    {{ if .token_type }}
		<input type="hidden" name="token_type" value="{{ .token_type }}"/>
		{{ end }}
	    {{ if .id_token }}
		<input type="hidden" name="id_token" value="{{ .id_token }}"/>
		{{ end }}
	    {{ if .response }}
		<input type="hidden" name="response" value="{{ .response }}"/>
		{{ end }}
	    {{ if .error }}
		<input type="hidden" name="error" value="{{ .error }}"/>
		{{ end }}
	    {{ if .error_description }}
		<input type="hidden" name="error_description" value="{{ .error_description }}"/>
		{{ end }}
	  </form>
	</body>
	</html>
`
)

type request struct {
	ClientID string `json:"client_id"`
	goidc.AuthorizationParameters
	AdmissionTransport *requestAdmissionTransport `json:"-"`
}

type requestAdmissionTransport struct {
	parameters url.Values
	parseErr   error
}

// UnmarshalJSON makes sure the field "requested_expiry" can be unmarshalled
// either from an integer or an string.
func (req *request) UnmarshalJSON(data []byte) error {
	type alias request
	aux := &struct {
		RequestedExpiry json.RawMessage `json:"requested_expiry"`
		*alias
	}{
		alias: (*alias)(req),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.RequestedExpiry == nil {
		return nil
	}

	var intValue int
	if err := json.Unmarshal(aux.RequestedExpiry, &intValue); err == nil {
		req.RequestedExpiry = &intValue
		return nil
	}

	var strValue string
	if err := json.Unmarshal(aux.RequestedExpiry, &strValue); err != nil {
		return fmt.Errorf("requested_expiry is neither int nor string: %w", err)
	}

	intValue, err := strconv.Atoi(strValue)
	if err != nil {
		return fmt.Errorf("requested_expiry is an invalid integer string: %w", err)
	}
	req.RequestedExpiry = &intValue
	return nil
}

func newRequest(req *http.Request) request {
	query, parseErr := url.ParseQuery(req.URL.RawQuery)
	params := request{
		ClientID: query.Get("client_id"),
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:              query.Get("request_uri"),
			RequestObject:           query.Get("request"),
			RedirectURI:             query.Get("redirect_uri"),
			ResponseMode:            goidc.ResponseMode(query.Get("response_mode")),
			ResponseType:            goidc.ResponseType(query.Get("response_type")),
			Scopes:                  query.Get("scope"),
			State:                   query.Get("state"),
			Nonce:                   query.Get("nonce"),
			CodeChallenge:           query.Get("code_challenge"),
			CodeChallengeMethod:     goidc.CodeChallengeMethod(query.Get("code_challenge_method")),
			Prompt:                  goidc.PromptType(query.Get("prompt")),
			Display:                 goidc.DisplayValue(query.Get("display")),
			ACRValues:               query.Get("acr_values"),
			Resources:               query["resource"],
			DPoPJKT:                 query.Get("dpop_jkt"),
			LoginHint:               query.Get("login_hint"),
			LoginHintToken:          query.Get("login_hint_token"),
			IDTokenHint:             query.Get("id_token_hint"),
			ClientNotificationToken: query.Get("client_notification_token"),
			BindingMessage:          query.Get("binding_message"),
			UserCode:                query.Get("user_code"),
		},
		AdmissionTransport: captureRequestAdmissionTransport(query, parseErr),
	}

	if maxAge, err := strconv.Atoi(query.Get("max_age")); err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	if claims := query.Get("claims"); claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	if authorizationDetails := query.Get("authorization_details"); authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthDetails = authorizationDetailsObject
		}
	}

	if requestedExpiry, err := strconv.Atoi(query.Get("requested_expiry")); err == nil {
		params.RequestedExpiry = &requestedExpiry
	}

	return params
}

type response struct {
	response          string
	issuer            string
	accessToken       string
	tokenType         goidc.TokenType
	idToken           string
	authorizationCode string
	state             string
	errorCode         goidc.ErrorCode
	errorDescription  string
	errorURI          string
}

func (resp response) parameters() map[string]string {
	if resp.response != "" {
		return map[string]string{"response": resp.response}
	}

	params := make(map[string]string)

	if resp.issuer != "" {
		params["iss"] = resp.issuer
	}
	if resp.accessToken != "" {
		params["access_token"] = resp.accessToken
	}
	if resp.tokenType != "" {
		params["token_type"] = string(resp.tokenType)
	}
	if resp.idToken != "" {
		params["id_token"] = resp.idToken
	}
	if resp.authorizationCode != "" {
		params["code"] = resp.authorizationCode
	}
	if resp.state != "" {
		params["state"] = resp.state
	}
	if resp.errorCode != "" {
		params["error"] = string(resp.errorCode)
	}
	if resp.errorDescription != "" {
		params["error_description"] = resp.errorDescription
	}
	if resp.errorURI != "" {
		params["error_uri"] = resp.errorURI
	}

	return params
}

func newFormRequest(req *http.Request) request {
	parseErr := parseRequestForm(req)
	admissionTransport := captureRequestAdmissionTransport(req.PostForm, parseErr)
	params := goidc.AuthorizationParameters{
		RequestURI:              req.PostFormValue("request_uri"),
		RequestObject:           req.PostFormValue("request"),
		RedirectURI:             req.PostFormValue("redirect_uri"),
		ResponseMode:            goidc.ResponseMode(req.PostFormValue("response_mode")),
		ResponseType:            goidc.ResponseType(req.PostFormValue("response_type")),
		Scopes:                  req.PostFormValue("scope"),
		State:                   req.PostFormValue("state"),
		Nonce:                   req.PostFormValue("nonce"),
		CodeChallenge:           req.PostFormValue("code_challenge"),
		CodeChallengeMethod:     goidc.CodeChallengeMethod(req.PostFormValue("code_challenge_method")),
		Prompt:                  goidc.PromptType(req.PostFormValue("prompt")),
		Display:                 goidc.DisplayValue(req.PostFormValue("display")),
		ACRValues:               req.PostFormValue("acr_values"),
		Resources:               req.PostForm["resource"],
		DPoPJKT:                 req.PostFormValue("dpop_jkt"),
		LoginHint:               req.PostFormValue("login_hint"),
		LoginHintToken:          req.PostFormValue("login_hint_token"),
		IDTokenHint:             req.PostFormValue("id_token_hint"),
		ClientNotificationToken: req.PostFormValue("client_notification_token"),
		BindingMessage:          req.PostFormValue("binding_message"),
		UserCode:                req.PostFormValue("user_code"),
	}

	if maxAge, err := strconv.Atoi(req.PostFormValue("max_age")); err == nil {
		params.MaxAuthnAgeSecs = &maxAge
	}

	if claims := req.PostFormValue("claims"); claims != "" {
		var claimsObject goidc.ClaimsObject
		if err := json.Unmarshal([]byte(claims), &claimsObject); err == nil {
			params.Claims = &claimsObject
		}
	}

	if authorizationDetails := req.PostFormValue("authorization_details"); authorizationDetails != "" {
		var authorizationDetailsObject []goidc.AuthDetail
		if err := json.Unmarshal([]byte(authorizationDetails), &authorizationDetailsObject); err == nil {
			params.AuthDetails = authorizationDetailsObject
		}
	}

	if requestedExpiry, err := strconv.Atoi(req.PostFormValue("requested_expiry")); err == nil {
		params.RequestedExpiry = &requestedExpiry
	}

	return request{
		ClientID:                req.PostFormValue("client_id"),
		AuthorizationParameters: params,
		AdmissionTransport:      admissionTransport,
	}
}

func parseRequestForm(req *http.Request) error {
	// PostFormValue uses the same 32 MiB in-memory multipart threshold. Calling
	// the parser explicitly preserves that legacy behavior while retaining the
	// first parse error for strict request admission instead of discarding it.
	parseErr := req.ParseForm()
	multipartErr := req.ParseMultipartForm(32 << 20)
	if parseErr != nil {
		return parseErr
	}
	if errors.Is(multipartErr, http.ErrNotMultipart) {
		return nil
	}
	return multipartErr
}

func captureRequestAdmissionTransport(values url.Values, parseErr error) *requestAdmissionTransport {
	parameters := make(url.Values, len(values))
	for name, members := range values {
		parameters[name] = append([]string(nil), members...)
	}
	return &requestAdmissionTransport{parameters: parameters, parseErr: parseErr}
}

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

type cibaResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

func newAuthnSession(ctx oidc.Context, params goidc.AuthorizationParameters, c *goidc.Client) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:                      ctx.AuthnSessionID(),
		PersistenceID:           ctx.AuthnSessionPersistenceID(),
		Status:                  goidc.StatusPending,
		ClientID:                c.ID,
		AuthorizationParameters: params,
		CreatedAt:               timeutil.TimestampNow(),
		Store:                   make(map[string]any),
	}
}

func mergeParams(inParams goidc.AuthorizationParameters, outParams goidc.AuthorizationParameters) goidc.AuthorizationParameters {
	return goidc.AuthorizationParameters{
		RedirectURI:             nonZeroOrDefault(inParams.RedirectURI, outParams.RedirectURI),
		ResponseMode:            nonZeroOrDefault(inParams.ResponseMode, outParams.ResponseMode),
		ResponseType:            nonZeroOrDefault(inParams.ResponseType, outParams.ResponseType),
		Scopes:                  nonZeroOrDefault(inParams.Scopes, outParams.Scopes),
		State:                   nonZeroOrDefault(inParams.State, outParams.State),
		Nonce:                   nonZeroOrDefault(inParams.Nonce, outParams.Nonce),
		CodeChallenge:           nonZeroOrDefault(inParams.CodeChallenge, outParams.CodeChallenge),
		CodeChallengeMethod:     nonZeroOrDefault(inParams.CodeChallengeMethod, outParams.CodeChallengeMethod),
		Prompt:                  nonZeroOrDefault(inParams.Prompt, outParams.Prompt),
		MaxAuthnAgeSecs:         nonZeroOrDefault(inParams.MaxAuthnAgeSecs, outParams.MaxAuthnAgeSecs),
		Display:                 nonZeroOrDefault(inParams.Display, outParams.Display),
		ACRValues:               nonZeroOrDefault(inParams.ACRValues, outParams.ACRValues),
		Claims:                  nonZeroOrDefault(inParams.Claims, outParams.Claims),
		AuthDetails:             nonZeroOrDefault(inParams.AuthDetails, outParams.AuthDetails),
		Resources:               nonZeroOrDefault(inParams.Resources, outParams.Resources),
		DPoPJKT:                 nonZeroOrDefault(inParams.DPoPJKT, outParams.DPoPJKT),
		LoginHint:               nonZeroOrDefault(inParams.LoginHint, outParams.LoginHint),
		LoginHintToken:          nonZeroOrDefault(inParams.LoginHintToken, outParams.LoginHintToken),
		IDTokenHint:             nonZeroOrDefault(inParams.IDTokenHint, outParams.IDTokenHint),
		ClientNotificationToken: nonZeroOrDefault(inParams.ClientNotificationToken, outParams.ClientNotificationToken),
		BindingMessage:          nonZeroOrDefault(inParams.BindingMessage, outParams.BindingMessage),
		UserCode:                nonZeroOrDefault(inParams.UserCode, outParams.UserCode),
		RequestedExpiry:         nonZeroOrDefault(inParams.RequestedExpiry, outParams.RequestedExpiry),
	}
}

func nonZeroOrDefault[T any](s1 T, s2 T) T {
	if isNil(s1) || reflect.ValueOf(s1).IsZero() {
		return s2
	}

	return s1
}

func isNil(i any) bool {
	return i == nil
}
