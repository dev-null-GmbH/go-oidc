package authorize

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewAuthnSessionAllocatesPersistenceIDExactlyOnce(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	var sessionIDCalls int
	ctx.AuthSessionIDFunc = func(context.Context) string {
		sessionIDCalls++
		return "authn_session_id"
	}
	var persistenceIDCalls int
	ctx.AuthSessionPersistenceIDFunc = func(context.Context) string {
		persistenceIDCalls++
		return "authn_session_persistence_id"
	}

	session := newAuthnSession(ctx, goidc.AuthorizationParameters{}, client)

	if session.ID != "authn_session_id" {
		t.Fatalf("ID = %q, want %q", session.ID, "authn_session_id")
	}
	if session.PersistenceID != "authn_session_persistence_id" {
		t.Fatalf("PersistenceID = %q, want %q", session.PersistenceID, "authn_session_persistence_id")
	}
	if session.ID == session.PersistenceID {
		t.Fatal("authentication session ID and persistence ID must be generated independently")
	}
	if sessionIDCalls != 1 {
		t.Fatalf("AuthSessionIDFunc calls = %d, want 1", sessionIDCalls)
	}
	if persistenceIDCalls != 1 {
		t.Fatalf("AuthSessionPersistenceIDFunc calls = %d, want 1", persistenceIDCalls)
	}
}

func TestNewRequest(t *testing.T) {
	// Given.
	rawParams, params := setUpParams(t)
	rawParams.Set("client_id", "random_client_id")

	reqURL, _ := url.Parse("https://example.com/authorize")
	reqURL.RawQuery = rawParams.Encode()
	r := httptest.NewRequest(http.MethodPost, reqURL.String(), nil)

	// When.
	req := newRequest(r)

	// Then.
	want := request{
		ClientID:                "random_client_id",
		AuthorizationParameters: params,
	}
	if diff := cmp.Diff(req, want, cmpopts.EquateComparable()); diff != "" {
		t.Error(diff)
	}
}

func TestNewPushedRequest(t *testing.T) {
	// Given.
	rawParams, params := setUpParams(t)
	rawParams.Set("client_id", "random_client_id")

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(rawParams.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// When.
	req := newFormRequest(r)

	// Then.
	want := request{
		ClientID:                "random_client_id",
		AuthorizationParameters: params,
	}
	if diff := cmp.Diff(req, want, cmpopts.EquateComparable()); diff != "" {
		t.Error(diff)
	}
}

func TestMergeParams(t *testing.T) {
	// Given.
	insideParams := goidc.AuthorizationParameters{
		RedirectURI: "https:example1.com",
		State:       "random_state",
		AuthDetails: []goidc.AuthDetail{},
	}
	outsideParams := goidc.AuthorizationParameters{
		RedirectURI: "https:example2.com",
		Nonce:       "random_nonce",
		Claims:      &goidc.ClaimsObject{},
	}

	// When.
	mergedParams := mergeParams(insideParams, outsideParams)

	// Then.
	want := goidc.AuthorizationParameters{
		RedirectURI: "https:example1.com",
		State:       "random_state",
		AuthDetails: []goidc.AuthDetail{},
		Nonce:       "random_nonce",
		Claims:      &goidc.ClaimsObject{},
	}
	if diff := cmp.Diff(mergedParams, want, cmpopts.EquateComparable()); diff != "" {
		t.Error(diff)
	}
}

func setUpParams(t *testing.T) (url.Values, goidc.AuthorizationParameters) {
	t.Helper()

	rawParams := url.Values{}
	rawParams.Set("request_uri", "random_request_uri")
	rawParams.Set("request", "random_request_object")
	rawParams.Set("redirect_uri", "random_redirect_uri")
	rawParams.Set("response_mode", "query")
	rawParams.Set("response_type", "code")
	rawParams.Set("scope", "openid")
	rawParams.Set("state", "random_state")
	rawParams.Set("nonce", "random_nonce")
	rawParams.Set("code_challenge", "random_code_challenge")
	rawParams.Set("code_challenge_method", "S256")
	rawParams.Set("prompt", "login")
	rawParams.Set("display", "page")
	rawParams.Set("acr_values", "0 1")
	rawParams.Set("max_age", "0")
	rawParams.Set("claims", `{"id_token": {"auth_time": {"essential": true}}}`)
	rawParams.Set("authorization_details", `[{"key": "value"}]`)
	rawParams.Set("login_hint", "random_user")
	rawParams.Set("id_token_hint", "random_id_token")
	rawParams.Set("resource", "resource1")
	rawParams.Add("resource", "resource2")

	maxAge := 0
	params := goidc.AuthorizationParameters{
		RequestURI:          "random_request_uri",
		RequestObject:       "random_request_object",
		RedirectURI:         "random_redirect_uri",
		ResponseMode:        goidc.ResponseModeQuery,
		ResponseType:        goidc.ResponseTypeCode,
		Scopes:              "openid",
		State:               "random_state",
		Nonce:               "random_nonce",
		CodeChallenge:       "random_code_challenge",
		CodeChallengeMethod: goidc.CodeChallengeMethodSHA256,
		Prompt:              goidc.PromptTypeLogin,
		Display:             goidc.DisplayValuePage,
		ACRValues:           "0 1",
		MaxAuthnAgeSecs:     &maxAge,
		Claims: &goidc.ClaimsObject{
			IDToken: map[string]goidc.ClaimObjectInfo{
				"auth_time": {
					IsEssential: true,
				},
			},
		},
		AuthDetails: []goidc.AuthDetail{
			map[string]any{
				"key": "value",
			},
		},
		Resources:   []string{"resource1", "resource2"},
		LoginHint:   "random_user",
		IDTokenHint: "random_id_token",
	}

	return rawParams, params
}
