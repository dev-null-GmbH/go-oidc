package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	humanFlowIssuer         = "https://auth.d0.eu"
	humanFlowClientID       = "dashboard-confidential-bff"
	humanFlowRedirectURI    = "https://dashboard.d0.eu/oidc/callback"
	humanFlowResource       = "https://api.d0.eu/accounting/v1"
	humanFlowACR            = "urn:d0:acr:passkey"
	humanFlowState          = "dashboard-state-0001"
	humanFlowNonce          = "dashboard-nonce-0001"
	humanFlowVerifier       = "human-flow-code-verifier-000000000000000000000000"
	humanFlowKeyAuthorityID = "dashboard-key-authority-0001"
	humanFlowGrantID        = "human-grant-000001"
	humanFlowSubject        = "pairwise-human-subject-0001"
	humanFlowOrganizationID = "organization-00000001"
	humanFlowMembershipID   = "membership-00000001"
	humanFlowCookieName     = "__Host-d0-human-oidc"
)

func TestHumanConfidentialBFFProviderEndToEndFlow(t *testing.T) {
	serverKey := oidctest.PrivatePS256JWK(t, "human-flow-server-key", goidc.KeyUsageSignature)
	clientKey := oidctest.PrivatePS256JWK(t, "human-flow-client-key", goidc.KeyUsageSignature)
	authority := newHumanFlowAuthority(t)
	client := &goidc.Client{
		ID:                          humanFlowClientID,
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 17,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{{
				Key:            clientKey.Public(),
				KeyAuthorityID: humanFlowKeyAuthorityID,
			}},
		},
		ClientMeta: goidc.ClientMeta{
			ApplicationType:   goidc.ApplicationTypeWeb,
			SubIdentifierType: goidc.SubIdentifierPairwise,
			IDTokenSigAlg:     goidc.SigAlgPS256,
			TokenAuthnMethod:  goidc.AuthnMethodPrivateKeyJWT,
			TokenAuthnSigAlg:  goidc.SigAlgPS256,
			RedirectURIs:      []string{humanFlowRedirectURI},
			ScopeIDs:          "offline_access openid profile",
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		},
	}

	var jtiMu sync.Mutex
	consumedJTIs := make(map[string]struct{})
	op, err := New(Config{
		Issuer: humanFlowIssuer,
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{serverKey}}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{goidc.SigAlgPS256},
	},
		WithStaticClients(client),
		WithScopes(goidc.ScopeOfflineAccess, goidc.ScopeOpenID, goidc.ScopeProfile),
		WithResourceIndicators([]goidc.ResourceIndicator{humanFlowResource}),
		WithACRs(humanFlowACR),
		WithJTIUseConsumer(func(_ context.Context, use goidc.JTIUse) error {
			if use.Purpose != goidc.JTIUsePurposeClientAssertion || use.ID == "" ||
				use.Issuer != humanFlowClientID || use.ExpiresAt.IsZero() {
				return goidc.ErrInvalidJTIUse
			}
			jtiMu.Lock()
			defer jtiMu.Unlock()
			if _, exists := consumedJTIs[use.ID]; exists {
				return goidc.ErrJTIReplay
			}
			consumedJTIs[use.ID] = struct{}{}
			return nil
		}),
		WithHumanConfidentialBFFAuthorizationAuthority(authority,
			WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
			WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
			WithHumanConfidentialBFFBrowserBindingCookieName(humanFlowCookieName),
		),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handler := op.Handler()

	parValues := url.Values{
		"client_id":             {humanFlowClientID},
		"client_assertion":      {humanFlowClientAssertion(t, clientKey, "human-flow-par")},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
		"redirect_uri":          {humanFlowRedirectURI},
		"response_type":         {string(goidc.ResponseTypeCode)},
		"response_mode":         {string(goidc.ResponseModeQuery)},
		"scope":                 {"offline_access openid profile"},
		"state":                 {humanFlowState},
		"nonce":                 {humanFlowNonce},
		"code_challenge":        {humanFlowCodeChallenge()},
		"code_challenge_method": {string(goidc.CodeChallengeMethodSHA256)},
		"prompt":                {string(goidc.PromptTypeLogin)},
		"max_age":               {"300"},
		"acr_values":            {humanFlowACR},
		"resource":              {humanFlowResource},
	}
	parResponse := humanFlowFormRequest(t, handler, "/par", parValues, nil)
	if parResponse.Code != http.StatusCreated || parResponse.Header().Get("Cache-Control") != "no-store" ||
		parResponse.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("PAR response = status %d headers %#v body %q",
			parResponse.Code, parResponse.Header(), parResponse.Body.String())
	}
	var parPayload struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	humanFlowDecodeJSON(t, parResponse, &parPayload)
	if parPayload.RequestURI != authority.requestURI || parPayload.ExpiresIn != 60 {
		t.Fatalf("PAR payload = %#v", parPayload)
	}

	authorizeTarget := "/authorize?" + url.Values{
		"client_id":   {humanFlowClientID},
		"request_uri": {parPayload.RequestURI},
	}.Encode()
	authorizeResponse := humanFlowRequest(t, handler, http.MethodGet, authorizeTarget, nil, nil)
	if authorizeResponse.Code != http.StatusSeeOther ||
		authorizeResponse.Header().Get("Location") !=
			"https://id.d0.eu/oidc/interaction/identity#"+authority.entry ||
		authorizeResponse.Header().Get("Cache-Control") != "no-store" ||
		authorizeResponse.Header().Get("Pragma") != "no-cache" ||
		authorizeResponse.Header().Get("Referrer-Policy") != "no-referrer" ||
		authorizeResponse.Body.Len() != 0 {
		t.Fatalf("authorize response = status %d headers %#v body %q",
			authorizeResponse.Code, authorizeResponse.Header(), authorizeResponse.Body.String())
	}
	browserBindingCookie := humanFlowBrowserBindingCookie(t, authorizeResponse.Result(), authority.binding)

	browserPage := humanFlowRequest(t, handler, http.MethodGet, "/oidc/interaction/browser", nil, nil)
	if browserPage.Code != http.StatusOK || browserPage.Header().Get("Set-Cookie") != "" ||
		!strings.Contains(browserPage.Body.String(), `action="/oidc/interaction/browser"`) {
		t.Fatalf("browser page = status %d headers %#v body %q",
			browserPage.Code, browserPage.Header(), browserPage.Body.String())
	}
	browserReturn := humanFlowBrowserReturn(t, browserPage.Body.String())
	browserResponse := humanFlowFormRequest(t, handler, "/oidc/interaction/browser", url.Values{
		"identity_return": {authority.identityReturn},
		"browser_return":  {browserReturn},
	}, map[string]string{
		"Cookie": browserBindingCookie.Name + "=" + browserBindingCookie.Value,
		"Origin": humanFlowIssuer,
	})
	if browserResponse.Code != http.StatusSeeOther ||
		browserResponse.Header().Get("Location") !=
			"https://id.d0.eu/oidc/interaction/ready#"+browserReturn ||
		browserResponse.Body.Len() != 0 {
		t.Fatalf("browser confirmation = status %d headers %#v body %q",
			browserResponse.Code, browserResponse.Header(), browserResponse.Body.String())
	}

	consumePage := humanFlowRequest(t, handler, http.MethodGet, "/oidc/interaction/consume", nil, nil)
	if consumePage.Code != http.StatusOK ||
		!strings.Contains(consumePage.Body.String(), `action="/oidc/interaction/consume"`) {
		t.Fatalf("consume page = status %d headers %#v body %q",
			consumePage.Code, consumePage.Header(), consumePage.Body.String())
	}
	consumeHeaders := map[string]string{
		"Cookie": browserBindingCookie.Name + "=" + browserBindingCookie.Value,
		"Origin": humanFlowIssuer,
	}
	completionResponse := humanFlowFormRequest(t, handler, "/oidc/interaction/consume", url.Values{
		"ready": {authority.ready},
	}, consumeHeaders)
	if completionResponse.Code != http.StatusSeeOther || completionResponse.Body.Len() != 0 {
		t.Fatalf("completion response = status %d headers %#v body %q",
			completionResponse.Code, completionResponse.Header(), completionResponse.Body.String())
	}
	completionURL, err := url.Parse(completionResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse completion redirect: %v", err)
	}
	if completionURL.Scheme+"://"+completionURL.Host+completionURL.Path != humanFlowRedirectURI ||
		completionURL.Query().Get("code") != authority.authorizationCode ||
		completionURL.Query().Get("state") != humanFlowState ||
		completionURL.Query().Get("iss") != humanFlowIssuer {
		t.Fatalf("completion redirect = %q", completionResponse.Header().Get("Location"))
	}
	humanFlowAssertCookieCleared(t, completionResponse.Result())

	completionReplay := humanFlowFormRequest(t, handler, "/oidc/interaction/consume", url.Values{
		"ready": {authority.ready},
	}, consumeHeaders)
	if completionReplay.Code != http.StatusBadRequest || completionReplay.Header().Get("Location") != "" ||
		strings.Contains(completionReplay.Body.String(), authority.authorizationCode) {
		t.Fatalf("completion replay = status %d headers %#v body %q",
			completionReplay.Code, completionReplay.Header(), completionReplay.Body.String())
	}

	codeValues := url.Values{
		"grant_type":            {string(goidc.GrantAuthorizationCode)},
		"code":                  {authority.authorizationCode},
		"redirect_uri":          {humanFlowRedirectURI},
		"code_verifier":         {humanFlowVerifier},
		"client_id":             {humanFlowClientID},
		"client_assertion":      {humanFlowClientAssertion(t, clientKey, "human-flow-code")},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	codeResponse := humanFlowFormRequest(t, handler, "/token", codeValues, nil)
	codeTokens := humanFlowDecodeTokenResponse(t, codeResponse, true)
	if codeTokens.RefreshToken != authority.refreshOne || codeTokens.IDToken == "" ||
		codeTokens.RefreshTokenExpiresIn < 3598 || codeTokens.RefreshTokenExpiresIn > 3600 {
		t.Fatalf("authorization-code token response = %#v", codeTokens)
	}
	accessClaims := humanFlowTokenClaims(t, codeTokens.AccessToken, serverKey, "at+jwt")
	humanFlowAssertAccessToken(t, accessClaims)
	idClaims := humanFlowTokenClaims(t, codeTokens.IDToken, serverKey, "JWT")
	humanFlowAssertIDToken(t, idClaims)

	codeReplayValues := humanFlowCloneValues(codeValues)
	codeReplayValues.Set("client_assertion", humanFlowClientAssertion(t, clientKey, "human-flow-code-replay"))
	codeReplay := humanFlowFormRequest(t, handler, "/token", codeReplayValues, nil)
	humanFlowAssertOAuthError(t, codeReplay, http.StatusBadRequest, goidc.ErrorCodeInvalidGrant)

	refreshValues := humanFlowRefreshValues(t, clientKey, authority.refreshOne, "human-flow-refresh")
	refreshResponse := humanFlowFormRequest(t, handler, "/token", refreshValues, nil)
	refreshTokens := humanFlowDecodeTokenResponse(t, refreshResponse, false)
	if refreshTokens.RefreshToken != authority.refreshTwo || refreshTokens.IDToken != "" ||
		refreshTokens.RefreshToken == codeTokens.RefreshToken {
		t.Fatalf("refresh token response = %#v", refreshTokens)
	}
	refreshClaims := humanFlowTokenClaims(t, refreshTokens.AccessToken, serverKey, "at+jwt")
	humanFlowAssertAccessToken(t, refreshClaims)
	if _, exists := refreshClaims[goidc.ClaimNonce]; exists {
		t.Fatalf("refresh access token replayed nonce: %#v", refreshClaims)
	}

	refreshReplayValues := humanFlowRefreshValues(t, clientKey, authority.refreshOne, "human-flow-refresh-replay")
	refreshReplay := humanFlowFormRequest(t, handler, "/token", refreshReplayValues, nil)
	humanFlowAssertOAuthError(t, refreshReplay, http.StatusBadRequest, goidc.ErrorCodeInvalidGrant)

	revocationResponse := humanFlowFormRequest(t, handler, "/revoke", url.Values{
		"token":                 {authority.refreshTwo},
		"token_type_hint":       {string(goidc.TokenHintRefresh)},
		"client_id":             {humanFlowClientID},
		"client_assertion":      {humanFlowClientAssertion(t, clientKey, "human-flow-revoke")},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}, nil)
	if revocationResponse.Code != http.StatusOK || revocationResponse.Body.Len() != 0 ||
		revocationResponse.Header().Get("Cache-Control") != "no-store" ||
		revocationResponse.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("revocation response = status %d headers %#v body %q",
			revocationResponse.Code, revocationResponse.Header(), revocationResponse.Body.String())
	}

	revokedRefresh := humanFlowFormRequest(t, handler, "/token",
		humanFlowRefreshValues(t, clientKey, authority.refreshTwo, "human-flow-refresh-revoked"), nil)
	humanFlowAssertOAuthError(t, revokedRefresh, http.StatusBadRequest, goidc.ErrorCodeInvalidGrant)
	authority.assertFinished(t)
}

type humanFlowAuthority struct {
	t *testing.T

	mu sync.Mutex

	requestURI        string
	entry             string
	binding           string
	identityReturn    string
	ready             string
	authorizationCode string
	refreshOne        string
	refreshTwo        string

	parStored        bool
	parConsumed      bool
	browserConfirmed bool
	completed        bool
	codeConsumed     bool
	refreshConsumed  map[string]bool
	revoked          map[string]bool
	calls            []string
}

func newHumanFlowAuthority(t *testing.T) *humanFlowAuthority {
	t.Helper()
	return &humanFlowAuthority{
		t:                 t,
		requestURI:        goidc.HumanPushedRequestURIPrefix + humanFlowEntropy(1),
		entry:             "d0_hio_e1_" + humanFlowEntropy(2),
		binding:           "d0_hio_b1_" + humanFlowEntropy(3),
		identityReturn:    "d0_hio_r1_" + humanFlowEntropy(4),
		ready:             "d0_hio_s1_" + humanFlowEntropy(5),
		authorizationCode: "d0_hac_1_" + humanFlowEntropy(6),
		refreshOne:        "d0_hrt_1_" + humanFlowEntropy(7),
		refreshTwo:        "d0_hrt_1_" + humanFlowEntropy(8),
		refreshConsumed:   make(map[string]bool),
		revoked:           make(map[string]bool),
	}
}

func (authority *humanFlowAuthority) StorePAR(
	_ context.Context,
	input goidc.HumanPARInput,
) (goidc.HumanPARDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "par")
	maxAge, hasMaxAge := input.MaxAuthenticationAge()
	if authority.parStored || !input.Valid() || input.ClientID() != humanFlowClientID ||
		input.ClientAssertionAuthority() != humanFlowVerifiedAuthority() ||
		input.RedirectURI() != humanFlowRedirectURI ||
		!slices.Equal(input.Scopes(), []string{"offline_access", "openid", "profile"}) ||
		!slices.Equal(input.Resources(), []string{humanFlowResource}) ||
		input.State() != humanFlowState || input.Nonce() != humanFlowNonce ||
		input.CodeChallenge() != humanFlowCodeChallenge() ||
		input.CodeChallengeMethod() != goidc.CodeChallengeMethodSHA256 ||
		input.ResponseType() != goidc.ResponseTypeCode || input.ResponseMode() != goidc.ResponseModeQuery ||
		input.Prompt() != goidc.PromptTypeLogin || !hasMaxAge || maxAge != 300 ||
		!slices.Equal(input.ACRValues(), []goidc.ACR{humanFlowACR}) {
		return goidc.HumanPARDecision{}, errors.New("unexpected strict PAR input")
	}
	authority.parStored = true
	requestURI, err := goidc.NewHumanPushedRequestURI(authority.requestURI)
	if err != nil {
		return goidc.HumanPARDecision{}, err
	}
	receipt, err := goidc.NewHumanPARReceipt(requestURI, 60)
	if err != nil {
		return goidc.HumanPARDecision{}, err
	}
	return goidc.NewHumanPARDecision(goidc.HumanPAROutcomeCreated, receipt)
}

func (authority *humanFlowAuthority) ConsumePARAndStartContinuation(
	_ context.Context,
	input goidc.HumanStartInput,
) (goidc.HumanStartDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "start")
	rendered, err := input.RequestURI().Render()
	if err != nil || !input.Valid() || input.ClientID() != humanFlowClientID || rendered != authority.requestURI {
		return goidc.HumanStartDecision{}, errors.New("unexpected strict start input")
	}
	if !authority.parStored || authority.parConsumed {
		return goidc.NewHumanStartDecision(goidc.HumanStartDecisionConfig{
			Outcome: goidc.HumanStartOutcomeRejected,
		})
	}
	authority.parConsumed = true
	entry, err := goidc.NewHumanInteractionEntryCapability(authority.entry)
	if err != nil {
		return goidc.HumanStartDecision{}, err
	}
	binding, err := goidc.NewHumanBrowserBindingCapability(authority.binding)
	if err != nil {
		return goidc.HumanStartDecision{}, err
	}
	return goidc.NewHumanStartDecision(goidc.HumanStartDecisionConfig{
		Outcome:                  goidc.HumanStartOutcomePending,
		EntryCapability:          entry,
		BrowserBindingCapability: binding,
		ExpiresAt:                time.Now().Unix() + 300,
	})
}

func (authority *humanFlowAuthority) ConfirmBrowser(
	_ context.Context,
	input goidc.HumanContinuationInput,
) (goidc.HumanContinuationDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "confirm")
	identityReturn, identityErr := input.IdentityReturnCapability().Render()
	_, browserErr := input.BrowserReturnCapability().Render()
	binding, bindingErr := input.BrowserBindingCapability().Render()
	if identityErr != nil || browserErr != nil || bindingErr != nil || !input.Valid() ||
		identityReturn != authority.identityReturn || binding != authority.binding ||
		!authority.parConsumed || authority.browserConfirmed {
		return goidc.HumanContinuationDecision{}, errors.New("unexpected browser confirmation input")
	}
	authority.browserConfirmed = true
	return goidc.NewHumanContinuationDecision(
		goidc.HumanContinuationOutcomeConfirmed,
		input.BrowserReturnCapability(),
	)
}

func (authority *humanFlowAuthority) CompleteAuthorization(
	_ context.Context,
	input goidc.HumanCompletionInput,
) (goidc.HumanCompletionDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "complete")
	ready, readyErr := input.ReadyCapability().Render()
	binding, bindingErr := input.BrowserBindingCapability().Render()
	if readyErr != nil || bindingErr != nil || !input.Valid() || ready != authority.ready ||
		binding != authority.binding || !authority.browserConfirmed {
		return goidc.HumanCompletionDecision{}, errors.New("unexpected completion input")
	}
	if authority.completed {
		return goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
			Outcome: goidc.HumanCompletionOutcomeReplayed,
		})
	}
	authority.completed = true
	code, err := goidc.NewHumanAuthorizationCode(authority.authorizationCode)
	if err != nil {
		return goidc.HumanCompletionDecision{}, err
	}
	return goidc.NewHumanCompletionDecision(goidc.HumanCompletionDecisionConfig{
		Outcome:                 goidc.HumanCompletionOutcomeCompleted,
		Profile:                 goidc.AuthorizationRequestProfileHumanConfidentialBFF,
		ClientID:                humanFlowClientID,
		ClientSnapshotRevision:  17,
		AdmissionKeyAuthorityID: humanFlowKeyAuthorityID,
		AuthorizationCode:       code,
		RedirectURI:             humanFlowRedirectURI,
		State:                   humanFlowState,
		CodeExpiresInSeconds:    60,
	})
}

func (authority *humanFlowAuthority) RedeemAuthorizationCode(
	_ context.Context,
	input goidc.HumanCodeRedemptionInput,
) (goidc.HumanCodeRedemptionDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "redeem")
	code, codeErr := input.AuthorizationCode().Render()
	if codeErr != nil || !input.Valid() || code != authority.authorizationCode ||
		input.CodeVerifier() != humanFlowVerifier || input.RedirectURI() != humanFlowRedirectURI ||
		input.ClientID() != humanFlowClientID ||
		input.ClientAssertionAuthority() != humanFlowVerifiedAuthority() || !authority.completed {
		return goidc.HumanCodeRedemptionDecision{}, errors.New("unexpected code redemption input")
	}
	if authority.codeConsumed {
		return goidc.NewHumanCodeRedemptionDecision(goidc.HumanCodeRedemptionDecisionConfig{
			Outcome: goidc.HumanCodeRedemptionOutcomeRejected,
		})
	}
	authority.codeConsumed = true
	now := time.Now().Unix()
	refresh, err := goidc.NewHumanRefreshToken(authority.refreshOne)
	if err != nil {
		return goidc.HumanCodeRedemptionDecision{}, err
	}
	return goidc.NewHumanCodeRedemptionDecision(goidc.HumanCodeRedemptionDecisionConfig{
		Outcome:                  goidc.HumanCodeRedemptionOutcomeRedeemed,
		RefreshToken:             refresh,
		RefreshTokenExpiresAt:    now + 3600,
		GrantID:                  humanFlowGrantID,
		Subject:                  humanFlowSubject,
		OrganizationID:           humanFlowOrganizationID,
		MembershipID:             humanFlowMembershipID,
		MembershipRevision:       7,
		ClientID:                 humanFlowClientID,
		ClientAssertionAuthority: humanFlowVerifiedAuthority(),
		Scopes:                   []string{"offline_access", "openid", "profile"},
		Resources:                []string{humanFlowResource},
		Nonce:                    humanFlowNonce,
		AuthenticationTime:       now - 5,
		AuthenticationContext:    humanFlowACR,
		AuthenticationMethods:    []string{"passkey"},
		CreatedAt:                now,
		ExpiresAt:                now + 60,
	})
}

func (authority *humanFlowAuthority) RotateRefreshToken(
	_ context.Context,
	input goidc.HumanRefreshRotationInput,
) (goidc.HumanRefreshRotationDecision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "rotate")
	presented, err := input.RefreshToken().Render()
	if err != nil || !input.Valid() || input.ClientID() != humanFlowClientID ||
		input.ClientAssertionAuthority() != humanFlowVerifiedAuthority() {
		return goidc.HumanRefreshRotationDecision{}, errors.New("unexpected refresh rotation input")
	}
	if authority.refreshConsumed[presented] || authority.revoked[presented] ||
		presented != authority.refreshOne {
		return goidc.NewHumanRefreshRotationDecision(goidc.HumanRefreshRotationDecisionConfig{
			Outcome: goidc.HumanRefreshRotationOutcomeRejected,
		})
	}
	authority.refreshConsumed[presented] = true
	now := time.Now().Unix()
	successor, err := goidc.NewHumanRefreshToken(authority.refreshTwo)
	if err != nil {
		return goidc.HumanRefreshRotationDecision{}, err
	}
	return goidc.NewHumanRefreshRotationDecision(goidc.HumanRefreshRotationDecisionConfig{
		Outcome:                  goidc.HumanRefreshRotationOutcomeRotated,
		RefreshToken:             successor,
		RefreshTokenExpiresAt:    now + 3600,
		GrantID:                  humanFlowGrantID,
		Subject:                  humanFlowSubject,
		OrganizationID:           humanFlowOrganizationID,
		MembershipID:             humanFlowMembershipID,
		MembershipRevision:       7,
		ClientID:                 humanFlowClientID,
		ClientAssertionAuthority: humanFlowVerifiedAuthority(),
		Scopes:                   []string{"offline_access", "openid", "profile"},
		Resources:                []string{humanFlowResource},
		AuthenticationTime:       now - 5,
		AuthenticationContext:    humanFlowACR,
		AuthenticationMethods:    []string{"passkey"},
		CreatedAt:                now,
		ExpiresAt:                now + 60,
	})
}

func (authority *humanFlowAuthority) RevokeRefreshToken(
	_ context.Context,
	input goidc.HumanRefreshRevocationInput,
) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, "revoke")
	presented, err := input.RefreshToken().Render()
	if err != nil || !input.Valid() || presented != authority.refreshTwo ||
		input.ClientID() != humanFlowClientID ||
		input.ClientAssertionAuthority() != humanFlowVerifiedAuthority() {
		return errors.New("unexpected refresh revocation input")
	}
	authority.revoked[presented] = true
	return nil
}

func (authority *humanFlowAuthority) assertFinished(t *testing.T) {
	t.Helper()
	authority.mu.Lock()
	defer authority.mu.Unlock()
	wantCalls := []string{
		"par", "start", "confirm", "complete", "complete", "redeem", "redeem",
		"rotate", "rotate", "revoke", "rotate",
	}
	if !authority.parStored || !authority.parConsumed || !authority.browserConfirmed ||
		!authority.completed || !authority.codeConsumed || !authority.refreshConsumed[authority.refreshOne] ||
		!authority.revoked[authority.refreshTwo] || !slices.Equal(authority.calls, wantCalls) {
		t.Fatalf("authority state incomplete: calls=%v par=%t/%t browser=%t completed=%t code=%t refresh=%v revoked=%v",
			authority.calls, authority.parStored, authority.parConsumed, authority.browserConfirmed,
			authority.completed, authority.codeConsumed, authority.refreshConsumed, authority.revoked)
	}
}

var _ goidc.HumanAuthorizationAuthority = (*humanFlowAuthority)(nil)

type humanFlowTokenResponse struct {
	AccessToken           string   `json:"access_token"`
	IDToken               string   `json:"id_token"`
	RefreshToken          string   `json:"refresh_token"`
	RefreshTokenExpiresIn int      `json:"refresh_token_expires_in"`
	ExpiresIn             int      `json:"expires_in"`
	TokenType             string   `json:"token_type"`
	Scope                 string   `json:"scope"`
	Resources             []string `json:"resources"`
}

func humanFlowDecodeTokenResponse(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantIDToken bool,
) humanFlowTokenResponse {
	t.Helper()
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token response = status %d headers %#v body %q",
			response.Code, response.Header(), response.Body.String())
	}
	var payload humanFlowTokenResponse
	humanFlowDecodeJSON(t, response, &payload)
	if payload.AccessToken == "" || payload.RefreshToken == "" || payload.ExpiresIn != 300 ||
		payload.TokenType != "Bearer" || payload.Scope != "offline_access openid profile" ||
		!slices.Equal(payload.Resources, []string{humanFlowResource}) ||
		(payload.IDToken != "") != wantIDToken {
		t.Fatalf("token payload = %#v", payload)
	}
	return payload
}

func humanFlowTokenClaims(
	t *testing.T,
	value string,
	serverKey goidc.JSONWebKey,
	wantType string,
) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(value, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatalf("parse PS256 token: %v", err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].Algorithm != string(jose.PS256) ||
		parsed.Headers[0].KeyID != serverKey.KeyID ||
		parsed.Headers[0].ExtraHeaders[jose.HeaderType] != wantType {
		t.Fatalf("token header = %#v, want kid %q PS256 typ %q", parsed.Headers, serverKey.KeyID, wantType)
	}
	var claims map[string]any
	if err := parsed.Claims(serverKey.Public().Key, &claims); err != nil {
		t.Fatalf("verify PS256 token: %v", err)
	}
	return claims
}

func humanFlowAssertAccessToken(t *testing.T, claims map[string]any) {
	t.Helper()
	humanFlowAssertClaim(t, claims, goidc.ClaimIssuer, humanFlowIssuer)
	humanFlowAssertClaim(t, claims, goidc.ClaimSubject, humanFlowSubject)
	humanFlowAssertClaim(t, claims, goidc.ClaimClientID, humanFlowClientID)
	humanFlowAssertClaim(t, claims, goidc.ClaimScope, "offline_access openid profile")
	humanFlowAssertClaim(t, claims, goidc.ClaimGrantID, humanFlowGrantID)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/organization_id", humanFlowOrganizationID)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/membership_id", humanFlowMembershipID)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/membership_revision", float64(7))
	if audience := humanFlowStringSliceClaim(t, claims, goidc.ClaimAudience); !slices.Equal(audience, []string{humanFlowResource}) {
		t.Fatalf("access token audience = %v", audience)
	}
	if lifetime := humanFlowIntegerClaim(t, claims, goidc.ClaimExpiry) -
		humanFlowIntegerClaim(t, claims, goidc.ClaimIssuedAt); lifetime != 300 {
		t.Fatalf("access token lifetime = %d, want 300", lifetime)
	}
}

func humanFlowAssertIDToken(t *testing.T, claims map[string]any) {
	t.Helper()
	humanFlowAssertClaim(t, claims, goidc.ClaimIssuer, humanFlowIssuer)
	humanFlowAssertClaim(t, claims, goidc.ClaimSubject, humanFlowSubject)
	humanFlowAssertClaim(t, claims, goidc.ClaimAudience, humanFlowClientID)
	humanFlowAssertClaim(t, claims, goidc.ClaimNonce, humanFlowNonce)
	humanFlowAssertClaim(t, claims, goidc.ClaimACR, humanFlowACR)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/organization_id", humanFlowOrganizationID)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/membership_id", humanFlowMembershipID)
	humanFlowAssertClaim(t, claims, "https://d0.eu/claims/membership_revision", float64(7))
	if methods := humanFlowStringSliceClaim(t, claims, goidc.ClaimAMR); !slices.Equal(methods, []string{"passkey"}) {
		t.Fatalf("ID token amr = %v", methods)
	}
	if lifetime := humanFlowIntegerClaim(t, claims, goidc.ClaimExpiry) -
		humanFlowIntegerClaim(t, claims, goidc.ClaimIssuedAt); lifetime != 600 {
		t.Fatalf("ID token lifetime = %d, want 600", lifetime)
	}
}

func humanFlowAssertClaim(t *testing.T, claims map[string]any, name string, want any) {
	t.Helper()
	if got := claims[name]; got != want {
		t.Fatalf("claim %q = %#v, want %#v", name, got, want)
	}
}

func humanFlowIntegerClaim(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()
	value, ok := claims[name].(float64)
	if !ok || value != float64(int64(value)) {
		t.Fatalf("claim %q = %#v, want integer", name, claims[name])
	}
	return int64(value)
}

func humanFlowStringSliceClaim(t *testing.T, claims map[string]any, name string) []string {
	t.Helper()
	values, ok := claims[name].([]any)
	if !ok {
		t.Fatalf("claim %q = %#v, want string array", name, claims[name])
	}
	result := make([]string, len(values))
	for index, value := range values {
		item, ok := value.(string)
		if !ok {
			t.Fatalf("claim %q[%d] = %#v, want string", name, index, value)
		}
		result[index] = item
	}
	return result
}

func humanFlowFormRequest(
	t *testing.T,
	handler http.Handler,
	target string,
	values url.Values,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	return humanFlowRequest(t, handler, http.MethodPost, target, strings.NewReader(values.Encode()),
		func() map[string]string {
			result := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			for name, value := range headers {
				result[name] = value
			}
			return result
		}(),
	)
}

func humanFlowRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	target string,
	body *strings.Reader,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, humanFlowIssuer+target, nil)
	} else {
		request = httptest.NewRequest(method, humanFlowIssuer+target, body)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func humanFlowClientAssertion(
	t *testing.T,
	key goidc.JSONWebKey,
	id string,
) string {
	t.Helper()
	now := time.Now().Unix()
	return oidctest.Sign(t, map[string]any{
		goidc.ClaimIssuer:   humanFlowClientID,
		goidc.ClaimSubject:  humanFlowClientID,
		goidc.ClaimAudience: humanFlowIssuer,
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + 50,
		goidc.ClaimTokenID:  id,
	}, key)
}

func humanFlowRefreshValues(
	t *testing.T,
	clientKey goidc.JSONWebKey,
	refreshToken string,
	assertionID string,
) url.Values {
	t.Helper()
	return url.Values{
		"grant_type":            {string(goidc.GrantRefreshToken)},
		"refresh_token":         {refreshToken},
		"client_id":             {humanFlowClientID},
		"client_assertion":      {humanFlowClientAssertion(t, clientKey, assertionID)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
}

func humanFlowAssertOAuthError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantCode goidc.ErrorCode,
) {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	humanFlowDecodeJSON(t, response, &payload)
	if response.Code != wantStatus || payload.Error != string(wantCode) {
		t.Fatalf("OAuth error response = status %d body %q, want %d/%s",
			response.Code, response.Body.String(), wantStatus, wantCode)
	}
}

func humanFlowDecodeJSON(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode JSON response %q: %v", response.Body.String(), err)
	}
}

func humanFlowBrowserBindingCookie(
	t *testing.T,
	response *http.Response,
	wantValue string,
) *http.Cookie {
	t.Helper()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize cookies = %#v, want one browser-binding cookie", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != humanFlowCookieName || cookie.Value != wantValue || cookie.Path != "/" ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.Domain != "" || cookie.MaxAge < 1 || cookie.MaxAge > 300 {
		t.Fatalf("browser-binding cookie = %#v", cookie)
	}
	return cookie
}

func humanFlowAssertCookieCleared(t *testing.T, response *http.Response) {
	t.Helper()
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != humanFlowCookieName || cookies[0].Value != "" ||
		cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cleared browser-binding cookie = %#v", cookies)
	}
}

func humanFlowBrowserReturn(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="browser_return" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("browser-return capability missing from page: %q", body)
	}
	if _, err := goidc.NewHumanBrowserReturnCapability(match[1]); err != nil {
		t.Fatalf("browser-return capability is invalid: %v", err)
	}
	return match[1]
}

func humanFlowCodeChallenge() string {
	digest := sha256.Sum256([]byte(humanFlowVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func humanFlowVerifiedAuthority() goidc.VerifiedClientAssertionAuthority {
	return goidc.VerifiedClientAssertionAuthority{
		SnapshotRevision: 17,
		KeyAuthorityID:   humanFlowKeyAuthorityID,
	}
}

func humanFlowEntropy(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func humanFlowCloneValues(source url.Values) url.Values {
	clone := make(url.Values, len(source))
	for name, values := range source {
		clone[name] = slices.Clone(values)
	}
	return clone
}
