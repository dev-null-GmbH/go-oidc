package token

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

const (
	humanRefreshDeliveryMaxFormBytes int64 = 16 * 1024

	humanRefreshDeliveryPredecessorParameter  = "refresh_token"
	humanRefreshDeliverySuccessorParameter    = "successor_refresh_token"
	humanRefreshDeliveryReceiptParameter      = "delivery_receipt"
	humanRefreshDeliveryMaximumAssertionBytes = 8 * 1024
)

type humanRefreshDeliveryOperation uint8

const (
	humanRefreshDeliveryPrepare humanRefreshDeliveryOperation = iota + 1
	humanRefreshDeliveryActivate
	humanRefreshDeliveryAbort
)

type humanRefreshDeliveryStatusResponse struct {
	Status    string `json:"status"`
	ExpiresIn int    `json:"expires_in"`
}

type humanRefreshDeliveryAbortResponse struct {
	Status string `json:"status"`
}

func handleHumanRefreshDeliveryPrepare(ctx oidc.Context) {
	setHumanRefreshDeliveryNoStore(ctx)
	limitHumanRefreshDeliveryFormBody(ctx)
	status, err := prepareHumanRefreshDelivery(ctx)
	if err != nil {
		writeHumanRefreshDeliveryError(ctx, err)
		return
	}
	if ctx.Err() == nil {
		if writeErr := ctx.Write(status, http.StatusOK); writeErr != nil && ctx.Err() == nil {
			ctx.WriteError(humanRefreshDeliveryServerError())
		}
	}
}

func handleHumanRefreshDeliveryActivate(ctx oidc.Context) {
	setHumanRefreshDeliveryNoStore(ctx)
	limitHumanRefreshDeliveryFormBody(ctx)
	tokenResponse, err := activateHumanRefreshDelivery(ctx)
	if err != nil {
		writeHumanRefreshDeliveryError(ctx, err)
		return
	}
	if ctx.Err() == nil {
		if writeErr := writeTokenResponse(ctx, tokenResponse); writeErr != nil && ctx.Err() == nil {
			ctx.WriteError(humanRefreshDeliveryServerError())
		}
	}
}

func handleHumanRefreshDeliveryAbort(ctx oidc.Context) {
	setHumanRefreshDeliveryNoStore(ctx)
	limitHumanRefreshDeliveryFormBody(ctx)
	outcome, err := abortHumanRefreshDelivery(ctx)
	if err != nil {
		writeHumanRefreshDeliveryError(ctx, err)
		return
	}
	statusCode := http.StatusOK
	if outcome == goidc.HumanRefreshDeliveryAbortOutcomeActivatedConflict {
		statusCode = http.StatusConflict
	}
	if ctx.Err() == nil {
		if writeErr := ctx.Write(humanRefreshDeliveryAbortResponse{Status: string(outcome)}, statusCode); writeErr != nil && ctx.Err() == nil {
			ctx.WriteError(humanRefreshDeliveryServerError())
		}
	}
}

func prepareHumanRefreshDelivery(ctx oidc.Context) (status humanRefreshDeliveryStatusResponse, err error) {
	defer func() {
		if recover() != nil {
			status = humanRefreshDeliveryStatusResponse{}
			err = humanRefreshDeliveryServerError()
		}
	}()
	if !validHumanRefreshDeliveryForm(ctx, humanRefreshDeliveryPrepare) {
		return status, humanAuthorizationInvalidRequest()
	}
	ctx, isolatedClient, assertionAuthority, err := authenticateHumanRefreshDeliveryClient(ctx)
	if err != nil {
		return status, err
	}
	predecessor, err := goidc.NewHumanRefreshToken(
		ctx.Request.PostFormValue(humanRefreshDeliveryPredecessorParameter),
	)
	if err != nil {
		return status, humanRefreshInvalidGrant()
	}
	successor, receipt, err := parseHumanRefreshDeliveryProof(ctx.Request)
	if err != nil {
		return status, humanRefreshInvalidGrant()
	}
	input, err := goidc.NewHumanRefreshDeliveryPrepareInput(goidc.HumanRefreshDeliveryPrepareInputConfig{
		PredecessorRefreshToken:  predecessor,
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 isolatedClient.ID,
		ClientAssertionAuthority: assertionAuthority,
	})
	if err != nil {
		return status, humanRefreshInvalidGrant()
	}
	decision, err := ctx.HumanPrepareRefreshDelivery(input)
	if err != nil {
		return status, humanRefreshDeliveryServerError()
	}
	if decision.Outcome() == goidc.HumanRefreshDeliveryPrepareOutcomeRejected {
		return status, humanRefreshInvalidGrant()
	}
	now := int64(timeutil.TimestampNow())
	if !validHumanRefreshDeliveryPrepareDecision(decision, isolatedClient, now, int64(ctx.JWTLeewayTimeSecs)) {
		return status, humanRefreshDeliveryServerError()
	}
	expiresIn := decision.ExpiresAt() - now
	if expiresIn < 0 {
		expiresIn = 0
	}
	if expiresIn > 300 {
		expiresIn = 300
	}
	if decision.Outcome() == goidc.HumanRefreshDeliveryPrepareOutcomePending && expiresIn < 1 {
		expiresIn = 1
	}
	return humanRefreshDeliveryStatusResponse{Status: string(decision.Outcome()), ExpiresIn: int(expiresIn)}, nil
}

func activateHumanRefreshDelivery(ctx oidc.Context) (tokenResponse response, err error) {
	defer func() {
		if recover() != nil {
			tokenResponse = response{}
			err = humanRefreshDeliveryServerError()
		}
	}()
	if !validHumanRefreshDeliveryForm(ctx, humanRefreshDeliveryActivate) {
		return response{}, humanAuthorizationInvalidRequest()
	}
	ctx, isolatedClient, assertionAuthority, err := authenticateHumanRefreshDeliveryClient(ctx)
	if err != nil {
		return response{}, err
	}
	policy, err := humanTokenPolicy(ctx, isolatedClient)
	if err != nil {
		return response{}, humanRefreshDeliveryServerError()
	}
	successor, receipt, err := parseHumanRefreshDeliveryProof(ctx.Request)
	if err != nil {
		return response{}, humanRefreshInvalidGrant()
	}
	input, err := goidc.NewHumanRefreshDeliveryActivateInput(goidc.HumanRefreshDeliveryActivateInputConfig{
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 isolatedClient.ID,
		ClientAssertionAuthority: assertionAuthority,
	})
	if err != nil {
		return response{}, humanRefreshInvalidGrant()
	}

	// This is the only state transition. Every fallible signing operation is
	// intentionally after the activated decision so an exact replay can recover
	// a response without rotating the family a second time.
	decision, err := ctx.HumanActivateRefreshDelivery(input)
	if err != nil {
		return response{}, humanRefreshDeliveryServerError()
	}
	if decision.Outcome() == goidc.HumanRefreshDeliveryActivateOutcomeRejected {
		return response{}, humanRefreshInvalidGrant()
	}
	now := timeutil.TimestampNow()
	if !validActivatedHumanRefreshDelivery(decision, isolatedClient, policy, int64(now)) {
		return response{}, humanRefreshDeliveryServerError()
	}
	refreshTokenValue, refreshTokenExpiresIn, err := humanRefreshTokenResponse(
		successor,
		true,
		decision.RefreshTokenExpiresAt(),
		int64(now),
		policy.authorityClockSkewSeconds,
	)
	if err != nil {
		return response{}, humanRefreshDeliveryServerError()
	}
	scopes := decision.Scopes()
	resources := decision.Resources()
	accessToken, err := issueHumanAccessToken(ctx, policy, humanAccessTokenFacts{
		grantID:            decision.GrantID(),
		subject:            decision.Subject(),
		organizationID:     decision.OrganizationID(),
		membershipID:       decision.MembershipID(),
		membershipRevision: decision.MembershipRevision(),
		clientID:           decision.ClientID(),
		scopes:             scopes,
		resources:          resources,
	}, now)
	if err != nil {
		return response{}, humanRefreshDeliveryServerError()
	}
	return response{
		AccessToken:           accessToken,
		RefreshToken:          refreshTokenValue,
		RefreshTokenExpiresIn: refreshTokenExpiresIn,
		ExpiresIn:             policy.accessTokenLifetimeSeconds,
		TokenType:             goidc.TokenTypeBearer,
		Scopes:                strings.Join(scopes, " "),
		Resources:             goidc.Resources(resources),
		noStore:               true,
	}, nil
}

func abortHumanRefreshDelivery(ctx oidc.Context) (outcome goidc.HumanRefreshDeliveryAbortOutcome, err error) {
	defer func() {
		if recover() != nil {
			outcome = ""
			err = humanRefreshDeliveryServerError()
		}
	}()
	if !validHumanRefreshDeliveryForm(ctx, humanRefreshDeliveryAbort) {
		return "", humanAuthorizationInvalidRequest()
	}
	ctx, isolatedClient, assertionAuthority, err := authenticateHumanRefreshDeliveryClient(ctx)
	if err != nil {
		return "", err
	}
	successor, receipt, err := parseHumanRefreshDeliveryProof(ctx.Request)
	if err != nil {
		return "", humanRefreshInvalidGrant()
	}
	input, err := goidc.NewHumanRefreshDeliveryAbortInput(goidc.HumanRefreshDeliveryAbortInputConfig{
		SuccessorRefreshToken:    successor,
		DeliveryReceipt:          receipt,
		ClientID:                 isolatedClient.ID,
		ClientAssertionAuthority: assertionAuthority,
	})
	if err != nil {
		return "", humanRefreshInvalidGrant()
	}
	decision, err := ctx.HumanAbortRefreshDelivery(input)
	if err != nil {
		return "", humanRefreshDeliveryServerError()
	}
	if decision.Outcome() == goidc.HumanRefreshDeliveryAbortOutcomeRejected {
		return "", humanRefreshInvalidGrant()
	}
	return decision.Outcome(), nil
}

func authenticateHumanRefreshDeliveryClient(
	ctx oidc.Context,
) (oidc.Context, *goidc.Client, goidc.VerifiedClientAssertionAuthority, error) {
	ctx = ctx.BeginClientAssertionAuthentication()
	authenticated, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return ctx, nil, goidc.VerifiedClientAssertionAuthority{}, err
	}
	isolated, err := isolateHumanTokenClient(authenticated)
	if err != nil {
		return ctx, nil, goidc.VerifiedClientAssertionAuthority{}, humanRefreshDeliveryServerError()
	}
	authority, err := ctx.ClientAssertionAuthority(isolated)
	if err != nil || !humanTokenAuthorityMatchesClient(authority, isolated) {
		return ctx, nil, goidc.VerifiedClientAssertionAuthority{}, humanRefreshDeliveryServerError()
	}
	return ctx, isolated, *authority, nil
}

func parseHumanRefreshDeliveryProof(
	request *http.Request,
) (goidc.HumanRefreshToken, goidc.HumanRefreshDeliveryReceipt, error) {
	if request == nil {
		return goidc.HumanRefreshToken{}, goidc.HumanRefreshDeliveryReceipt{}, errors.New("missing request")
	}
	successor, err := goidc.NewHumanRefreshToken(request.PostFormValue(humanRefreshDeliverySuccessorParameter))
	if err != nil {
		return goidc.HumanRefreshToken{}, goidc.HumanRefreshDeliveryReceipt{}, errors.New("invalid successor")
	}
	receipt, err := goidc.NewHumanRefreshDeliveryReceipt(request.PostFormValue(humanRefreshDeliveryReceiptParameter))
	if err != nil {
		return goidc.HumanRefreshToken{}, goidc.HumanRefreshDeliveryReceipt{}, errors.New("invalid receipt")
	}
	return successor, receipt, nil
}

func validHumanRefreshDeliveryForm(ctx oidc.Context, operation humanRefreshDeliveryOperation) bool {
	request := ctx.Request
	if request == nil || request.URL == nil || oidc.FormParseFailed(request) || request.Method != http.MethodPost ||
		request.URL.RawQuery != "" || request.URL.ForceQuery ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.TLS != nil && len(request.TLS.PeerCertificates) != 0 ||
		request.URL.Path != ctx.EndpointPrefix+humanRefreshDeliveryRoute(operation) {
		return false
	}
	for _, header := range []string{
		"Authorization",
		goidc.HeaderDPoP,
		"OAuth-Client-Attestation",
		"OAuth-Client-Attestation-PoP",
	} {
		if len(request.Header.Values(header)) != 0 {
			return false
		}
	}
	allowed := humanRefreshDeliveryParameters(operation)
	if len(request.PostForm) != len(allowed) {
		return false
	}
	for name, values := range request.PostForm {
		if !slices.Contains(allowed, name) || len(values) != 1 || values[0] == "" {
			return false
		}
	}
	clientID := request.PostFormValue("client_id")
	assertion := request.PostFormValue("client_assertion")
	if !humanTokenClientIDPattern.MatchString(clientID) || len(assertion) > humanRefreshDeliveryMaximumAssertionBytes ||
		request.PostFormValue("client_assertion_type") != string(goidc.AssertionTypeJWTBearer) {
		return false
	}
	if _, _, err := parseHumanRefreshDeliveryProof(request); err != nil {
		return false
	}
	if operation == humanRefreshDeliveryPrepare {
		predecessor, predecessorErr := goidc.NewHumanRefreshToken(
			request.PostFormValue(humanRefreshDeliveryPredecessorParameter),
		)
		successor, successorErr := goidc.NewHumanRefreshToken(
			request.PostFormValue(humanRefreshDeliverySuccessorParameter),
		)
		if predecessorErr != nil || successorErr != nil {
			return false
		}
		predecessorText, _ := predecessor.Render()
		successorText, _ := successor.Render()
		if predecessorText == successorText {
			return false
		}
	}
	return true
}

func humanRefreshDeliveryParameters(operation humanRefreshDeliveryOperation) []string {
	parameters := []string{
		humanRefreshDeliverySuccessorParameter,
		humanRefreshDeliveryReceiptParameter,
		"client_id",
		"client_assertion",
		"client_assertion_type",
	}
	if operation == humanRefreshDeliveryPrepare {
		return append([]string{humanRefreshDeliveryPredecessorParameter}, parameters...)
	}
	return parameters
}

func humanRefreshDeliveryRoute(operation humanRefreshDeliveryOperation) string {
	switch operation {
	case humanRefreshDeliveryPrepare:
		return goidc.HumanRefreshDeliveryPrepareRoute
	case humanRefreshDeliveryActivate:
		return goidc.HumanRefreshDeliveryActivateRoute
	case humanRefreshDeliveryAbort:
		return goidc.HumanRefreshDeliveryAbortRoute
	default:
		return ""
	}
}

func validHumanRefreshDeliveryPrepareDecision(
	decision goidc.HumanRefreshDeliveryPrepareDecision,
	client *goidc.Client,
	now int64,
	skew int64,
) bool {
	if !decision.Valid() || client == nil || decision.ClientID() != client.ID || now < 1 ||
		!validHumanAuthorityClockSkew(skew) || decision.CreatedAt() > now+skew {
		return false
	}
	if decision.Outcome() == goidc.HumanRefreshDeliveryPrepareOutcomePending {
		return humanAuthorityTimestampNotExpired(decision.ExpiresAt(), now, skew)
	}
	return decision.Outcome() == goidc.HumanRefreshDeliveryPrepareOutcomeActivated ||
		decision.Outcome() == goidc.HumanRefreshDeliveryPrepareOutcomeAborted
}

func validActivatedHumanRefreshDelivery(
	decision goidc.HumanRefreshDeliveryActivateDecision,
	client *goidc.Client,
	policy humanTokenIssuancePolicy,
	now int64,
) bool {
	if !decision.Valid() || decision.Outcome() != goidc.HumanRefreshDeliveryActivateOutcomeActivated {
		return false
	}
	scopes := decision.Scopes()
	resources := decision.Resources()
	return client != nil && decision.ClientID() == client.ID &&
		slices.Contains(scopes, goidc.ScopeOfflineAccess.ID) &&
		humanAuthorityTimestampNotExpired(decision.RefreshTokenExpiresAt(), now, policy.authorityClockSkewSeconds) &&
		humanTokenSortedSubset(scopes, strings.Split(client.ScopeIDs, " ")) &&
		humanTokenSortedSubset(scopes, policy.scopeIDs) && len(resources) != 0 &&
		policy.resourceIndicatorsEnabled && humanTokenSortedSubset(resources, policy.resourceIndicators) &&
		slices.Contains(policy.authenticationContexts, decision.AuthenticationContext()) &&
		decision.AuthenticationTime() <= decision.CreatedAt() &&
		validHumanAuthorityDecisionWindow(
			decision.CreatedAt(),
			decision.ExpiresAt(),
			now,
			policy.authorityClockSkewSeconds,
		)
}

func setHumanRefreshDeliveryNoStore(ctx oidc.Context) {
	if ctx.Response != nil {
		ctx.Response.Header().Set("Cache-Control", "no-store")
		ctx.Response.Header().Set("Pragma", "no-cache")
	}
}

func writeHumanRefreshDeliveryError(ctx oidc.Context, err error) {
	if ctx.Err() == nil {
		_ = ctx.WriteErrorResult(err)
	}
}

func limitHumanRefreshDeliveryFormBody(ctx oidc.Context) {
	if ctx.Request == nil || ctx.Request.Body == nil || ctx.Request.PostForm != nil {
		return
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Response, ctx.Request.Body, humanRefreshDeliveryMaxFormBytes)
}

func limitHumanRefreshDeliveryMiddlewareBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		request = oidc.ParseBoundedForm(response, request, humanRefreshDeliveryMaxFormBytes)
		next.ServeHTTP(response, request)
	})
}

func humanRefreshDeliveryServerError() error {
	return goidc.WrapError(
		goidc.ErrorCodeServerError,
		"server error",
		errors.New("human refresh delivery failed"),
	)
}
