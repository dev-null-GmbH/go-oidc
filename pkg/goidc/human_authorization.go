package goidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const (
	// HumanPushedRequestURIPrefix is the strict PAR namespace. It is distinct
	// from legacy RFC 9126 handles so dispatch can fail closed across client
	// profile rotation.
	HumanPushedRequestURIPrefix      = "urn:ietf:params:oauth:request_uri:d0_hpar_1_"
	humanPushedRequestURIPrefix      = HumanPushedRequestURIPrefix
	humanEntryCapabilityPrefix       = "d0_hio_e1_"
	humanBrowserBindingPrefix        = "d0_hio_b1_"
	humanIdentityReturnPrefix        = "d0_hio_r1_"
	humanBrowserReturnPrefix         = "d0_hio_c1_"
	humanReadyCapabilityPrefix       = "d0_hio_s1_"
	humanAuthorizationCodePrefix     = "d0_hac_1_"
	humanRefreshCapabilityPrefix     = "d0_hrt_1_"
	humanCapabilityPayloadBytes      = 43
	maxHumanAuthorizationOpaqueBytes = 512
	maxHumanAuthorizationURIBytes    = 512
	maxHumanAuthorizationScopes      = 32
	maxHumanAuthorizationResources   = 8
	maxHumanAuthorizationMaxAge      = 24 * 60 * 60
	maxHumanRefreshTokenLifetime     = 24 * 60 * 60
)

var (
	// ErrInvalidHumanAuthorizationValue indicates that a value did not satisfy
	// the closed confidential-BFF authorization contract.
	ErrInvalidHumanAuthorizationValue = errors.New("invalid human authorization value")
	// ErrHumanAuthorizationSerialization prevents bearer capabilities and
	// authorization state from crossing generic JSON boundaries.
	ErrHumanAuthorizationSerialization = errors.New("human authorization serialization forbidden")

	humanAuthorizationClientIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanAuthorizationHandlePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$`)
	humanAuthorizationKeyIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	humanAuthorizationScopePattern     = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
	humanAuthorizationAssurancePattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`,
	)
	humanAuthorizationMethodPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)
	humanAuthorizationHostPattern   = regexp.MustCompile(
		`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`,
	)
	humanAuthorizationPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

// HumanAuthorizationAuthority owns every state transition in the strict human
// confidential-BFF authorization-code flow. Implementations must make each
// method atomic and safe for concurrent calls. A strict flow never falls back
// to AuthManager, PARManager, GrantManager, or mutable grant callbacks. Callback
// contexts inherit the request cancellation, deadline, and values; authorities
// must honor cancellation because the provider does not add a hidden timeout.
type HumanAuthorizationAuthority interface {
	StorePAR(context.Context, HumanPARInput) (HumanPARDecision, error)
	ConsumePARAndStartContinuation(context.Context, HumanStartInput) (HumanStartDecision, error)
	ConfirmBrowser(context.Context, HumanContinuationInput) (HumanContinuationDecision, error)
	CompleteAuthorization(context.Context, HumanCompletionInput) (HumanCompletionDecision, error)
	RedeemAuthorizationCode(context.Context, HumanCodeRedemptionInput) (HumanCodeRedemptionDecision, error)
	RotateRefreshToken(context.Context, HumanRefreshRotationInput) (HumanRefreshRotationDecision, error)
	// RevokeRefreshToken atomically revokes the family selected by a refresh
	// capability. Unknown, expired, already revoked, and client-mismatched
	// capabilities are acknowledged with nil so the RFC 7009 response never
	// exposes token state. Only an operational failure returns an error.
	RevokeRefreshToken(context.Context, HumanRefreshRevocationInput) error
}

// humanAuthorizationRedaction is embedded in every sealed boundary value. Its
// promoted methods make generic formatting and logging redacted and make
// generic JSON persistence fail closed.
type humanAuthorizationRedaction struct{}

func (humanAuthorizationRedaction) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[human authorization value]"))
}

func (humanAuthorizationRedaction) LogValue() slog.Value {
	return slog.StringValue("[human authorization value]")
}

func (humanAuthorizationRedaction) MarshalJSON() ([]byte, error) {
	return nil, ErrHumanAuthorizationSerialization
}

type humanRenderedValueState struct{ value string }

// HumanPushedRequestURI is the one-use RFC 9126 request_uri returned by the
// human authorization authority. Render is the sole raw transport accessor.
type HumanPushedRequestURI struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

// NewHumanPushedRequestURI validates and seals an authority-minted request_uri.
func NewHumanPushedRequestURI(value string) (HumanPushedRequestURI, error) {
	if !validHumanPushedRequestURI(value) {
		return HumanPushedRequestURI{}, ErrInvalidHumanAuthorizationValue
	}
	return HumanPushedRequestURI{state: &humanRenderedValueState{value: value}}, nil
}

func (value HumanPushedRequestURI) Valid() bool {
	return value.state != nil && validHumanPushedRequestURI(value.state.value)
}

func (value HumanPushedRequestURI) Render() (string, error) {
	if !value.Valid() {
		return "", ErrInvalidHumanAuthorizationValue
	}
	return value.state.value, nil
}

// HumanInteractionEntryCapability is the entry capability transported only in
// the fragment of the fixed identity-interaction endpoint.
type HumanInteractionEntryCapability struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanInteractionEntryCapability(value string) (HumanInteractionEntryCapability, error) {
	state, err := newHumanCapabilityState(value, humanEntryCapabilityPrefix)
	return HumanInteractionEntryCapability{state: state}, err
}

func (value HumanInteractionEntryCapability) Valid() bool {
	return validHumanCapabilityState(value.state, humanEntryCapabilityPrefix)
}
func (value HumanInteractionEntryCapability) Render() (string, error) {
	return renderHumanCapability(value.state, humanEntryCapabilityPrefix)
}

// HumanBrowserBindingCapability is transported only in the configured
// host-only Secure, HttpOnly, SameSite=Strict browser-binding cookie.
type HumanBrowserBindingCapability struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanBrowserBindingCapability(value string) (HumanBrowserBindingCapability, error) {
	state, err := newHumanCapabilityState(value, humanBrowserBindingPrefix)
	return HumanBrowserBindingCapability{state: state}, err
}

func (value HumanBrowserBindingCapability) Valid() bool {
	return validHumanCapabilityState(value.state, humanBrowserBindingPrefix)
}
func (value HumanBrowserBindingCapability) Render() (string, error) {
	return renderHumanCapability(value.state, humanBrowserBindingPrefix)
}

// HumanIdentityReturnCapability is accepted only by the auth-origin browser
// confirmation stage.
type HumanIdentityReturnCapability struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanIdentityReturnCapability(value string) (HumanIdentityReturnCapability, error) {
	state, err := newHumanCapabilityState(value, humanIdentityReturnPrefix)
	return HumanIdentityReturnCapability{state: state}, err
}

func (value HumanIdentityReturnCapability) Valid() bool {
	return validHumanCapabilityState(value.state, humanIdentityReturnPrefix)
}
func (value HumanIdentityReturnCapability) Render() (string, error) {
	return renderHumanCapability(value.state, humanIdentityReturnPrefix)
}

// HumanBrowserReturnCapability is the auth-origin successor transported to the
// identity-origin ready stage after browser confirmation.
type HumanBrowserReturnCapability struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanBrowserReturnCapability(value string) (HumanBrowserReturnCapability, error) {
	state, err := newHumanCapabilityState(value, humanBrowserReturnPrefix)
	return HumanBrowserReturnCapability{state: state}, err
}

func (value HumanBrowserReturnCapability) Valid() bool {
	return validHumanCapabilityState(value.state, humanBrowserReturnPrefix)
}
func (value HumanBrowserReturnCapability) Render() (string, error) {
	return renderHumanCapability(value.state, humanBrowserReturnPrefix)
}

// HumanReadyCapability is accepted only by the final auth-origin completion
// stage after the second identity-origin proof.
type HumanReadyCapability struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanReadyCapability(value string) (HumanReadyCapability, error) {
	state, err := newHumanCapabilityState(value, humanReadyCapabilityPrefix)
	return HumanReadyCapability{state: state}, err
}

func (value HumanReadyCapability) Valid() bool {
	return validHumanCapabilityState(value.state, humanReadyCapabilityPrefix)
}
func (value HumanReadyCapability) Render() (string, error) {
	return renderHumanCapability(value.state, humanReadyCapabilityPrefix)
}

// HumanAuthorizationCode is an authority-minted one-use authorization code.
// Render is the sole raw transport accessor.
type HumanAuthorizationCode struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanAuthorizationCode(value string) (HumanAuthorizationCode, error) {
	state, err := newHumanCapabilityState(value, humanAuthorizationCodePrefix)
	return HumanAuthorizationCode{state: state}, err
}

func (value HumanAuthorizationCode) Valid() bool {
	return validHumanCapabilityState(value.state, humanAuthorizationCodePrefix)
}
func (value HumanAuthorizationCode) Render() (string, error) {
	return renderHumanCapability(value.state, humanAuthorizationCodePrefix)
}

// HumanRefreshToken is an authority-minted, one-use refresh capability.
// Render is the sole raw transport accessor. Every successful rotation must
// replace it with a new capability before returning.
type HumanRefreshToken struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

// NewHumanRefreshToken validates and seals an authority-minted refresh token.
func NewHumanRefreshToken(value string) (HumanRefreshToken, error) {
	state, err := newHumanCapabilityState(value, humanRefreshCapabilityPrefix)
	return HumanRefreshToken{state: state}, err
}

func (value HumanRefreshToken) Valid() bool {
	return validHumanCapabilityState(value.state, humanRefreshCapabilityPrefix)
}

func (value HumanRefreshToken) Render() (string, error) {
	return renderHumanCapability(value.state, humanRefreshCapabilityPrefix)
}

func newHumanCapabilityState(value, prefix string) (*humanRenderedValueState, error) {
	if !validHumanCapability(value, prefix) {
		return nil, ErrInvalidHumanAuthorizationValue
	}
	return &humanRenderedValueState{value: value}, nil
}

func validHumanCapabilityState(state *humanRenderedValueState, prefix string) bool {
	return state != nil && validHumanCapability(state.value, prefix)
}

func renderHumanCapability(state *humanRenderedValueState, prefix string) (string, error) {
	if !validHumanCapabilityState(state, prefix) {
		return "", ErrInvalidHumanAuthorizationValue
	}
	return state.value, nil
}

func validHumanCapability(value, prefix string) bool {
	if len(value) != len(prefix)+humanCapabilityPayloadBytes || !strings.HasPrefix(value, prefix) {
		return false
	}
	return validHumanBase64URL256(value[len(prefix):])
}

// HumanPARInputConfig contains only the canonical fields admitted by the
// strict code/query/PAR/PKCE-S256 profile. The constructor copies all slices
// and pointer values before sealing them.
type HumanPARInputConfig struct {
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
	RedirectURI              string
	Scopes                   []string
	Resources                []string
	State                    string
	Nonce                    string
	CodeChallenge            string
	Prompt                   PromptType
	MaxAuthenticationAge     *int
	ACRValues                []ACR
}

type humanPARInputState struct {
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
	redirectURI              string
	scopes                   []string
	resources                []string
	state                    string
	nonce                    string
	codeChallenge            string
	prompt                   PromptType
	maxAuthenticationAge     *int
	acrValues                []ACR
}

// HumanPARInput is a sealed canonical pushed request. Unsupported request
// fields have no representation in this type.
type HumanPARInput struct {
	humanAuthorizationRedaction
	state *humanPARInputState
}

func NewHumanPARInput(config HumanPARInputConfig) (HumanPARInput, error) {
	state := &humanPARInputState{
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
		redirectURI:              config.RedirectURI,
		scopes:                   slices.Clone(config.Scopes),
		resources:                slices.Clone(config.Resources),
		state:                    config.State,
		nonce:                    config.Nonce,
		codeChallenge:            config.CodeChallenge,
		prompt:                   config.Prompt,
		maxAuthenticationAge:     cloneHumanAuthorizationInt(config.MaxAuthenticationAge),
		acrValues:                slices.Clone(config.ACRValues),
	}
	input := HumanPARInput{state: state}
	if !input.Valid() {
		return HumanPARInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanPARInput) Valid() bool {
	if input.state == nil {
		return false
	}
	state := input.state
	return validHumanClientID(state.clientID) &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority) &&
		validHumanAbsoluteHTTPSURI(state.redirectURI) &&
		validHumanStringSet(state.scopes, maxHumanAuthorizationScopes, humanAuthorizationScopePattern.MatchString) &&
		slices.Contains(state.scopes, ScopeOpenID.ID) &&
		validHumanStringSet(state.resources, maxHumanAuthorizationResources, validHumanAbsoluteHTTPSURI) &&
		validHumanOpaqueParameter(state.state) && validHumanOpaqueParameter(state.nonce) &&
		validHumanCodeChallenge(state.codeChallenge) &&
		(state.prompt == "" || state.prompt == PromptTypeLogin || state.prompt == PromptTypeNone) &&
		validHumanMaximumAuthenticationAge(state.maxAuthenticationAge) &&
		validHumanACRSet(state.acrValues)
}

func (input HumanPARInput) ClientID() string { return input.stateOrZero().clientID }
func (input HumanPARInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	return input.stateOrZero().clientAssertionAuthority
}
func (input HumanPARInput) RedirectURI() string        { return input.stateOrZero().redirectURI }
func (input HumanPARInput) Scopes() []string           { return slices.Clone(input.stateOrZero().scopes) }
func (input HumanPARInput) Resources() []string        { return slices.Clone(input.stateOrZero().resources) }
func (input HumanPARInput) State() string              { return input.stateOrZero().state }
func (input HumanPARInput) Nonce() string              { return input.stateOrZero().nonce }
func (input HumanPARInput) CodeChallenge() string      { return input.stateOrZero().codeChallenge }
func (input HumanPARInput) Prompt() PromptType         { return input.stateOrZero().prompt }
func (input HumanPARInput) ACRValues() []ACR           { return slices.Clone(input.stateOrZero().acrValues) }
func (input HumanPARInput) ResponseType() ResponseType { return ResponseTypeCode }
func (input HumanPARInput) ResponseMode() ResponseMode { return ResponseModeQuery }
func (input HumanPARInput) CodeChallengeMethod() CodeChallengeMethod {
	return CodeChallengeMethodSHA256
}
func (input HumanPARInput) MaxAuthenticationAge() (int, bool) {
	state := input.stateOrZero()
	if state.maxAuthenticationAge == nil {
		return 0, false
	}
	return *state.maxAuthenticationAge, true
}

func (input HumanPARInput) stateOrZero() *humanPARInputState {
	if input.state == nil {
		return &humanPARInputState{}
	}
	return input.state
}

type humanPARReceiptState struct {
	requestURI       HumanPushedRequestURI
	expiresInSeconds int
}

// HumanPARReceipt is the bounded successful result of StorePAR.
type HumanPARReceipt struct {
	humanAuthorizationRedaction
	state *humanPARReceiptState
}

func NewHumanPARReceipt(requestURI HumanPushedRequestURI, expiresInSeconds int) (HumanPARReceipt, error) {
	receipt := HumanPARReceipt{state: &humanPARReceiptState{
		requestURI: requestURI, expiresInSeconds: expiresInSeconds,
	}}
	if !receipt.Valid() {
		return HumanPARReceipt{}, ErrInvalidHumanAuthorizationValue
	}
	return receipt, nil
}

func (receipt HumanPARReceipt) Valid() bool {
	return receipt.state != nil && receipt.state.requestURI.Valid() &&
		receipt.state.expiresInSeconds > 0 && receipt.state.expiresInSeconds < 600
}
func (receipt HumanPARReceipt) RequestURI() HumanPushedRequestURI {
	if receipt.state == nil {
		return HumanPushedRequestURI{}
	}
	return receipt.state.requestURI
}
func (receipt HumanPARReceipt) ExpiresInSeconds() int {
	if receipt.state == nil {
		return 0
	}
	return receipt.state.expiresInSeconds
}

// HumanPAROutcome is the closed pushed-request admission result. Rejections do
// not expose whether a client, key, redirect, or replay check failed.
type HumanPAROutcome string

const (
	HumanPAROutcomeCreated  HumanPAROutcome = "created"
	HumanPAROutcomeRejected HumanPAROutcome = "rejected"
)

type humanPARDecisionState struct {
	outcome HumanPAROutcome
	receipt HumanPARReceipt
}

// HumanPARDecision distinguishes a normal protocol rejection from an
// operational error without exposing rejection details.
type HumanPARDecision struct {
	humanAuthorizationRedaction
	state *humanPARDecisionState
}

func NewHumanPARDecision(outcome HumanPAROutcome, receipt HumanPARReceipt) (HumanPARDecision, error) {
	decision := HumanPARDecision{state: &humanPARDecisionState{outcome: outcome, receipt: receipt}}
	if !decision.Valid() {
		return HumanPARDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}
func (decision HumanPARDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	switch decision.state.outcome {
	case HumanPAROutcomeCreated:
		return decision.state.receipt.Valid()
	case HumanPAROutcomeRejected:
		return !decision.state.receipt.Valid()
	default:
		return false
	}
}
func (decision HumanPARDecision) Outcome() HumanPAROutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanPARDecision) Receipt() (HumanPARReceipt, bool) {
	if decision.state == nil || !decision.state.receipt.Valid() {
		return HumanPARReceipt{}, false
	}
	return decision.state.receipt, true
}

type humanStartInputState struct {
	clientID   string
	requestURI HumanPushedRequestURI
}

// HumanStartInput is the exact outer authorization request accepted after
// strict transport parsing.
type HumanStartInput struct {
	humanAuthorizationRedaction
	state *humanStartInputState
}

func NewHumanStartInput(clientID string, requestURI HumanPushedRequestURI) (HumanStartInput, error) {
	input := HumanStartInput{state: &humanStartInputState{clientID: clientID, requestURI: requestURI}}
	if !input.Valid() {
		return HumanStartInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}
func (input HumanStartInput) Valid() bool {
	return input.state != nil && validHumanClientID(input.state.clientID) && input.state.requestURI.Valid()
}
func (input HumanStartInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}
func (input HumanStartInput) RequestURI() HumanPushedRequestURI {
	if input.state == nil {
		return HumanPushedRequestURI{}
	}
	return input.state.requestURI
}

type humanStartDecisionState struct {
	outcome        HumanStartOutcome
	entry          HumanInteractionEntryCapability
	browserBinding HumanBrowserBindingCapability
	expiresAt      int64
}

// HumanStartDecision contains only the two purpose-separated browser
// capabilities and the database-owned interaction deadline.
type HumanStartDecision struct {
	humanAuthorizationRedaction
	state *humanStartDecisionState
}

// HumanStartOutcome is the closed outer authorization result.
type HumanStartOutcome string

const (
	HumanStartOutcomePending  HumanStartOutcome = "pending"
	HumanStartOutcomeRejected HumanStartOutcome = "rejected"
)

type HumanStartDecisionConfig struct {
	Outcome                  HumanStartOutcome
	EntryCapability          HumanInteractionEntryCapability
	BrowserBindingCapability HumanBrowserBindingCapability
	ExpiresAt                int64
}

func NewHumanStartDecision(config HumanStartDecisionConfig) (HumanStartDecision, error) {
	decision := HumanStartDecision{state: &humanStartDecisionState{
		outcome: config.Outcome, entry: config.EntryCapability,
		browserBinding: config.BrowserBindingCapability, expiresAt: config.ExpiresAt,
	}}
	if !decision.Valid() {
		return HumanStartDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}
func (decision HumanStartDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	switch decision.state.outcome {
	case HumanStartOutcomePending:
		return decision.state.entry.Valid() && decision.state.browserBinding.Valid() && decision.state.expiresAt > 0
	case HumanStartOutcomeRejected:
		return !decision.state.entry.Valid() && !decision.state.browserBinding.Valid() && decision.state.expiresAt == 0
	default:
		return false
	}
}
func (decision HumanStartDecision) Outcome() HumanStartOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanStartDecision) EntryCapability() HumanInteractionEntryCapability {
	if decision.state == nil {
		return HumanInteractionEntryCapability{}
	}
	return decision.state.entry
}
func (decision HumanStartDecision) BrowserBindingCapability() HumanBrowserBindingCapability {
	if decision.state == nil {
		return HumanBrowserBindingCapability{}
	}
	return decision.state.browserBinding
}
func (decision HumanStartDecision) ExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.expiresAt
}

type humanContinuationInputState struct {
	identityReturn HumanIdentityReturnCapability
	browserReturn  HumanBrowserReturnCapability
	browserBinding HumanBrowserBindingCapability
}

// HumanContinuationInput is the exact auth-origin R+C+B browser-confirmation
// transition. C is generated before the explicit confirmation POST and is
// echoed only after the authority commits; S remains identity-origin authority.
type HumanContinuationInput struct {
	humanAuthorizationRedaction
	state *humanContinuationInputState
}

func NewHumanContinuationInput(
	identityReturn HumanIdentityReturnCapability,
	browserReturn HumanBrowserReturnCapability,
	browserBinding HumanBrowserBindingCapability,
) (HumanContinuationInput, error) {
	input := HumanContinuationInput{state: &humanContinuationInputState{
		identityReturn: identityReturn, browserReturn: browserReturn, browserBinding: browserBinding,
	}}
	if !input.Valid() {
		return HumanContinuationInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}
func (input HumanContinuationInput) Valid() bool {
	return input.state != nil && input.state.identityReturn.Valid() &&
		input.state.browserReturn.Valid() && input.state.browserBinding.Valid()
}
func (input HumanContinuationInput) IdentityReturnCapability() HumanIdentityReturnCapability {
	if input.state == nil {
		return HumanIdentityReturnCapability{}
	}
	return input.state.identityReturn
}
func (input HumanContinuationInput) BrowserReturnCapability() HumanBrowserReturnCapability {
	if input.state == nil {
		return HumanBrowserReturnCapability{}
	}
	return input.state.browserReturn
}
func (input HumanContinuationInput) BrowserBindingCapability() HumanBrowserBindingCapability {
	if input.state == nil {
		return HumanBrowserBindingCapability{}
	}
	return input.state.browserBinding
}

// HumanContinuationOutcome is the closed browser-confirmation result.
type HumanContinuationOutcome string

const (
	HumanContinuationOutcomeConfirmed HumanContinuationOutcome = "confirmed"
	HumanContinuationOutcomeReplayed  HumanContinuationOutcome = "replayed"
	HumanContinuationOutcomeExpired   HumanContinuationOutcome = "expired"
	HumanContinuationOutcomeRejected  HumanContinuationOutcome = "rejected"
)

type humanContinuationDecisionState struct {
	outcome       HumanContinuationOutcome
	browserReturn HumanBrowserReturnCapability
}

type HumanContinuationDecision struct {
	humanAuthorizationRedaction
	state *humanContinuationDecisionState
}

func NewHumanContinuationDecision(
	outcome HumanContinuationOutcome,
	browserReturn HumanBrowserReturnCapability,
) (HumanContinuationDecision, error) {
	decision := HumanContinuationDecision{state: &humanContinuationDecisionState{
		outcome: outcome, browserReturn: browserReturn,
	}}
	if !decision.Valid() {
		return HumanContinuationDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}
func (decision HumanContinuationDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	switch decision.state.outcome {
	case HumanContinuationOutcomeConfirmed, HumanContinuationOutcomeReplayed:
		return decision.state.browserReturn.Valid()
	case HumanContinuationOutcomeExpired, HumanContinuationOutcomeRejected:
		return !decision.state.browserReturn.Valid()
	default:
		return false
	}
}
func (decision HumanContinuationDecision) Outcome() HumanContinuationOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanContinuationDecision) BrowserReturnCapability() (HumanBrowserReturnCapability, bool) {
	if decision.state == nil || !decision.state.browserReturn.Valid() {
		return HumanBrowserReturnCapability{}, false
	}
	return decision.state.browserReturn, true
}

type humanCompletionInputState struct {
	ready          HumanReadyCapability
	browserBinding HumanBrowserBindingCapability
}

// HumanCompletionInput is the exact final S+B transition. The authority owns
// authorization-code randomness and persists only its one-use verifier.
type HumanCompletionInput struct {
	humanAuthorizationRedaction
	state *humanCompletionInputState
}

func NewHumanCompletionInput(
	ready HumanReadyCapability,
	browserBinding HumanBrowserBindingCapability,
) (HumanCompletionInput, error) {
	input := HumanCompletionInput{state: &humanCompletionInputState{
		ready: ready, browserBinding: browserBinding,
	}}
	if !input.Valid() {
		return HumanCompletionInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}
func (input HumanCompletionInput) Valid() bool {
	return input.state != nil && input.state.ready.Valid() && input.state.browserBinding.Valid()
}
func (input HumanCompletionInput) ReadyCapability() HumanReadyCapability {
	if input.state == nil {
		return HumanReadyCapability{}
	}
	return input.state.ready
}
func (input HumanCompletionInput) BrowserBindingCapability() HumanBrowserBindingCapability {
	if input.state == nil {
		return HumanBrowserBindingCapability{}
	}
	return input.state.browserBinding
}

// HumanCompletionOutcome is the closed final authorization result.
type HumanCompletionOutcome string

const (
	HumanCompletionOutcomeCompleted HumanCompletionOutcome = "completed"
	HumanCompletionOutcomeFailed    HumanCompletionOutcome = "failed"
	HumanCompletionOutcomeReplayed  HumanCompletionOutcome = "replayed"
	HumanCompletionOutcomeExpired   HumanCompletionOutcome = "expired"
	HumanCompletionOutcomeRejected  HumanCompletionOutcome = "rejected"
)

// HumanAuthorizationFailure is the bounded redirect-safe failure vocabulary.
type HumanAuthorizationFailure string

const (
	HumanAuthorizationFailureAccessDenied        HumanAuthorizationFailure = "access_denied"
	HumanAuthorizationFailureLoginRequired       HumanAuthorizationFailure = "login_required"
	HumanAuthorizationFailureInteractionRequired HumanAuthorizationFailure = "interaction_required"
	HumanAuthorizationFailureProtocolCancelled   HumanAuthorizationFailure = "protocol_cancelled"
)

type HumanCompletionDecisionConfig struct {
	Outcome                 HumanCompletionOutcome
	Profile                 AuthorizationRequestProfile
	ClientID                string
	ClientSnapshotRevision  int64
	AdmissionKeyAuthorityID string
	AuthorizationCode       HumanAuthorizationCode
	RedirectURI             string
	State                   string
	CodeExpiresInSeconds    int
	Failure                 HumanAuthorizationFailure
}

type humanCompletionDecisionState struct {
	outcome                 HumanCompletionOutcome
	profile                 AuthorizationRequestProfile
	clientID                string
	clientSnapshotRevision  int64
	admissionKeyAuthorityID string
	authorizationCode       HumanAuthorizationCode
	redirectURI             string
	state                   string
	codeExpiresInSeconds    int
	failure                 HumanAuthorizationFailure
}

// HumanCompletionDecision contains redirect material only for a completed or
// cleanly failed authorization. Terminal/replay outcomes carry no bearer or
// client-controlled value.
type HumanCompletionDecision struct {
	humanAuthorizationRedaction
	state *humanCompletionDecisionState
}

func NewHumanCompletionDecision(config HumanCompletionDecisionConfig) (HumanCompletionDecision, error) {
	decision := HumanCompletionDecision{state: &humanCompletionDecisionState{
		outcome: config.Outcome, profile: config.Profile, clientID: config.ClientID,
		clientSnapshotRevision:  config.ClientSnapshotRevision,
		admissionKeyAuthorityID: config.AdmissionKeyAuthorityID,
		authorizationCode:       config.AuthorizationCode,
		redirectURI:             config.RedirectURI, state: config.State,
		codeExpiresInSeconds: config.CodeExpiresInSeconds, failure: config.Failure,
	}}
	if !decision.Valid() {
		return HumanCompletionDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}
func (decision HumanCompletionDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	bound := state.profile == AuthorizationRequestProfileHumanConfidentialBFF &&
		validHumanClientID(state.clientID) && state.clientSnapshotRevision > 0 &&
		humanAuthorizationKeyIDPattern.MatchString(state.admissionKeyAuthorityID)
	switch state.outcome {
	case HumanCompletionOutcomeCompleted:
		return bound && state.authorizationCode.Valid() && validHumanAbsoluteHTTPSURI(state.redirectURI) &&
			validHumanOpaqueParameter(state.state) && state.codeExpiresInSeconds > 0 &&
			state.codeExpiresInSeconds <= 600 && state.failure == ""
	case HumanCompletionOutcomeFailed:
		return bound && !state.authorizationCode.Valid() && validHumanAbsoluteHTTPSURI(state.redirectURI) &&
			validHumanOpaqueParameter(state.state) && state.codeExpiresInSeconds == 0 &&
			validHumanAuthorizationFailure(state.failure)
	case HumanCompletionOutcomeReplayed, HumanCompletionOutcomeExpired, HumanCompletionOutcomeRejected:
		return state.profile == "" && state.clientID == "" && state.clientSnapshotRevision == 0 &&
			state.admissionKeyAuthorityID == "" && !state.authorizationCode.Valid() &&
			state.redirectURI == "" && state.state == "" &&
			state.codeExpiresInSeconds == 0 && state.failure == ""
	default:
		return false
	}
}
func (decision HumanCompletionDecision) Outcome() HumanCompletionOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanCompletionDecision) Profile() AuthorizationRequestProfile {
	if decision.state == nil {
		return ""
	}
	return decision.state.profile
}
func (decision HumanCompletionDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}
func (decision HumanCompletionDecision) ClientSnapshotRevision() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.clientSnapshotRevision
}
func (decision HumanCompletionDecision) AdmissionKeyAuthorityID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.admissionKeyAuthorityID
}
func (decision HumanCompletionDecision) AuthorizationCode() (HumanAuthorizationCode, bool) {
	if decision.state == nil || !decision.state.authorizationCode.Valid() {
		return HumanAuthorizationCode{}, false
	}
	return decision.state.authorizationCode, true
}
func (decision HumanCompletionDecision) RedirectURI() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.redirectURI
}
func (decision HumanCompletionDecision) State() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.state
}
func (decision HumanCompletionDecision) CodeExpiresInSeconds() int {
	if decision.state == nil {
		return 0
	}
	return decision.state.codeExpiresInSeconds
}
func (decision HumanCompletionDecision) Failure() HumanAuthorizationFailure {
	if decision.state == nil {
		return ""
	}
	return decision.state.failure
}

type HumanCodeRedemptionInputConfig struct {
	AuthorizationCode        HumanAuthorizationCode
	CodeVerifier             string
	RedirectURI              string
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

type humanCodeRedemptionInputState struct {
	authorizationCode        HumanAuthorizationCode
	codeVerifier             string
	redirectURI              string
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanCodeRedemptionInput binds the code to the freshly authenticated token
// endpoint client authority, exact redirect, and PKCE verifier.
type HumanCodeRedemptionInput struct {
	humanAuthorizationRedaction
	state *humanCodeRedemptionInputState
}

func NewHumanCodeRedemptionInput(config HumanCodeRedemptionInputConfig) (HumanCodeRedemptionInput, error) {
	input := HumanCodeRedemptionInput{state: &humanCodeRedemptionInputState{
		authorizationCode: config.AuthorizationCode, codeVerifier: config.CodeVerifier,
		redirectURI: config.RedirectURI, clientID: config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanCodeRedemptionInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}
func (input HumanCodeRedemptionInput) Valid() bool {
	return input.state != nil && input.state.authorizationCode.Valid() &&
		validHumanCodeVerifier(input.state.codeVerifier) &&
		validHumanAbsoluteHTTPSURI(input.state.redirectURI) && validHumanClientID(input.state.clientID) &&
		validHumanClientAssertionAuthority(input.state.clientAssertionAuthority)
}
func (input HumanCodeRedemptionInput) AuthorizationCode() HumanAuthorizationCode {
	if input.state == nil {
		return HumanAuthorizationCode{}
	}
	return input.state.authorizationCode
}
func (input HumanCodeRedemptionInput) CodeVerifier() string {
	if input.state == nil {
		return ""
	}
	return input.state.codeVerifier
}
func (input HumanCodeRedemptionInput) RedirectURI() string {
	if input.state == nil {
		return ""
	}
	return input.state.redirectURI
}
func (input HumanCodeRedemptionInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}
func (input HumanCodeRedemptionInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

type HumanCodeRedemptionDecisionConfig struct {
	Outcome                  HumanCodeRedemptionOutcome
	RefreshToken             HumanRefreshToken
	RefreshTokenExpiresAt    int64
	GrantID                  string
	Subject                  string
	OrganizationID           string
	MembershipID             string
	MembershipRevision       int64
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
	Scopes                   []string
	Resources                []string
	Nonce                    string
	AuthenticationTime       int64
	AuthenticationContext    string
	AuthenticationMethods    []string
	CreatedAt                int64
	ExpiresAt                int64
}

type humanCodeRedemptionDecisionState struct {
	outcome                  HumanCodeRedemptionOutcome
	refreshToken             HumanRefreshToken
	refreshTokenExpiresAt    int64
	grantID                  string
	subject                  string
	organizationID           string
	membershipID             string
	membershipRevision       int64
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
	scopes                   []string
	resources                []string
	nonce                    string
	authenticationTime       int64
	authenticationContext    string
	authenticationMethods    []string
	createdAt                int64
	expiresAt                int64
}

// HumanCodeRedemptionDecision is the immutable, already-pairwise grant
// authority returned after atomic one-use code consumption.
type HumanCodeRedemptionDecision struct {
	humanAuthorizationRedaction
	state *humanCodeRedemptionDecisionState
}

// HumanCodeRedemptionOutcome keeps replay, expiry, PKCE mismatch, redirect
// mismatch, and authority mismatch inside one indistinguishable rejection.
type HumanCodeRedemptionOutcome string

const (
	HumanCodeRedemptionOutcomeRedeemed HumanCodeRedemptionOutcome = "redeemed"
	HumanCodeRedemptionOutcomeRejected HumanCodeRedemptionOutcome = "rejected"
)

func NewHumanCodeRedemptionDecision(config HumanCodeRedemptionDecisionConfig) (HumanCodeRedemptionDecision, error) {
	decision := HumanCodeRedemptionDecision{state: &humanCodeRedemptionDecisionState{
		outcome: config.Outcome, refreshToken: config.RefreshToken,
		refreshTokenExpiresAt: config.RefreshTokenExpiresAt,
		grantID:               config.GrantID, subject: config.Subject,
		organizationID: config.OrganizationID, membershipID: config.MembershipID,
		membershipRevision: config.MembershipRevision, clientID: config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
		scopes:                   slices.Clone(config.Scopes), resources: slices.Clone(config.Resources),
		nonce: config.Nonce, authenticationTime: config.AuthenticationTime,
		authenticationContext: config.AuthenticationContext,
		authenticationMethods: slices.Clone(config.AuthenticationMethods),
		createdAt:             config.CreatedAt, expiresAt: config.ExpiresAt,
	}}
	if !decision.Valid() {
		return HumanCodeRedemptionDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}
func (decision HumanCodeRedemptionDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	if state.outcome == HumanCodeRedemptionOutcomeRejected {
		return !state.refreshToken.Valid() && state.refreshTokenExpiresAt == 0 &&
			state.grantID == "" && state.subject == "" && state.organizationID == "" &&
			state.membershipID == "" && state.membershipRevision == 0 && state.clientID == "" &&
			state.clientAssertionAuthority == (VerifiedClientAssertionAuthority{}) &&
			len(state.scopes) == 0 && len(state.resources) == 0 && state.nonce == "" &&
			state.authenticationTime == 0 && state.authenticationContext == "" &&
			len(state.authenticationMethods) == 0 && state.createdAt == 0 && state.expiresAt == 0
	}
	hasOfflineAccess := slices.Contains(state.scopes, ScopeOfflineAccess.ID)
	validRefreshToken := state.refreshToken.Valid() &&
		validHumanRefreshTokenExpiry(state.createdAt, state.refreshTokenExpiresAt)
	return state.outcome == HumanCodeRedemptionOutcomeRedeemed &&
		humanAuthorizationHandlePattern.MatchString(state.grantID) &&
		validHumanOpaqueParameter(state.subject) && validHumanClientID(state.clientID) &&
		humanAuthorizationHandlePattern.MatchString(state.organizationID) &&
		humanAuthorizationHandlePattern.MatchString(state.membershipID) && state.membershipRevision > 0 &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority) &&
		validHumanStringSet(state.scopes, maxHumanAuthorizationScopes, humanAuthorizationScopePattern.MatchString) &&
		slices.Contains(state.scopes, ScopeOpenID.ID) &&
		validHumanStringSet(state.resources, maxHumanAuthorizationResources, validHumanAbsoluteHTTPSURI) &&
		validHumanOpaqueParameter(state.nonce) && state.authenticationTime > 0 &&
		state.authenticationTime <= state.createdAt &&
		humanAuthorizationAssurancePattern.MatchString(state.authenticationContext) &&
		validHumanStringSet(state.authenticationMethods, 8, humanAuthorizationMethodPattern.MatchString) &&
		state.createdAt > 0 && state.expiresAt > state.createdAt && state.expiresAt-state.createdAt <= 600 &&
		(hasOfflineAccess && validRefreshToken ||
			!hasOfflineAccess && !state.refreshToken.Valid() && state.refreshTokenExpiresAt == 0)
}
func (decision HumanCodeRedemptionDecision) Outcome() HumanCodeRedemptionOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanCodeRedemptionDecision) RefreshToken() (HumanRefreshToken, bool) {
	if decision.state == nil || !decision.state.refreshToken.Valid() {
		return HumanRefreshToken{}, false
	}
	return decision.state.refreshToken, true
}
func (decision HumanCodeRedemptionDecision) RefreshTokenExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.refreshTokenExpiresAt
}
func (decision HumanCodeRedemptionDecision) GrantID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.grantID
}
func (decision HumanCodeRedemptionDecision) Subject() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.subject
}
func (decision HumanCodeRedemptionDecision) OrganizationID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.organizationID
}
func (decision HumanCodeRedemptionDecision) MembershipID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.membershipID
}
func (decision HumanCodeRedemptionDecision) MembershipRevision() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.membershipRevision
}
func (decision HumanCodeRedemptionDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}
func (decision HumanCodeRedemptionDecision) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if decision.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return decision.state.clientAssertionAuthority
}
func (decision HumanCodeRedemptionDecision) Scopes() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.scopes)
}
func (decision HumanCodeRedemptionDecision) Resources() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.resources)
}
func (decision HumanCodeRedemptionDecision) Nonce() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.nonce
}
func (decision HumanCodeRedemptionDecision) AuthenticationTime() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.authenticationTime
}
func (decision HumanCodeRedemptionDecision) AuthenticationContext() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.authenticationContext
}
func (decision HumanCodeRedemptionDecision) AuthenticationMethods() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.authenticationMethods)
}
func (decision HumanCodeRedemptionDecision) CreatedAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.createdAt
}
func (decision HumanCodeRedemptionDecision) ExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.expiresAt
}

// HumanRefreshRotationInputConfig binds a one-use refresh capability to the
// freshly authenticated confidential client authority at the token endpoint.
type HumanRefreshRotationInputConfig struct {
	RefreshToken             HumanRefreshToken
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

type humanRefreshRotationInputState struct {
	refreshToken             HumanRefreshToken
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshRotationInput is the sealed input to atomic refresh rotation.
// Unsupported refresh grant parameters have no representation in this type.
type HumanRefreshRotationInput struct {
	humanAuthorizationRedaction
	state *humanRefreshRotationInputState
}

func NewHumanRefreshRotationInput(config HumanRefreshRotationInputConfig) (HumanRefreshRotationInput, error) {
	input := HumanRefreshRotationInput{state: &humanRefreshRotationInputState{
		refreshToken: config.RefreshToken, clientID: config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanRefreshRotationInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanRefreshRotationInput) Valid() bool {
	return input.state != nil && input.state.refreshToken.Valid() &&
		validHumanClientID(input.state.clientID) &&
		validHumanClientAssertionAuthority(input.state.clientAssertionAuthority)
}

func (input HumanRefreshRotationInput) RefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.refreshToken
}

func (input HumanRefreshRotationInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}

func (input HumanRefreshRotationInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

// HumanRefreshRevocationInputConfig binds an RFC 7009 refresh-family
// revocation to the freshly authenticated confidential client authority.
type HumanRefreshRevocationInputConfig struct {
	RefreshToken             HumanRefreshToken
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

type humanRefreshRevocationInputState struct {
	refreshToken             HumanRefreshToken
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshRevocationInput is the sealed input to atomic family
// revocation. The presented capability is redacted and cannot be serialized.
type HumanRefreshRevocationInput struct {
	humanAuthorizationRedaction
	state *humanRefreshRevocationInputState
}

func NewHumanRefreshRevocationInput(
	config HumanRefreshRevocationInputConfig,
) (HumanRefreshRevocationInput, error) {
	input := HumanRefreshRevocationInput{state: &humanRefreshRevocationInputState{
		refreshToken: config.RefreshToken, clientID: config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanRefreshRevocationInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanRefreshRevocationInput) Valid() bool {
	return input.state != nil && input.state.refreshToken.Valid() &&
		validHumanClientID(input.state.clientID) &&
		validHumanClientAssertionAuthority(input.state.clientAssertionAuthority)
}

func (input HumanRefreshRevocationInput) RefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.refreshToken
}

func (input HumanRefreshRevocationInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}

func (input HumanRefreshRevocationInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

// HumanRefreshRotationOutcome deliberately collapses replay, expiry,
// revocation, inactive identity state, and client-authority mismatch into one
// protocol rejection.
type HumanRefreshRotationOutcome string

const (
	HumanRefreshRotationOutcomeRotated  HumanRefreshRotationOutcome = "rotated"
	HumanRefreshRotationOutcomeRejected HumanRefreshRotationOutcome = "rejected"
)

// HumanRefreshRotationDecisionConfig contains an authority-owned successor and
// a short-lived immutable issuance snapshot. RefreshTokenExpiresAt is the
// refresh family's absolute deadline and is independent from ExpiresAt, which
// bounds only the freshness of this access-token issuance decision.
type HumanRefreshRotationDecisionConfig struct {
	Outcome                  HumanRefreshRotationOutcome
	RefreshToken             HumanRefreshToken
	RefreshTokenExpiresAt    int64
	GrantID                  string
	Subject                  string
	OrganizationID           string
	MembershipID             string
	MembershipRevision       int64
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
	Scopes                   []string
	Resources                []string
	AuthenticationTime       int64
	AuthenticationContext    string
	AuthenticationMethods    []string
	CreatedAt                int64
	ExpiresAt                int64
}

type humanRefreshRotationDecisionState struct {
	outcome                  HumanRefreshRotationOutcome
	refreshToken             HumanRefreshToken
	refreshTokenExpiresAt    int64
	grantID                  string
	subject                  string
	organizationID           string
	membershipID             string
	membershipRevision       int64
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
	scopes                   []string
	resources                []string
	authenticationTime       int64
	authenticationContext    string
	authenticationMethods    []string
	createdAt                int64
	expiresAt                int64
}

// HumanRefreshRotationDecision is returned only after the authority has
// atomically consumed the presented token and installed its successor.
type HumanRefreshRotationDecision struct {
	humanAuthorizationRedaction
	state *humanRefreshRotationDecisionState
}

func NewHumanRefreshRotationDecision(
	config HumanRefreshRotationDecisionConfig,
) (HumanRefreshRotationDecision, error) {
	decision := HumanRefreshRotationDecision{state: &humanRefreshRotationDecisionState{
		outcome: config.Outcome, refreshToken: config.RefreshToken,
		refreshTokenExpiresAt: config.RefreshTokenExpiresAt,
		grantID:               config.GrantID, subject: config.Subject,
		organizationID: config.OrganizationID, membershipID: config.MembershipID,
		membershipRevision: config.MembershipRevision, clientID: config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
		scopes:                   slices.Clone(config.Scopes), resources: slices.Clone(config.Resources),
		authenticationTime:    config.AuthenticationTime,
		authenticationContext: config.AuthenticationContext,
		authenticationMethods: slices.Clone(config.AuthenticationMethods),
		createdAt:             config.CreatedAt, expiresAt: config.ExpiresAt,
	}}
	if !decision.Valid() {
		return HumanRefreshRotationDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}

func (decision HumanRefreshRotationDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	if state.outcome == HumanRefreshRotationOutcomeRejected {
		return !state.refreshToken.Valid() && state.refreshTokenExpiresAt == 0 &&
			state.grantID == "" && state.subject == "" && state.organizationID == "" &&
			state.membershipID == "" && state.membershipRevision == 0 && state.clientID == "" &&
			state.clientAssertionAuthority == (VerifiedClientAssertionAuthority{}) &&
			len(state.scopes) == 0 && len(state.resources) == 0 && state.authenticationTime == 0 &&
			state.authenticationContext == "" && len(state.authenticationMethods) == 0 &&
			state.createdAt == 0 && state.expiresAt == 0
	}
	return state.outcome == HumanRefreshRotationOutcomeRotated && state.refreshToken.Valid() &&
		validHumanRefreshTokenExpiry(state.createdAt, state.refreshTokenExpiresAt) &&
		humanAuthorizationHandlePattern.MatchString(state.grantID) &&
		validHumanOpaqueParameter(state.subject) && validHumanClientID(state.clientID) &&
		humanAuthorizationHandlePattern.MatchString(state.organizationID) &&
		humanAuthorizationHandlePattern.MatchString(state.membershipID) && state.membershipRevision > 0 &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority) &&
		validHumanStringSet(state.scopes, maxHumanAuthorizationScopes, humanAuthorizationScopePattern.MatchString) &&
		slices.Contains(state.scopes, ScopeOpenID.ID) && slices.Contains(state.scopes, ScopeOfflineAccess.ID) &&
		validHumanStringSet(state.resources, maxHumanAuthorizationResources, validHumanAbsoluteHTTPSURI) &&
		state.authenticationTime > 0 && state.authenticationTime <= state.createdAt &&
		humanAuthorizationAssurancePattern.MatchString(state.authenticationContext) &&
		validHumanStringSet(state.authenticationMethods, 8, humanAuthorizationMethodPattern.MatchString) &&
		state.createdAt > 0 && state.expiresAt > state.createdAt && state.expiresAt-state.createdAt <= 600
}

func (decision HumanRefreshRotationDecision) Outcome() HumanRefreshRotationOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}

func (decision HumanRefreshRotationDecision) RefreshToken() (HumanRefreshToken, bool) {
	if decision.state == nil || !decision.state.refreshToken.Valid() {
		return HumanRefreshToken{}, false
	}
	return decision.state.refreshToken, true
}

func (decision HumanRefreshRotationDecision) RefreshTokenExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.refreshTokenExpiresAt
}

func (decision HumanRefreshRotationDecision) GrantID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.grantID
}

func (decision HumanRefreshRotationDecision) Subject() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.subject
}

func (decision HumanRefreshRotationDecision) OrganizationID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.organizationID
}

func (decision HumanRefreshRotationDecision) MembershipID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.membershipID
}

func (decision HumanRefreshRotationDecision) MembershipRevision() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.membershipRevision
}

func (decision HumanRefreshRotationDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}

func (decision HumanRefreshRotationDecision) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if decision.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return decision.state.clientAssertionAuthority
}

func (decision HumanRefreshRotationDecision) Scopes() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.scopes)
}

func (decision HumanRefreshRotationDecision) Resources() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.resources)
}

func (decision HumanRefreshRotationDecision) AuthenticationTime() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.authenticationTime
}

func (decision HumanRefreshRotationDecision) AuthenticationContext() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.authenticationContext
}

func (decision HumanRefreshRotationDecision) AuthenticationMethods() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.authenticationMethods)
}

func (decision HumanRefreshRotationDecision) CreatedAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.createdAt
}

func (decision HumanRefreshRotationDecision) ExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.expiresAt
}

func validHumanRefreshTokenExpiry(createdAt, refreshTokenExpiresAt int64) bool {
	return createdAt > 0 && refreshTokenExpiresAt > createdAt &&
		refreshTokenExpiresAt-createdAt <= maxHumanRefreshTokenLifetime
}

func validHumanClientID(value string) bool {
	return humanAuthorizationClientIDPattern.MatchString(value)
}

func validHumanClientAssertionAuthority(authority VerifiedClientAssertionAuthority) bool {
	return authority.SnapshotRevision > 0 && humanAuthorizationKeyIDPattern.MatchString(authority.KeyAuthorityID)
}

func validHumanPushedRequestURI(value string) bool {
	return validHumanCapability(value, humanPushedRequestURIPrefix)
}

func validHumanOpaqueParameter(value string) bool {
	if len(value) < 16 || len(value) > maxHumanAuthorizationOpaqueBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validHumanCodeChallenge(value string) bool {
	return validHumanBase64URL256(value)
}

func validHumanBase64URL256(value string) bool {
	if len(value) != humanCapabilityPayloadBytes {
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

func validHumanCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if !humanAuthorizationUnreserved(value[index]) {
			return false
		}
	}
	return true
}

func humanAuthorizationUnreserved(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' || character == '-' || character == '.' ||
		character == '_' || character == '~'
}

func validHumanMaximumAuthenticationAge(value *int) bool {
	return value == nil || *value >= 0 && *value <= maxHumanAuthorizationMaxAge
}

func validHumanACRSet(values []ACR) bool {
	if len(values) > 1 {
		return false
	}
	return len(values) == 0 || humanAuthorizationAssurancePattern.MatchString(string(values[0]))
}

func validHumanAuthorizationFailure(value HumanAuthorizationFailure) bool {
	switch value {
	case HumanAuthorizationFailureAccessDenied, HumanAuthorizationFailureLoginRequired,
		HumanAuthorizationFailureInteractionRequired, HumanAuthorizationFailureProtocolCancelled:
		return true
	default:
		return false
	}
}

func validHumanStringSet(values []string, maximum int, validate func(string) bool) bool {
	if len(values) < 1 || len(values) > maximum {
		return false
	}
	previous := ""
	for index, value := range values {
		if !validate(value) || index > 0 && previous >= value {
			return false
		}
		previous = value
	}
	return true
}

func validHumanAbsoluteHTTPSURI(value string) bool {
	if value == "" || len(value) > maxHumanAuthorizationURIBytes || strings.Contains(value, "*") || !humanASCII(value) {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.String() != value ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() != "" ||
		net.ParseIP(parsed.Hostname()) != nil || !humanAuthorizationHostPattern.MatchString(parsed.Hostname()) ||
		parsed.Hostname() != parsed.Host || !humanAuthorizationPathPattern.MatchString(parsed.Path) ||
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

func humanASCII(value string) bool {
	for index := range len(value) {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func cloneHumanAuthorizationInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
