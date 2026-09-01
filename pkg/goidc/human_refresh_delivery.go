package goidc

import (
	"crypto/subtle"
	"slices"
)

const (
	// HumanRefreshTokenPrefix is the canonical framing for both initial and
	// caller-generated strict human refresh capabilities.
	HumanRefreshTokenPrefix = "d0_hrt_1_" //nolint:gosec // Public framing, not a credential.
	// HumanRefreshDeliveryReceiptPrefix is the canonical framing for the
	// caller-generated opaque delivery receipt.
	HumanRefreshDeliveryReceiptPrefix = "d0_hrd_1_"
	// HumanRefreshCapabilityEntropyBytes is the exact random byte count clients
	// encode with unpadded base64url after either prefix.
	HumanRefreshCapabilityEntropyBytes = 32
	// HumanRefreshCapabilityPayloadBytes is the exact unpadded base64url length
	// produced by HumanRefreshCapabilityEntropyBytes.
	HumanRefreshCapabilityPayloadBytes = 43

	// HumanRefreshDeliveryPrepareRoute creates or exactly replays one pending,
	// client-generated successor without consuming the active predecessor.
	HumanRefreshDeliveryPrepareRoute = "/refresh-deliveries/prepare"
	// HumanRefreshDeliveryActivateRoute atomically promotes the prepared
	// successor before the provider signs an access token.
	HumanRefreshDeliveryActivateRoute = "/refresh-deliveries/activate"
	// HumanRefreshDeliveryAbortRoute terminally abandons a pending successor
	// while leaving its predecessor active.
	HumanRefreshDeliveryAbortRoute = "/refresh-deliveries/abort"

	humanRefreshDeliveryReceiptPrefix = HumanRefreshDeliveryReceiptPrefix
	maxHumanRefreshDeliveryLifetime   = 5 * 60
)

// HumanRefreshDeliveryReceipt is a client-generated, purpose-separated
// capability that identifies one delivery attempt. Implementations must store
// only a purpose-separated digest of the rendered value.
type HumanRefreshDeliveryReceipt struct {
	humanAuthorizationRedaction
	state *humanRenderedValueState
}

func NewHumanRefreshDeliveryReceipt(value string) (HumanRefreshDeliveryReceipt, error) {
	state, err := newHumanCapabilityState(value, humanRefreshDeliveryReceiptPrefix)
	return HumanRefreshDeliveryReceipt{state: state}, err
}

func (value HumanRefreshDeliveryReceipt) Valid() bool {
	return validHumanCapabilityState(value.state, humanRefreshDeliveryReceiptPrefix)
}

func (value HumanRefreshDeliveryReceipt) Render() (string, error) {
	return renderHumanCapability(value.state, humanRefreshDeliveryReceiptPrefix)
}

// HumanRefreshDeliveryPrepareInputConfig binds a predecessor, a
// client-generated successor, and a delivery receipt to freshly verified
// confidential-client authority. Authorities must digest, not persist, the
// three rendered capabilities.
type HumanRefreshDeliveryPrepareInputConfig struct {
	PredecessorRefreshToken  HumanRefreshToken
	SuccessorRefreshToken    HumanRefreshToken
	DeliveryReceipt          HumanRefreshDeliveryReceipt
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

type humanRefreshDeliveryPrepareInputState struct {
	predecessorRefreshToken  HumanRefreshToken
	successorRefreshToken    HumanRefreshToken
	deliveryReceipt          HumanRefreshDeliveryReceipt
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshDeliveryPrepareInput has no representation for narrowing or
// other mutable refresh-grant parameters.
type HumanRefreshDeliveryPrepareInput struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryPrepareInputState
}

func NewHumanRefreshDeliveryPrepareInput(
	config HumanRefreshDeliveryPrepareInputConfig,
) (HumanRefreshDeliveryPrepareInput, error) {
	input := HumanRefreshDeliveryPrepareInput{state: &humanRefreshDeliveryPrepareInputState{
		predecessorRefreshToken:  config.PredecessorRefreshToken,
		successorRefreshToken:    config.SuccessorRefreshToken,
		deliveryReceipt:          config.DeliveryReceipt,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanRefreshDeliveryPrepareInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanRefreshDeliveryPrepareInput) Valid() bool {
	return input.state != nil && input.state.predecessorRefreshToken.Valid() &&
		input.state.successorRefreshToken.Valid() &&
		input.state.predecessorRefreshToken.state.value != input.state.successorRefreshToken.state.value &&
		input.state.deliveryReceipt.Valid() &&
		distinctHumanRefreshDeliveryEntropy(input.state.successorRefreshToken, input.state.deliveryReceipt) &&
		validHumanClientID(input.state.clientID) &&
		validHumanClientAssertionAuthority(input.state.clientAssertionAuthority)
}

func (input HumanRefreshDeliveryPrepareInput) PredecessorRefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.predecessorRefreshToken
}

func (input HumanRefreshDeliveryPrepareInput) SuccessorRefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.successorRefreshToken
}

func (input HumanRefreshDeliveryPrepareInput) DeliveryReceipt() HumanRefreshDeliveryReceipt {
	if input.state == nil {
		return HumanRefreshDeliveryReceipt{}
	}
	return input.state.deliveryReceipt
}

func (input HumanRefreshDeliveryPrepareInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}

func (input HumanRefreshDeliveryPrepareInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

type humanRefreshDeliveryProofState struct {
	successorRefreshToken    HumanRefreshToken
	deliveryReceipt          HumanRefreshDeliveryReceipt
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

func validHumanRefreshDeliveryProof(state *humanRefreshDeliveryProofState) bool {
	return state != nil && state.successorRefreshToken.Valid() && state.deliveryReceipt.Valid() &&
		distinctHumanRefreshDeliveryEntropy(state.successorRefreshToken, state.deliveryReceipt) &&
		validHumanClientID(state.clientID) &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority)
}

func distinctHumanRefreshDeliveryEntropy(
	successor HumanRefreshToken,
	receipt HumanRefreshDeliveryReceipt,
) bool {
	if !successor.Valid() || !receipt.Valid() {
		return false
	}
	successorPayload := []byte(successor.state.value[len(humanRefreshCapabilityPrefix):])
	receiptPayload := []byte(receipt.state.value[len(humanRefreshDeliveryReceiptPrefix):])
	return subtle.ConstantTimeCompare(successorPayload, receiptPayload) != 1
}

type HumanRefreshDeliveryActivateInputConfig struct {
	SuccessorRefreshToken    HumanRefreshToken
	DeliveryReceipt          HumanRefreshDeliveryReceipt
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshDeliveryActivateInput proves possession of both client-created
// delivery capabilities. It cannot name or consume a different predecessor.
type HumanRefreshDeliveryActivateInput struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryProofState
}

func NewHumanRefreshDeliveryActivateInput(
	config HumanRefreshDeliveryActivateInputConfig,
) (HumanRefreshDeliveryActivateInput, error) {
	input := HumanRefreshDeliveryActivateInput{state: &humanRefreshDeliveryProofState{
		successorRefreshToken:    config.SuccessorRefreshToken,
		deliveryReceipt:          config.DeliveryReceipt,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanRefreshDeliveryActivateInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanRefreshDeliveryActivateInput) Valid() bool {
	return validHumanRefreshDeliveryProof(input.state)
}

func (input HumanRefreshDeliveryActivateInput) SuccessorRefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.successorRefreshToken
}

func (input HumanRefreshDeliveryActivateInput) DeliveryReceipt() HumanRefreshDeliveryReceipt {
	if input.state == nil {
		return HumanRefreshDeliveryReceipt{}
	}
	return input.state.deliveryReceipt
}

func (input HumanRefreshDeliveryActivateInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}

func (input HumanRefreshDeliveryActivateInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

type HumanRefreshDeliveryAbortInputConfig struct {
	SuccessorRefreshToken    HumanRefreshToken
	DeliveryReceipt          HumanRefreshDeliveryReceipt
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshDeliveryAbortInput proves the exact pending tuple to abandon.
// The authority must report an activated tuple as an activated conflict and
// never roll it back.
type HumanRefreshDeliveryAbortInput struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryProofState
}

func NewHumanRefreshDeliveryAbortInput(
	config HumanRefreshDeliveryAbortInputConfig,
) (HumanRefreshDeliveryAbortInput, error) {
	input := HumanRefreshDeliveryAbortInput{state: &humanRefreshDeliveryProofState{
		successorRefreshToken:    config.SuccessorRefreshToken,
		deliveryReceipt:          config.DeliveryReceipt,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !input.Valid() {
		return HumanRefreshDeliveryAbortInput{}, ErrInvalidHumanAuthorizationValue
	}
	return input, nil
}

func (input HumanRefreshDeliveryAbortInput) Valid() bool {
	return validHumanRefreshDeliveryProof(input.state)
}

func (input HumanRefreshDeliveryAbortInput) SuccessorRefreshToken() HumanRefreshToken {
	if input.state == nil {
		return HumanRefreshToken{}
	}
	return input.state.successorRefreshToken
}

func (input HumanRefreshDeliveryAbortInput) DeliveryReceipt() HumanRefreshDeliveryReceipt {
	if input.state == nil {
		return HumanRefreshDeliveryReceipt{}
	}
	return input.state.deliveryReceipt
}

func (input HumanRefreshDeliveryAbortInput) ClientID() string {
	if input.state == nil {
		return ""
	}
	return input.state.clientID
}

func (input HumanRefreshDeliveryAbortInput) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if input.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return input.state.clientAssertionAuthority
}

type HumanRefreshDeliveryPrepareOutcome string

const (
	HumanRefreshDeliveryPrepareOutcomePending   HumanRefreshDeliveryPrepareOutcome = "delivery_pending"
	HumanRefreshDeliveryPrepareOutcomeActivated HumanRefreshDeliveryPrepareOutcome = "activated"
	HumanRefreshDeliveryPrepareOutcomeAborted   HumanRefreshDeliveryPrepareOutcome = "aborted"
	HumanRefreshDeliveryPrepareOutcomeRejected  HumanRefreshDeliveryPrepareOutcome = "rejected"
)

type HumanRefreshDeliveryPrepareDecisionConfig struct {
	Outcome                  HumanRefreshDeliveryPrepareOutcome
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
	CreatedAt                int64
	ExpiresAt                int64
}

type humanRefreshDeliveryPrepareDecisionState struct {
	outcome                  HumanRefreshDeliveryPrepareOutcome
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
	createdAt                int64
	expiresAt                int64
}

// HumanRefreshDeliveryPrepareDecision contains no rendered delivery value.
// Accepted decisions retain the original prepare timestamps. An exact replay
// remains distinguishable as activated or aborted after that pending deadline;
// only a still-pending decision must be unexpired.
type HumanRefreshDeliveryPrepareDecision struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryPrepareDecisionState
}

func NewHumanRefreshDeliveryPrepareDecision(
	config HumanRefreshDeliveryPrepareDecisionConfig,
) (HumanRefreshDeliveryPrepareDecision, error) {
	decision := HumanRefreshDeliveryPrepareDecision{state: &humanRefreshDeliveryPrepareDecisionState{
		outcome:                  config.Outcome,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
		createdAt:                config.CreatedAt,
		expiresAt:                config.ExpiresAt,
	}}
	if !decision.Valid() {
		return HumanRefreshDeliveryPrepareDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}

func (decision HumanRefreshDeliveryPrepareDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	if state.outcome == HumanRefreshDeliveryPrepareOutcomeRejected {
		return state.clientID == "" && state.clientAssertionAuthority == (VerifiedClientAssertionAuthority{}) &&
			state.createdAt == 0 && state.expiresAt == 0
	}
	validAcceptedOutcome := state.outcome == HumanRefreshDeliveryPrepareOutcomePending ||
		state.outcome == HumanRefreshDeliveryPrepareOutcomeActivated ||
		state.outcome == HumanRefreshDeliveryPrepareOutcomeAborted
	return validAcceptedOutcome && validHumanClientID(state.clientID) &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority) && state.createdAt > 0 &&
		state.expiresAt > state.createdAt && state.expiresAt-state.createdAt <= maxHumanRefreshDeliveryLifetime
}

func (decision HumanRefreshDeliveryPrepareDecision) Outcome() HumanRefreshDeliveryPrepareOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}

func (decision HumanRefreshDeliveryPrepareDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}

func (decision HumanRefreshDeliveryPrepareDecision) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if decision.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return decision.state.clientAssertionAuthority
}

func (decision HumanRefreshDeliveryPrepareDecision) CreatedAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.createdAt
}

func (decision HumanRefreshDeliveryPrepareDecision) ExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.expiresAt
}

type HumanRefreshDeliveryActivateOutcome string

const (
	HumanRefreshDeliveryActivateOutcomeActivated HumanRefreshDeliveryActivateOutcome = "activated"
	HumanRefreshDeliveryActivateOutcomeRejected  HumanRefreshDeliveryActivateOutcome = "rejected"
)

// HumanRefreshDeliveryActivateDecisionConfig is the authority-owned issuance
// snapshot returned after atomic activation or revalidation of an exact active
// replay. RefreshTokenExpiresAt is the original absolute family deadline and
// must never be extended by replay; CreatedAt and ExpiresAt bound this freshly
// revalidated access-token decision. The config deliberately has no field that
// can carry the raw successor or delivery receipt.
type HumanRefreshDeliveryActivateDecisionConfig struct {
	Outcome                  HumanRefreshDeliveryActivateOutcome
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

type humanRefreshDeliveryActivateDecisionState struct {
	outcome                  HumanRefreshDeliveryActivateOutcome
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

// HumanRefreshDeliveryActivateDecision can represent both first activation
// and an exact activated replay after the pending deadline. Both carry current
// caller-authorized issuance facts and permit a fresh equivalent access-token
// signature without a second rotation or refresh-family deadline extension.
type HumanRefreshDeliveryActivateDecision struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryActivateDecisionState
}

func NewHumanRefreshDeliveryActivateDecision(
	config HumanRefreshDeliveryActivateDecisionConfig,
) (HumanRefreshDeliveryActivateDecision, error) {
	decision := HumanRefreshDeliveryActivateDecision{state: &humanRefreshDeliveryActivateDecisionState{
		outcome:                  config.Outcome,
		refreshTokenExpiresAt:    config.RefreshTokenExpiresAt,
		grantID:                  config.GrantID,
		subject:                  config.Subject,
		organizationID:           config.OrganizationID,
		membershipID:             config.MembershipID,
		membershipRevision:       config.MembershipRevision,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
		scopes:                   slices.Clone(config.Scopes),
		resources:                slices.Clone(config.Resources),
		authenticationTime:       config.AuthenticationTime,
		authenticationContext:    config.AuthenticationContext,
		authenticationMethods:    slices.Clone(config.AuthenticationMethods),
		createdAt:                config.CreatedAt,
		expiresAt:                config.ExpiresAt,
	}}
	if !decision.Valid() {
		return HumanRefreshDeliveryActivateDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}

func (decision HumanRefreshDeliveryActivateDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	if state.outcome == HumanRefreshDeliveryActivateOutcomeRejected {
		return state.refreshTokenExpiresAt == 0 && state.grantID == "" && state.subject == "" &&
			state.organizationID == "" && state.membershipID == "" && state.membershipRevision == 0 &&
			state.clientID == "" && state.clientAssertionAuthority == (VerifiedClientAssertionAuthority{}) &&
			len(state.scopes) == 0 && len(state.resources) == 0 && state.authenticationTime == 0 &&
			state.authenticationContext == "" && len(state.authenticationMethods) == 0 &&
			state.createdAt == 0 && state.expiresAt == 0
	}
	return state.outcome == HumanRefreshDeliveryActivateOutcomeActivated &&
		validHumanRefreshTokenExpiry(state.createdAt, state.refreshTokenExpiresAt) &&
		humanAuthorizationHandlePattern.MatchString(state.grantID) && validHumanOpaqueParameter(state.subject) &&
		humanAuthorizationHandlePattern.MatchString(state.organizationID) &&
		humanAuthorizationHandlePattern.MatchString(state.membershipID) && state.membershipRevision > 0 &&
		validHumanClientID(state.clientID) && validHumanClientAssertionAuthority(state.clientAssertionAuthority) &&
		validHumanStringSet(state.scopes, maxHumanAuthorizationScopes, humanAuthorizationScopePattern.MatchString) &&
		slices.Contains(state.scopes, ScopeOpenID.ID) && slices.Contains(state.scopes, ScopeOfflineAccess.ID) &&
		validHumanStringSet(state.resources, maxHumanAuthorizationResources, validHumanAbsoluteHTTPSURI) &&
		state.authenticationTime > 0 && state.authenticationTime <= state.createdAt &&
		humanAuthorizationAssurancePattern.MatchString(state.authenticationContext) &&
		validHumanStringSet(state.authenticationMethods, 8, humanAuthorizationMethodPattern.MatchString) &&
		state.createdAt > 0 && state.expiresAt > state.createdAt && state.expiresAt-state.createdAt <= 600
}

func (decision HumanRefreshDeliveryActivateDecision) Outcome() HumanRefreshDeliveryActivateOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanRefreshDeliveryActivateDecision) RefreshTokenExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.refreshTokenExpiresAt
}
func (decision HumanRefreshDeliveryActivateDecision) GrantID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.grantID
}
func (decision HumanRefreshDeliveryActivateDecision) Subject() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.subject
}
func (decision HumanRefreshDeliveryActivateDecision) OrganizationID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.organizationID
}
func (decision HumanRefreshDeliveryActivateDecision) MembershipID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.membershipID
}
func (decision HumanRefreshDeliveryActivateDecision) MembershipRevision() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.membershipRevision
}
func (decision HumanRefreshDeliveryActivateDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}
func (decision HumanRefreshDeliveryActivateDecision) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if decision.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return decision.state.clientAssertionAuthority
}
func (decision HumanRefreshDeliveryActivateDecision) Scopes() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.scopes)
}
func (decision HumanRefreshDeliveryActivateDecision) Resources() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.resources)
}
func (decision HumanRefreshDeliveryActivateDecision) AuthenticationTime() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.authenticationTime
}
func (decision HumanRefreshDeliveryActivateDecision) AuthenticationContext() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.authenticationContext
}
func (decision HumanRefreshDeliveryActivateDecision) AuthenticationMethods() []string {
	if decision.state == nil {
		return nil
	}
	return slices.Clone(decision.state.authenticationMethods)
}
func (decision HumanRefreshDeliveryActivateDecision) CreatedAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.createdAt
}
func (decision HumanRefreshDeliveryActivateDecision) ExpiresAt() int64 {
	if decision.state == nil {
		return 0
	}
	return decision.state.expiresAt
}

type HumanRefreshDeliveryAbortOutcome string

const (
	HumanRefreshDeliveryAbortOutcomeAborted           HumanRefreshDeliveryAbortOutcome = "aborted"
	HumanRefreshDeliveryAbortOutcomeActivatedConflict HumanRefreshDeliveryAbortOutcome = "activated_conflict"
	HumanRefreshDeliveryAbortOutcomeRejected          HumanRefreshDeliveryAbortOutcome = "rejected"
)

type HumanRefreshDeliveryAbortDecisionConfig struct {
	Outcome                  HumanRefreshDeliveryAbortOutcome
	ClientID                 string
	ClientAssertionAuthority VerifiedClientAssertionAuthority
}

type humanRefreshDeliveryAbortDecisionState struct {
	outcome                  HumanRefreshDeliveryAbortOutcome
	clientID                 string
	clientAssertionAuthority VerifiedClientAssertionAuthority
}

// HumanRefreshDeliveryAbortDecision reports an abort, exact abort replay, or
// the distinguishable conflict required when the tuple is already activated.
// Rejected deliberately collapses only unknown, mismatched, and expired
// pending tuples.
type HumanRefreshDeliveryAbortDecision struct {
	humanAuthorizationRedaction
	state *humanRefreshDeliveryAbortDecisionState
}

func NewHumanRefreshDeliveryAbortDecision(
	config HumanRefreshDeliveryAbortDecisionConfig,
) (HumanRefreshDeliveryAbortDecision, error) {
	decision := HumanRefreshDeliveryAbortDecision{state: &humanRefreshDeliveryAbortDecisionState{
		outcome:                  config.Outcome,
		clientID:                 config.ClientID,
		clientAssertionAuthority: config.ClientAssertionAuthority,
	}}
	if !decision.Valid() {
		return HumanRefreshDeliveryAbortDecision{}, ErrInvalidHumanAuthorizationValue
	}
	return decision, nil
}

func (decision HumanRefreshDeliveryAbortDecision) Valid() bool {
	if decision.state == nil {
		return false
	}
	state := decision.state
	if state.outcome == HumanRefreshDeliveryAbortOutcomeRejected {
		return state.clientID == "" && state.clientAssertionAuthority == (VerifiedClientAssertionAuthority{})
	}
	acceptedOutcome := state.outcome == HumanRefreshDeliveryAbortOutcomeAborted ||
		state.outcome == HumanRefreshDeliveryAbortOutcomeActivatedConflict
	return acceptedOutcome && validHumanClientID(state.clientID) &&
		validHumanClientAssertionAuthority(state.clientAssertionAuthority)
}

func (decision HumanRefreshDeliveryAbortDecision) Outcome() HumanRefreshDeliveryAbortOutcome {
	if decision.state == nil {
		return ""
	}
	return decision.state.outcome
}
func (decision HumanRefreshDeliveryAbortDecision) ClientID() string {
	if decision.state == nil {
		return ""
	}
	return decision.state.clientID
}
func (decision HumanRefreshDeliveryAbortDecision) ClientAssertionAuthority() VerifiedClientAssertionAuthority {
	if decision.state == nil {
		return VerifiedClientAssertionAuthority{}
	}
	return decision.state.clientAssertionAuthority
}
