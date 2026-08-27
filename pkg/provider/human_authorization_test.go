package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestNewHumanConfidentialBFFAuthorizationDoesNotInstallLegacyManagers(t *testing.T) {
	authority := humanAuthorizationAuthorityProviderStub{}
	provider, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(authority,
			WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
			WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
			WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc"),
		),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	config := provider.config
	if !config.HumanConfidentialBFFAuthorizationEnabled || config.HumanAuthorizationAuthority != authority ||
		config.HumanIdentityInteractionEndpoint != "https://id.d0.eu/oidc/interaction/identity" ||
		config.HumanIdentityReadyEndpoint != "https://id.d0.eu/oidc/interaction/ready" ||
		config.HumanBrowserBindingCookieName != "__Host-d0-human-oidc" ||
		config.HumanAccessTokenLifetimeSecs != 300 || config.PARLifetimeSecs != defaultPARLifetimeSecs {
		t.Fatalf("human authorization configuration = %#v", config)
	}
	if config.LegacyAuthorizationCodeEnabled || config.LegacyPAREnabled || config.AuthManager != nil ||
		config.PARManager != nil || config.AuthCodeFunc != nil || config.PARIDFunc != nil ||
		config.PARHandleSessionFunc != nil || config.LegacyRefreshTokenGrantEnabled ||
		config.RefreshTokenManager != nil || config.RefreshTokenFunc != nil ||
		config.RefreshTokenShouldIssueFunc != nil {
		t.Fatal("strict human-only provider installed legacy authorization or refresh state/callbacks")
	}
	if len(config.GrantTypes) != 2 || config.GrantTypes[0] != goidc.GrantAuthorizationCode ||
		config.GrantTypes[1] != goidc.GrantRefreshToken ||
		!slices.Contains(config.ResponseTypes, goidc.ResponseTypeCode) ||
		!config.PAREnabled || config.PARRequired || !config.PKCEEnabled || config.PKCERequired ||
		len(config.PKCEChallengeMethods) != 1 || config.PKCEChallengeMethods[0] != goidc.CodeChallengeMethodSHA256 ||
		!slices.Contains(config.AuthnMethods, goidc.AuthnMethodSecretPost) ||
		!slices.Contains(config.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) ||
		!slices.Contains(config.AuthnMethodPrivateKeyJWTSigAlgs, goidc.SigAlgPS256) ||
		!slices.Contains(config.SubIdentifierTypes, goidc.SubIdentifierPairwise) ||
		!config.TokenRevocationEnabled || config.LegacyTokenRevocationEnabled ||
		config.TokenRevocationEndpoint != defaultEndpointTokenRevocation {
		t.Fatalf("strict protocol configuration incomplete: %#v", config)
	}
}

func TestNewHumanConfidentialBFFAuthorizationSupportsMixedLegacyDispatch(t *testing.T) {
	provider, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(humanAuthorizationAuthorityProviderStub{},
			WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
			WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
			WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc"),
		),
		WithAuthCodeGrant(AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			WithPAR(nil, WithPARRequired()),
		),
	)
	if err != nil {
		t.Fatalf("New() mixed provider error = %v", err)
	}
	if !provider.config.HumanConfidentialBFFAuthorizationEnabled ||
		!provider.config.LegacyAuthorizationCodeEnabled || !provider.config.LegacyPAREnabled ||
		provider.config.AuthManager == nil || provider.config.PARManager == nil ||
		provider.config.AuthCodeFunc == nil || provider.config.PARIDFunc == nil {
		t.Fatalf("mixed provider did not retain separate strict and legacy authorities: %#v", provider.config)
	}
	if len(provider.config.GrantTypes) != 2 ||
		len(provider.config.ResponseTypes) != 1 ||
		provider.config.ResponseTypes[0] != goidc.ResponseTypeCode {
		t.Fatalf("mixed provider duplicated protocol metadata: %#v", provider.config)
	}
	if provider.config.IssuerRespParamEnabled ||
		provider.config.SubIdentifierTypeDefault != goidc.SubIdentifierPublic ||
		!slices.Contains(provider.config.AuthnMethods, goidc.AuthnMethodSecretPost) ||
		!slices.Contains(provider.config.SubIdentifierTypes, goidc.SubIdentifierPublic) ||
		!slices.Contains(provider.config.SubIdentifierTypes, goidc.SubIdentifierPairwise) {
		t.Fatalf("Human authorization changed legacy response or subject defaults: %#v", provider.config)
	}
}

func TestNewHumanConfidentialBFFAuthorizationPreservesExplicitAuthnMethodsInEitherOrder(t *testing.T) {
	human := WithHumanConfidentialBFFAuthorizationAuthority(
		humanAuthorizationAuthorityProviderStub{},
		validHumanAuthorizationProviderOptions()...,
	)
	for name, options := range map[string][]Option{
		"explicit first": {WithNoneAuthn(), human},
		"explicit last":  {human, WithNoneAuthn()},
	} {
		t.Run(name, func(t *testing.T) {
			base := []Option{
				withHumanAuthorizationJTIUseConsumer(),
				withHumanAuthorizationResourceIndicators(),
				withHumanAuthorizationACRs(),
			}
			provider, err := New(
				humanAuthorizationProviderConfig(goidc.SigAlgPS256),
				append(base, options...)...,
			)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if !slices.Contains(provider.config.AuthnMethods, goidc.AuthnMethodNone) ||
				!slices.Contains(provider.config.AuthnMethods, goidc.AuthnMethodPrivateKeyJWT) ||
				slices.Contains(provider.config.AuthnMethods, goidc.AuthnMethodSecretPost) {
				t.Fatalf("explicit authn methods were not preserved: %v", provider.config.AuthnMethods)
			}
		})
	}
}

func TestNewHumanConfidentialBFFAuthorizationRejectsConflictingLaterOptions(t *testing.T) {
	for name, conflicting := range map[string]Option{
		"private-key JWT without PS256": WithPrivateKeyJWTAuthn(goidc.SigAlgES256),
		"PKCE without S256": WithAuthCodeGrant(
			AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodPlain}),
		),
		"subject identifiers without pairwise": WithSubjectIdentifiers(
			[]goidc.SubIdentifierType{goidc.SubIdentifierPublic},
		),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
				withHumanAuthorizationJTIUseConsumer(),
				withHumanAuthorizationResourceIndicators(),
				withHumanAuthorizationACRs(),
				WithHumanConfidentialBFFAuthorizationAuthority(
					humanAuthorizationAuthorityProviderStub{},
					validHumanAuthorizationProviderOptions()...,
				),
				conflicting,
			)
			if err == nil {
				t.Fatal("New() error = nil, want conflicting Human configuration rejected")
			}
		})
	}
}

func TestNewFAPI2MachineAndAtomicHumanProviderSupportsSeparateIssuancePaths(t *testing.T) {
	provider, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationACRs(),
		WithProfile(goidc.ProfileFAPI2, WithProfileValidation()),
		WithClientCredentialsGrant(),
		WithPrivateKeyJWTAuthn(goidc.SigAlgPS256),
		WithDPoP(
			[]goidc.SignatureAlgorithm{goidc.SigAlgES256},
			WithDPoPRequired(),
		),
		WithTokenBindingRequired(),
		WithResourceIndicators(
			[]goidc.ResourceIndicator{"https://api.d0.eu/accounting"},
			WithResourceIndicatorsRequired(),
		),
		WithAccessTokenClaims(func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
			return map[string]any{"machine_authority": "retained"}, nil
		}),
		WithHumanConfidentialBFFAuthorizationAuthority(humanAuthorizationAuthorityProviderStub{},
			WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
			WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
			WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc"),
		),
	)
	if err != nil {
		t.Fatalf("New() FAPI2 machine + atomic human provider error = %v", err)
	}
	if provider.config.LegacyAuthorizationCodeEnabled || provider.config.LegacyPAREnabled ||
		provider.config.PARRequired || provider.config.PKCERequired ||
		provider.config.IssuerRespParamEnabled || provider.config.AccessTokenClaimsFunc == nil {
		t.Fatalf("separate machine/human issuance configuration = %#v", provider.config)
	}
}

func TestHumanOnlyProviderDoesNotMountLegacyAuthorizationCallbacks(t *testing.T) {
	provider, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(humanAuthorizationAuthorityProviderStub{},
			WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
			WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
			WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc"),
		),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "https://auth.d0.eu/authorize/legacy-callback", nil)
		response := httptest.NewRecorder()
		provider.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s legacy callback status = %d, want 404", method, response.Code)
		}
	}
}

func TestNewHumanConfidentialBFFAuthorizationRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		options []HumanConfidentialBFFAuthorizationOption
	}{
		{name: "missing PS256", config: humanAuthorizationProviderConfig(goidc.SigAlgRS256), options: validHumanAuthorizationProviderOptions()},
		{name: "missing identity endpoint", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "missing identity ready endpoint", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "endpoint with query", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity?next=x"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "endpoint with IP host", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://127.0.0.1/oidc/interaction/identity"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "ready endpoint with query", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready?next=x"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "ready endpoint with IP host", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFIdentityReadyEndpoint("https://127.0.0.1/oidc/interaction/ready"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "non-host cookie", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFBrowserBindingCookieName("d0-human-oidc")}},
		{name: "empty host cookie suffix", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-")}},
		{name: "lifetime too long", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: append(validHumanAuthorizationProviderOptions(), WithHumanConfidentialBFFAccessTokenLifetime(601))},
		{name: "identity interaction on auth origin", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://auth.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "identity ready on auth origin", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFIdentityReadyEndpoint("https://auth.d0.eu/oidc/interaction/ready"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
		{name: "identity endpoints on different origins", config: humanAuthorizationProviderConfig(goidc.SigAlgPS256), options: []HumanConfidentialBFFAuthorizationOption{WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"), WithHumanConfidentialBFFIdentityReadyEndpoint("https://other-id.d0.eu/oidc/interaction/ready"), WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config,
				withHumanAuthorizationJTIUseConsumer(),
				withHumanAuthorizationResourceIndicators(),
				withHumanAuthorizationACRs(),
				WithHumanConfidentialBFFAuthorizationAuthority(humanAuthorizationAuthorityProviderStub{}, test.options...),
			)
			if err == nil {
				t.Fatal("New() error = nil, want strict configuration error")
			}
		})
	}

	if _, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(nil, validHumanAuthorizationProviderOptions()...),
	); err == nil {
		t.Fatal("New() accepted nil human authorization authority")
	}

	if _, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithIDTokenLifetime(601),
		WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		),
	); err == nil {
		t.Fatal("New() accepted an overlong human ID-token lifetime")
	}

	if _, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		),
		WithAuthCodeGrant(
			AuthCodeGrantConfig{ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode}},
			WithPAR(nil, WithPARLifetime(600)),
		),
	); err == nil {
		t.Fatal("New() accepted an overlong human PAR lifetime")
	}

	for _, skew := range []int{-1, 61, int(^uint(0) >> 1)} {
		if _, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
			withHumanAuthorizationJTIUseConsumer(),
			withHumanAuthorizationResourceIndicators(),
			withHumanAuthorizationACRs(),
			WithJWTLeewayTime(skew),
			WithHumanConfidentialBFFAuthorizationAuthority(
				humanAuthorizationAuthorityProviderStub{},
				validHumanAuthorizationProviderOptions()...,
			),
		); err == nil {
			t.Fatalf("New() accepted human authority clock skew %d", skew)
		}
	}
}

func TestNewHumanConfidentialBFFAuthorizationRequiresTypedJTIConsumer(t *testing.T) {
	newProvider := func(options ...Option) error {
		options = append(options, withHumanAuthorizationResourceIndicators())
		options = append(options, withHumanAuthorizationACRs())
		options = append(options, WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		))
		_, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256), options...)
		return err
	}

	if err := newProvider(); err == nil {
		t.Fatal("New() accepted strict human authorization without JTI replay protection")
	}
	if err := newProvider(WithJTIConsumer(func(context.Context, string) error { return nil })); err == nil {
		t.Fatal("New() accepted legacy untyped JTI replay protection for strict human authorization")
	}
}

func TestNewHumanConfidentialBFFAuthorizationRequiresResourceAuthority(t *testing.T) {
	_, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		),
	)
	if err == nil {
		t.Fatal("New() accepted strict human authorization without resource authority")
	}
}

func TestNewHumanConfidentialBFFAuthorizationRequiresACRAuthority(t *testing.T) {
	_, err := New(humanAuthorizationProviderConfig(goidc.SigAlgPS256),
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		),
	)
	if err == nil {
		t.Fatal("New() accepted strict human authorization without ACR authority")
	}
}

func TestNewHumanConfidentialBFFAuthorizationRejectsUnsafeIssuer(t *testing.T) {
	config := humanAuthorizationProviderConfig(goidc.SigAlgPS256)
	config.Issuer = "http://auth.d0.eu"
	_, err := New(config,
		withHumanAuthorizationJTIUseConsumer(),
		withHumanAuthorizationResourceIndicators(),
		withHumanAuthorizationACRs(),
		WithHumanConfidentialBFFAuthorizationAuthority(
			humanAuthorizationAuthorityProviderStub{},
			validHumanAuthorizationProviderOptions()...,
		),
	)
	if err == nil {
		t.Fatal("New() accepted a non-HTTPS human authorization issuer")
	}
}

func humanAuthorizationProviderConfig(algorithm goidc.SignatureAlgorithm) Config {
	return Config{
		Issuer: "https://auth.d0.eu",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{}, nil
		},
		IDTokenAlgs: []goidc.SignatureAlgorithm{algorithm},
	}
}

func validHumanAuthorizationProviderOptions() []HumanConfidentialBFFAuthorizationOption {
	return []HumanConfidentialBFFAuthorizationOption{
		WithHumanConfidentialBFFIdentityInteractionEndpoint("https://id.d0.eu/oidc/interaction/identity"),
		WithHumanConfidentialBFFIdentityReadyEndpoint("https://id.d0.eu/oidc/interaction/ready"),
		WithHumanConfidentialBFFBrowserBindingCookieName("__Host-d0-human-oidc"),
	}
}

func withHumanAuthorizationJTIUseConsumer() Option {
	return WithJTIUseConsumer(func(context.Context, goidc.JTIUse) error { return nil })
}

func withHumanAuthorizationResourceIndicators() Option {
	return WithResourceIndicators([]goidc.ResourceIndicator{"https://api.d0.eu/accounting/v1"})
}

func withHumanAuthorizationACRs() Option {
	return WithACRs("urn:d0:acr:passkey")
}

type humanAuthorizationAuthorityProviderStub struct{}

func (humanAuthorizationAuthorityProviderStub) StorePAR(context.Context, goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
	return goidc.HumanPARDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) ConsumePARAndStartContinuation(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
	return goidc.HumanStartDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) ConfirmBrowser(context.Context, goidc.HumanContinuationInput) (goidc.HumanContinuationDecision, error) {
	return goidc.HumanContinuationDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) CompleteAuthorization(context.Context, goidc.HumanCompletionInput) (goidc.HumanCompletionDecision, error) {
	return goidc.HumanCompletionDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) RedeemAuthorizationCode(context.Context, goidc.HumanCodeRedemptionInput) (goidc.HumanCodeRedemptionDecision, error) {
	return goidc.HumanCodeRedemptionDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) RotateRefreshToken(context.Context, goidc.HumanRefreshRotationInput) (goidc.HumanRefreshRotationDecision, error) {
	return goidc.HumanRefreshRotationDecision{}, nil
}
func (humanAuthorizationAuthorityProviderStub) RevokeRefreshToken(context.Context, goidc.HumanRefreshRevocationInput) error {
	return nil
}

var _ goidc.HumanAuthorizationAuthority = humanAuthorizationAuthorityProviderStub{}
