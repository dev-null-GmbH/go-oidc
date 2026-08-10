package token

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGenerateClientCredentialsToken(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, request, *goidc.Client) {
		tb.Helper()

		ctx := oidctest.NewContext(tb)

		c, secret := oidctest.NewClient(tb)
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		req := request{
			grantType: goidc.GrantClientCredentials,
			scopes:    oidctest.Scope1.ID,
		}

		return ctx, req, c
	}

	tests := []struct {
		name     string
		setup    func() (oidc.Context, request, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Subject != c.ID {
					t.Errorf("grant.Subject = %q, want %q", grant.Subject, c.ID)
				}
				if grant.ClientID != c.ID {
					t.Errorf("grant.ClientID = %q, want %q", grant.ClientID, c.ID)
				}
				if grant.RefreshToken != "" {
					t.Errorf("grant.RefreshToken = %q, want empty", grant.RefreshToken)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       c.ID,
					"client_id": c.ID,
					"scope":     grant.Scopes,
					"grant_id":  grant.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
				if resp.RefreshToken != "" {
					t.Errorf("resp.RefreshToken = %q, want empty", resp.RefreshToken)
				}
				if resp.IDToken != "" {
					t.Errorf("resp.IDToken = %q, want empty", resp.IDToken)
				}
			},
		},
		{
			name: "resource indicators",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				req.resources = []string{"https://resource.com"}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if diff := cmp.Diff(grants[0].Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}

				if diff := cmp.Diff(resp.Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				if diff := cmp.Diff(claims["aud"], "https://resource.com"); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "required resource indicator is missing",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicatorsRequired = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidTarget,
		},
		{
			name: "required resource indicator is empty",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicatorsRequired = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				req.resources = []string{""}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidTarget,
		},
		{
			name: "multiple required resource indicators",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicatorsRequired = true
				ctx.ResourceIndicators = []string{"https://resource.com", "https://other-resource.com"}
				req.resources = []string{"https://resource.com", "https://other-resource.com"}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				want := goidc.Resources{"https://resource.com", "https://other-resource.com"}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if diff := cmp.Diff(grants[0].Resources, want); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(resp.Resources, want); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth details",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				req.authDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				wantAuthDetails := []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if diff := cmp.Diff(grants[0].AuthDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}

				if diff := cmp.Diff(resp.AuthorizationDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := []any{
					map[string]any{
						"type":         "type1",
						"random_claim": "random_value",
					},
					map[string]any{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(claims["authorization_details"], wantClaims); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "openid scope filtered",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.scopes = "openid " + oidctest.Scope1.ID
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Scopes != oidctest.Scope1.ID {
					t.Errorf("grant.Scopes = %q, want %q", grants[0].Scopes, oidctest.Scope1.ID)
				}

				if resp.Scopes != oidctest.Scope1.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, oidctest.Scope1.ID)
				}
			},
		},
		{
			name: "mtls binding",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.MTLSTokenBindingEnabled = true
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return &x509.Certificate{Raw: []byte("test_client_cert")}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].CertThumbprint == "" {
					t.Fatal("expected certificate thumbprint to be set on grant")
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantConfirmation := map[string]any{
					"x5t#S256": grants[0].CertThumbprint,
				}
				if diff := cmp.Diff(claims["cnf"], wantConfirmation); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "invalid client auth",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "client lacks grant type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeUnauthorizedClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.scopes = "unknown_scope"
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "invalid resource",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
				req.resources = []string{"https://other-resource.com"}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidTarget,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "invalid auth details type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1"}
				req.authDetails = []goidc.AuthDetail{
					{
						"type": "type2",
					},
				}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidAuthDetails,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, c := test.setup()

			// When.
			resp, err := generateToken(ctx, req)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("got no error, wantErr=%v", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}

				if test.validate != nil {
					test.validate(t, ctx, resp, c)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c)
			}
		})
	}
}

func TestClientCredentialsAccessTokenClaimsRunBeforePersistenceAndSigning(t *testing.T) {
	ctx, req, client := clientCredentialsTestContext(t)
	privateJWK := oidctest.PrivateJWKS(t, ctx).Keys[0]
	signer, ok := privateJWK.Key.(crypto.Signer)
	if !ok {
		t.Fatalf("signing key type = %T, want crypto.Signer", privateJWK.Key)
	}

	claimsCalls := 0
	signerCalls := 0
	grantHandled := false
	ctx.HandleGrantFunc = func(context.Context, goidc.GrantType, *goidc.Grant) error {
		grantHandled = true
		return nil
	}
	ctx.AccessTokenClaimsFunc = func(_ context.Context, input goidc.AccessTokenClaimsInput) (map[string]any, error) {
		claimsCalls++
		if !grantHandled {
			t.Fatal("claims callback ran before grant validation")
		}
		if input.AuthenticatedClientID != client.ID {
			t.Fatalf("AuthenticatedClientID = %q, want %q", input.AuthenticatedClientID, client.ID)
		}
		if input.GrantType != goidc.GrantClientCredentials || input.ClientID != client.ID ||
			input.Subject != client.ID || input.Scopes != oidctest.Scope1.ID {
			t.Fatalf("claims identity/profile input = %#v, want exact client_credentials facts", input)
		}
		if input.Format != goidc.TokenFormatJWT || input.Type != goidc.TokenTypeBearer ||
			input.SignatureAlgorithm != goidc.SignatureAlgorithm(privateJWK.Algorithm) ||
			input.IssuedAt <= 0 || input.ExpiresAt-input.IssuedAt != 60 {
			t.Fatalf("claims token input = %#v, want exact JWT issuance facts", input)
		}
		if len(input.Resources) != 0 || input.DPoPJWKThumbprint != "" || input.CertificateThumbprint != "" ||
			input.AuthorizationDetailsPresent || input.ActorPresent {
			t.Fatalf("claims optional input = %#v, want empty", input)
		}
		if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
			t.Fatalf("claims callback observed %d persisted grants, want 0", len(grants))
		}
		if signerCalls != 0 {
			t.Fatalf("claims callback observed %d signer calls, want 0", signerCalls)
		}
		return map[string]any{"https://example.com/organization_id": "organization"}, nil
	}
	ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		signerCalls++
		if claimsCalls != 1 {
			t.Fatalf("signer observed %d claims calls, want 1", claimsCalls)
		}
		if grants := oidctest.Grants(t, ctx); len(grants) != 1 {
			t.Fatalf("signer observed %d persisted grants, want 1", len(grants))
		}
		return privateJWK.KeyID, signer, nil
	}

	resp, err := generateClientCredentialsToken(ctx, req)
	if err != nil {
		t.Fatalf("generateClientCredentialsToken() error = %v", err)
	}
	if claimsCalls != 1 || signerCalls != 1 {
		t.Fatalf("calls = claims:%d signer:%d, want 1 each", claimsCalls, signerCalls)
	}
	claims, err := oidctest.SafeClaims(resp.AccessToken, privateJWK)
	if err != nil {
		t.Fatalf("SafeClaims() error = %v", err)
	}
	if claims["https://example.com/organization_id"] != "organization" {
		t.Fatalf("additional claim = %v, want organization", claims["https://example.com/organization_id"])
	}
}

func TestClientCredentialsAccessTokenClaimsResourcesAreDefensivelyCopied(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	req.resources = goidc.Resources{"https://resource.example"}
	ctx.ResourceIndicatorsEnabled = true
	ctx.ResourceIndicators = slices.Clone(req.resources)
	ctx.AccessTokenClaimsFunc = func(_ context.Context, input goidc.AccessTokenClaimsInput) (map[string]any, error) {
		if diff := cmp.Diff(input.Resources, req.resources); diff != "" {
			t.Fatalf("callback resources mismatch (-got +want):\n%s", diff)
		}
		input.Resources[0] = "https://mutated.example"
		return nil, nil
	}

	resp, err := generateClientCredentialsToken(ctx, req)
	if err != nil {
		t.Fatalf("generateClientCredentialsToken() error = %v", err)
	}
	if diff := cmp.Diff(resp.Resources, goidc.Resources{"https://resource.example"}); diff != "" {
		t.Fatalf("response resources were aliased (-got +want):\n%s", diff)
	}
	grants := oidctest.Grants(t, ctx)
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	if diff := cmp.Diff(grants[0].Resources, goidc.Resources{"https://resource.example"}); diff != "" {
		t.Fatalf("persisted grant resources were aliased (-got +want):\n%s", diff)
	}
}

func TestClientCredentialsAccessTokenClaimsDistinguishesPresentEmptyAuthorizationDetails(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	ctx.RAREnabled = true
	req.authDetails = []goidc.AuthDetail{}
	ctx.AccessTokenClaimsFunc = func(_ context.Context, input goidc.AccessTokenClaimsInput) (map[string]any, error) {
		if !input.AuthorizationDetailsPresent {
			t.Fatal("AuthorizationDetailsPresent = false, want true for a serialized empty array")
		}
		return nil, nil
	}

	if _, err := generateClientCredentialsToken(ctx, req); err != nil {
		t.Fatalf("generateClientCredentialsToken() error = %v", err)
	}
}

func TestClientCredentialsAccessTokenClaimsRejectTokenOptionsIdentityMutation(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	ctx.AccessTokenClaimsFunc = func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
		t.Fatal("claims callback called after authenticated identity mutation")
		return nil, nil
	}
	ctx.TokenOptionsFunc = func(_ context.Context, grant *goidc.Grant, client *goidc.Client) goidc.TokenOptions {
		grant.ClientID = "substituted-client"
		client.ID = "substituted-client"
		return goidc.NewJWTTokenOptions(goidc.SigAlgPS256, 60)
	}

	_, err := generateClientCredentialsToken(ctx, req)
	assertTokenServerError(t, err)
	if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
		t.Fatalf("len(grants) = %d, want 0", len(grants))
	}
}

func TestClientCredentialsAccessTokenClaimsRejectNonJWTTokenOptions(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	ctx.AccessTokenClaimsFunc = func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
		t.Fatal("claims callback called for a non-JWT token")
		return nil, nil
	}
	ctx.TokenOptionsFunc = func(context.Context, *goidc.Grant, *goidc.Client) goidc.TokenOptions {
		return goidc.TokenOptions{}
	}

	_, err := generateClientCredentialsToken(ctx, req)
	assertTokenServerError(t, err)
	if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
		t.Fatalf("len(grants) = %d, want 0", len(grants))
	}
}

func TestClientCredentialsLegacyTokenClaimsRetainPersistedGrantOrdering(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	ctx.TokenClaimsFunc = func(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
		if grants := oidctest.Grants(t, ctx); len(grants) != 1 {
			t.Fatalf("legacy claims callback observed %d persisted grants, want 1", len(grants))
		}
		return map[string]any{"legacy": true}
	}

	resp, err := generateClientCredentialsToken(ctx, req)
	if err != nil {
		t.Fatalf("generateClientCredentialsToken() error = %v", err)
	}
	claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("SafeClaims() error = %v", err)
	}
	if claims["legacy"] != true {
		t.Fatalf("legacy claim = %v, want true", claims["legacy"])
	}
}

func TestClientCredentialsGrantSaveFailurePreventsSigning(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	manager := &failingTokenGrantManager{saveErr: errors.New("grant store unavailable")}
	ctx.GrantManager = manager
	claimsCalls := 0
	ctx.AccessTokenClaimsFunc = func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
		claimsCalls++
		return map[string]any{"https://example.com/organization_id": "organization"}, nil
	}
	signerCalls := 0
	ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		signerCalls++
		return "", nil, errors.New("signer must not be called")
	}

	_, err := generateClientCredentialsToken(ctx, req)
	if err == nil || !errors.Is(err, manager.saveErr) {
		t.Fatalf("error = %v, want grant save cause", err)
	}
	if claimsCalls != 1 || manager.saveCalls != 1 || signerCalls != 0 {
		t.Fatalf("calls = claims:%d save:%d signer:%d, want 1,1,0", claimsCalls, manager.saveCalls, signerCalls)
	}
}

func TestClientCredentialsCanceledClaimsContextFailsClosed(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	canceled, cancel := context.WithCancel(ctx.Request.Context())
	cancel()
	ctx.Request = ctx.Request.WithContext(canceled)
	claimsCalls := 0
	ctx.AccessTokenClaimsFunc = func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
		claimsCalls++
		return nil, nil
	}
	signerCalls := 0
	ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		signerCalls++
		return "", nil, errors.New("signer must not be called")
	}

	_, err := generateClientCredentialsToken(ctx, req)
	assertTokenServerError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled cause", err)
	}
	if claimsCalls != 0 || signerCalls != 0 || len(oidctest.Grants(t, ctx)) != 0 {
		t.Fatalf("calls/grants = claims:%d signer:%d grants:%d, want zero", claimsCalls, signerCalls, len(oidctest.Grants(t, ctx)))
	}
}

func TestClientCredentialsAccessTokenClaimsFailBeforePersistenceAndSigning(t *testing.T) {
	recursive := map[string]any{}
	recursive["recursive"] = recursive

	tests := []struct {
		name   string
		claims func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error)
	}{
		{
			name: "callback error",
			claims: func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
				return nil, errors.New("claims backend unavailable")
			},
		},
		{
			name: "callback panic",
			claims: func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
				panic("claims panic")
			},
		},
		{
			name: "unserializable claims",
			claims: func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
				return recursive, nil
			},
		},
		{
			name: "panicking JSON marshaler",
			claims: func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
				return map[string]any{"unsafe": panickingJSONMarshaler{}}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, _ := clientCredentialsTestContext(t)
			ctx.AccessTokenClaimsFunc = test.claims
			signerCalls := 0
			ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
				signerCalls++
				return "", nil, errors.New("signer must not be called")
			}

			_, err := generateClientCredentialsToken(ctx, req)
			assertTokenServerError(t, err)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("len(grants) = %d, want 0", len(grants))
			}
			if signerCalls != 0 {
				t.Fatalf("signer calls = %d, want 0", signerCalls)
			}
		})
	}
}

func TestValidatedAccessTokenClaimsPreservesLargeIntegers(t *testing.T) {
	additional, err := validatedAccessTokenClaims(
		context.Background(),
		map[string]any{"large": uint64(9_007_199_254_740_993)},
		map[string]any{goidc.ClaimIssuer: "https://example.com"},
	)
	if err != nil {
		t.Fatalf("validatedAccessTokenClaims() error = %v", err)
	}
	if additional["large"] != json.Number("9007199254740993") {
		t.Fatalf("large claim = %#v, want exact json.Number", additional["large"])
	}
}

func TestClientCredentialsAccessTokenClaimsRejectEngineOwnedClaims(t *testing.T) {
	reserved := []string{
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "scope", "cnf", "act",
		"authorization_details", "grant_id",
	}

	for _, claim := range reserved {
		t.Run(claim, func(t *testing.T) {
			ctx, req, _ := clientCredentialsTestContext(t)
			ctx.AccessTokenClaimsFunc = func(context.Context, goidc.AccessTokenClaimsInput) (map[string]any, error) {
				return map[string]any{claim: "forbidden"}, nil
			}
			signerCalls := 0
			ctx.SignerFunc = func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
				signerCalls++
				return "", nil, errors.New("signer must not be called")
			}

			_, err := generateClientCredentialsToken(ctx, req)
			assertTokenServerError(t, err)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("len(grants) = %d, want 0", len(grants))
			}
			if signerCalls != 0 {
				t.Fatalf("signer calls = %d, want 0", signerCalls)
			}
		})
	}
}

func TestClientCredentialsCanOmitSerializedGrantID(t *testing.T) {
	ctx, req, _ := clientCredentialsTestContext(t)
	ctx.AccessTokenGrantIDClaimDisabled = true
	ctx.TokenClaimsFunc = func(context.Context, *goidc.Token, *goidc.Grant) map[string]any {
		return map[string]any{goidc.ClaimGrantID: "callback-reinjection"}
	}

	resp, err := generateClientCredentialsToken(ctx, req)
	if err != nil {
		t.Fatalf("generateClientCredentialsToken() error = %v", err)
	}
	grants := oidctest.Grants(t, ctx)
	if len(grants) != 1 || grants[0].ID == "" {
		t.Fatalf("persisted grants = %#v, want one grant with an internal ID", grants)
	}
	claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("SafeClaims() error = %v", err)
	}
	if _, ok := claims[goidc.ClaimGrantID]; ok {
		t.Fatalf("JWT claims contain %q, want it omitted", goidc.ClaimGrantID)
	}
}

func clientCredentialsTestContext(t *testing.T) (oidc.Context, request, *goidc.Client) {
	t.Helper()
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	return ctx, request{grantType: goidc.GrantClientCredentials, scopes: oidctest.Scope1.ID}, client
}

func assertTokenServerError(t *testing.T, err error) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeServerError {
		t.Fatalf("error = %v, want %s", err, goidc.ErrorCodeServerError)
	}
}

type failingTokenGrantManager struct {
	saveCalls int
	saveErr   error
}

type panickingJSONMarshaler struct{}

func (panickingJSONMarshaler) MarshalJSON() ([]byte, error) {
	panic("marshal panic")
}

func (manager *failingTokenGrantManager) SaveGrant(context.Context, *goidc.Grant) error {
	manager.saveCalls++
	return manager.saveErr
}

func (*failingTokenGrantManager) Grant(context.Context, string) (*goidc.Grant, error) {
	return nil, goidc.ErrNotFound
}
