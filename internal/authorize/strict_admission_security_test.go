package authorize

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestHumanConfidentialBFFPublicClientCannotPushWithoutAssertion(t *testing.T) {
	t.Parallel()

	ctx, client, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	client.TokenAuthnMethod = goidc.AuthnMethodNone
	client.TokenAuthnSigAlg = ""
	client.PrivateKeyJWTAuthority = nil
	values.Del("client_assertion")
	values.Del("client_assertion_type")

	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest

	_, err := pushAuth(ctx, newFormRequest(httpRequest))
	assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("misqualified public human client persisted %d PAR sessions", len(sessions))
	}
}

func TestHumanConfidentialBFFClientQualificationFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*goidc.Client)
	}{
		{
			name: "wrong client authentication method",
			mutate: func(client *goidc.Client) {
				client.TokenAuthnMethod = goidc.AuthnMethodSecretPost
			},
		},
		{
			name: "wrong client assertion algorithm",
			mutate: func(client *goidc.Client) {
				client.TokenAuthnSigAlg = goidc.SigAlgRS256
			},
		},
		{
			name: "missing key authority",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority = nil
			},
		},
		{
			name: "invalid key authority revision",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.SnapshotRevision = 0
			},
		},
		{
			name: "empty key authority",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys = nil
			},
		},
		{
			name: "missing exact key authority identity",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = ""
			},
		},
		{
			name: "invalid exact key authority identity syntax",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = "authority identity"
			},
		},
		{
			name: "oversized exact key authority identity",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].KeyAuthorityID = strings.Repeat("a", 129)
			},
		},
		{
			name: "invalid JWK key ID syntax",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.KeyID = "key id"
			},
		},
		{
			name: "oversized JWK key ID",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.KeyID = strings.Repeat("k", 129)
			},
		},
		{
			name: "nonstandard RSA authority exponent",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey).E = 3
			},
		},
		{
			name: "oversized RSA authority modulus",
			mutate: func(client *goidc.Client) {
				modulus := new(big.Int).Lsh(big.NewInt(1), maxHumanConfidentialBFFRSAModulusBits)
				client.PrivateKeyJWTAuthority.Keys[0].Key.Key.(*rsa.PublicKey).N = modulus.SetBit(modulus, 0, 1)
			},
		},
		{
			name: "JWK certificate chain",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.Certificates = []*x509.Certificate{{}}
			},
		},
		{
			name: "JWK certificate URL",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.CertificatesURL = &url.URL{
					Scheme: "https",
					Host:   "keys.example.invalid",
				}
			},
		},
		{
			name: "JWK SHA-1 certificate thumbprint",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.CertificateThumbprintSHA1 = []byte{1}
			},
		},
		{
			name: "JWK SHA-256 certificate thumbprint",
			mutate: func(client *goidc.Client) {
				client.PrivateKeyJWTAuthority.Keys[0].Key.CertificateThumbprintSHA256 = []byte{1}
			},
		},
		{
			name: "oversized client name",
			mutate: func(client *goidc.Client) {
				client.Name = strings.Repeat("n", 129)
			},
		},
		{
			name: "invalid UTF-8 client name",
			mutate: func(client *goidc.Client) {
				client.Name = string([]byte{0xff})
			},
		},
		{
			name: "untrimmed client name",
			mutate: func(client *goidc.Client) {
				client.Name = " d0 dashboard"
			},
		},
		{
			name: "client name containing NUL",
			mutate: func(client *goidc.Client) {
				client.Name = "d0\x00dashboard"
			},
		},
		{
			name: "contradictory required request object",
			mutate: func(client *goidc.Client) {
				client.JARRequired = true
			},
		},
		{
			name: "contradictory request object metadata",
			mutate: func(client *goidc.Client) {
				client.JARSigAlg = goidc.SigAlgPS256
			},
		},
		{
			name: "contradictory secured authorization response",
			mutate: func(client *goidc.Client) {
				client.JARMSigAlg = goidc.SigAlgPS256
			},
		},
		{
			name: "forbidden authorization detail surface",
			mutate: func(client *goidc.Client) {
				client.AuthDetailTypes = []goidc.AuthDetailType{goidc.AuthDetailTypeOpenIDCredential}
			},
		},
		{
			name: "redirects span pairwise sectors",
			mutate: func(client *goidc.Client) {
				client.RedirectURIs = []string{
					"https://a.example.invalid/callback",
					"https://b.example.invalid/callback",
				}
			},
		},
		{
			name: "deferred sector identifier behavior",
			mutate: func(client *goidc.Client) {
				client.SectorIdentifierURI = "https://human-bff.example.invalid/sector.json"
			},
		},
		{
			name: "deferred ID token encryption",
			mutate: func(client *goidc.Client) {
				client.IDTokenKeyEncAlg = goidc.KeyEncRSAOAEP256
			},
		},
		{
			name: "deferred DPoP binding",
			mutate: func(client *goidc.Client) {
				client.DPoPTokenBindingRequired = true
			},
		},
		{
			name: "legacy client JWKS",
			mutate: func(client *goidc.Client) {
				client.JWKS = &goidc.JSONWebKeySet{}
			},
		},
		{
			name: "unqualified custom metadata",
			mutate: func(client *goidc.Client) {
				client.CustomAttributes = map[string]any{"mode": "deferred"}
			},
		},
		{
			name: "organization name metadata",
			mutate: func(client *goidc.Client) {
				client.OrganizationName = "attacker-controlled"
			},
		},
		{
			name: "display name metadata",
			mutate: func(client *goidc.Client) {
				client.DisplayName = "attacker-controlled"
			},
		},
		{
			name: "description metadata",
			mutate: func(client *goidc.Client) {
				client.Description = "attacker-controlled"
			},
		},
		{
			name: "keyword metadata",
			mutate: func(client *goidc.Client) {
				client.Keywords = []string{"attacker-controlled"}
			},
		},
		{
			name: "information URI metadata",
			mutate: func(client *goidc.Client) {
				client.InformationURI = "https://attacker.example.invalid/information"
			},
		},
		{
			name: "organization URI metadata",
			mutate: func(client *goidc.Client) {
				client.OrganizationURI = "https://attacker.example.invalid/organization"
			},
		},
		{
			name: "missing refresh grant metadata",
			mutate: func(client *goidc.Client) {
				client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
			},
		},
		{
			name: "reordered grant metadata",
			mutate: func(client *goidc.Client) {
				client.GrantTypes = []goidc.GrantType{goidc.GrantRefreshToken, goidc.GrantAuthorizationCode}
			},
		},
		{
			name: "third grant metadata",
			mutate: func(client *goidc.Client) {
				client.GrantTypes = append(client.GrantTypes, goidc.GrantClientCredentials)
			},
		},
		{
			name: "non-code-only response metadata",
			mutate: func(client *goidc.Client) {
				client.ResponseTypes = append(client.ResponseTypes, goidc.ResponseTypeIDToken)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, client, _ := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
			test.mutate(client)

			_, _, err := authorizationAdmissionClient(client)
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeServerError)
		})
	}
}

func TestHumanConfidentialBFFClientQualificationAcceptsBoundedName(t *testing.T) {
	t.Parallel()

	_, client, _ := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	client.Name = "d0 Dashboard"

	clone, strict, err := authorizationAdmissionClient(client)
	if err != nil {
		t.Fatalf("authorizationAdmissionClient() error = %v", err)
	}
	if !strict || clone == nil || clone.Name != client.Name {
		t.Fatalf("authorizationAdmissionClient() = (%#v, %t, nil), want isolated named strict client", clone, strict)
	}
}

func TestHumanConfidentialBFFPARRejectsConflictingAuthenticationHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setHeaders func(*http.Request, string, string)
	}{
		{
			name: "authorization basic alongside private key JWT",
			setHeaders: func(request *http.Request, clientID, _ string) {
				request.SetBasicAuth(clientID, "unused-secret")
			},
		},
		{
			name: "duplicate authorization header",
			setHeaders: func(request *http.Request, clientID, _ string) {
				request.SetBasicAuth(clientID, "unused-secret")
				request.Header.Add("Authorization", request.Header.Get("Authorization"))
			},
		},
		{
			name: "OAuth client attestation alongside private key JWT",
			setHeaders: func(request *http.Request, _ string, assertion string) {
				request.Header.Set("Oauth-Client-Attestation", assertion)
			},
		},
		{
			name: "duplicate OAuth client attestation header",
			setHeaders: func(request *http.Request, _ string, assertion string) {
				request.Header.Add("Oauth-Client-Attestation", assertion)
				request.Header.Add("Oauth-Client-Attestation", assertion)
			},
		},
		{
			name: "OAuth client attestation PoP alongside private key JWT",
			setHeaders: func(request *http.Request, _, assertion string) {
				request.Header.Set("Oauth-Client-Attestation-Pop", assertion)
			},
		},
		{
			name: "duplicate OAuth client attestation PoP header",
			setHeaders: func(request *http.Request, _, assertion string) {
				request.Header.Add("Oauth-Client-Attestation-Pop", assertion)
				request.Header.Add("Oauth-Client-Attestation-Pop", assertion)
			},
		},
		{
			name: "OAuth client attestation and PoP alongside private key JWT",
			setHeaders: func(request *http.Request, _, assertion string) {
				request.Header.Set("Oauth-Client-Attestation", assertion)
				request.Header.Set("Oauth-Client-Attestation-Pop", assertion)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
			httpRequest := httptest.NewRequest(
				http.MethodPost,
				"https://example.com/par",
				strings.NewReader(values.Encode()),
			)
			httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			test.setHeaders(httpRequest, client.ID, values.Get("client_assertion"))
			ctx.Request = httpRequest

			_, err := pushAuth(ctx, newFormRequest(httpRequest))
			assertAuthorizationErrorCode(t, err, goidc.ErrorCodeInvalidRequest)
			if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
				t.Fatalf("conflicting authentication headers persisted %d PAR sessions", len(sessions))
			}
		})
	}
}

func TestHumanConfidentialBFFPARUsesTypedProfileAuthority(t *testing.T) {
	t.Parallel()

	ctx, _, values := newStrictPARContext(t, goidc.AuthorizationRequestProfileHumanConfidentialBFF)
	called := false
	ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
		storePAR: func(_ context.Context, input goidc.HumanPARInput) (goidc.HumanPARDecision, error) {
			called = input.Valid()
			requestURI := mustHumanPushedRequestURI(t, strictHumanTestRequestURI)
			receipt, err := goidc.NewHumanPARReceipt(requestURI, 60)
			if err != nil {
				t.Fatal(err)
			}
			return mustHumanPARDecision(t, goidc.HumanPAROutcomeCreated, receipt), nil
		},
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "https://example.com/par", strings.NewReader(values.Encode()))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = httpRequest

	if _, err := pushAuth(ctx, newFormRequest(httpRequest)); err != nil {
		t.Fatalf("pushAuth() error = %v", err)
	}
	if !called {
		t.Fatal("strict PAR did not call the typed authority")
	}
	if sessions := oidctest.AuthnSessions(t, ctx); len(sessions) != 0 {
		t.Fatalf("strict PAR persisted %d legacy sessions", len(sessions))
	}
}

func TestInFlightPARAuthorizationAdmissionProfileDriftFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		sessionProfile goidc.AuthorizationRequestProfile
		currentProfile goidc.AuthorizationRequestProfile
		unsafeOuter    bool
		wantErr        goidc.ErrorCode
	}{
		{
			name:           "default PAR cannot upgrade to strict admission",
			sessionProfile: goidc.AuthorizationRequestProfileDefault,
			currentProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
			wantErr:        goidc.ErrorCodeInvalidRequest,
		},
		{
			name:           "strict PAR cannot downgrade to default admission",
			sessionProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
			currentProfile: goidc.AuthorizationRequestProfileDefault,
			unsafeOuter:    true,
			wantErr:        goidc.ErrorCodeServerError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, client, requestURI := newStrictOuterAuthorizationContext(t)
			client.AuthorizationRequestProfile = test.currentProfile
			if test.currentProfile == goidc.AuthorizationRequestProfileHumanConfidentialBFF {
				ctx.HumanAuthorizationAuthority = &stubHumanAuthorizationAuthority{
					start: func(context.Context, goidc.HumanStartInput) (goidc.HumanStartDecision, error) {
						return mustHumanStartDecision(t, goidc.HumanStartDecisionConfig{
							Outcome: goidc.HumanStartOutcomeRejected,
						}), nil
					},
				}
			}

			session, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(requestURI, parRequestURIPrefix))
			if err != nil {
				t.Fatalf("PARSessionByPushedAuthReqID() error = %v", err)
			}
			session.AuthorizationRequestProfile = test.sessionProfile
			before := cloneHumanConfidentialBFFAuthorizationParameters(session.AuthorizationParameters)
			if err := ctx.AuthSaveSession(session); err != nil {
				t.Fatalf("AuthSaveSession() error = %v", err)
			}

			outer := outerAuthorizationValues(client.ID, requestURI)
			if test.unsafeOuter {
				outer.Set("login_hint", "unsafe-outer-login-hint")
			}
			httpRequest := httptest.NewRequest(http.MethodGet, "https://example.com/authorize?"+outer.Encode(), nil)
			ctx.Request = httpRequest

			err = initAuth(ctx, newRequest(httpRequest))
			assertAuthorizationErrorCode(t, err, test.wantErr)
			if grants := oidctest.Grants(t, ctx); len(grants) != 0 {
				t.Fatalf("authorization profile drift issued %d grants", len(grants))
			}

			persisted, err := ctx.PARSessionByPushedAuthReqID(strings.TrimPrefix(requestURI, parRequestURIPrefix))
			if err != nil {
				t.Fatalf("PARSessionByPushedAuthReqID() after rejection error = %v", err)
			}
			if !humanConfidentialBFFAuthorizationParametersEqual(persisted.AuthorizationParameters, before) {
				t.Fatalf(
					"authorization profile drift changed persisted parameters: before=%#v after=%#v",
					before,
					persisted.AuthorizationParameters,
				)
			}
			if persisted.LoginHint == "unsafe-outer-login-hint" {
				t.Fatal("authorization profile drift merged an unsafe outer login_hint")
			}
		})
	}
}
