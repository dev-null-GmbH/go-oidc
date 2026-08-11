package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
)

func TestRegisterHandlers(t *testing.T) {
	tests := []struct {
		name             string
		enableIntrospect bool
		enableRevoke     bool
		validate         func(*testing.T, *http.ServeMux, oidc.Context)
	}{
		{
			name: "registers token endpoint",
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				ctx.StaticClients = append(ctx.StaticClients, client)

				form := url.Values{
					"grant_type":    {string(goidc.GrantClientCredentials)},
					"client_id":     {client.ID},
					"client_secret": {secret},
					"scope":         {"scope1"},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
			},
		},
		{
			name:             "registers introspection endpoint when enabled",
			enableIntrospect: true,
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				client.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return true
				}

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{ID: "grant_id", ClientID: client.ID, CreatedAt: now}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				jwks := oidctest.PrivateJWKS(t, ctx)
				tknValue := oidctest.Sign(t, map[string]any{
					"jti":       "token_id",
					"grant_id":  grant.ID,
					"iss":       ctx.Issuer(),
					"client_id": client.ID,
					"iat":       now,
					"exp":       now + 60,
				}, jwks.Keys[0])

				form := url.Values{
					"token":           {tknValue},
					"token_type_hint": {string(goidc.TokenHintAccess)},
					"client_id":       {client.ID},
					"client_secret":   {secret},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenIntrospectionEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
				if !strings.Contains(rec.Body.String(), `"active":true`) {
					t.Fatalf("response = %s, want active token", rec.Body.String())
				}
			},
		},
		{
			name:         "registers revocation endpoint when enabled",
			enableRevoke: true,
			validate: func(t *testing.T, mux *http.ServeMux, ctx oidc.Context) {
				client, secret := oidctest.NewClient(t)
				client.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretPost
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return true
				}
				ctx.RefreshTokenManager = oidctest.Manager(t, ctx)

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:           "grant_id",
					ClientID:     client.ID,
					RefreshToken: "refresh_token",
					CreatedAt:    now,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				form := url.Values{
					"token":           {grant.RefreshToken},
					"token_type_hint": {string(goidc.TokenHintRefresh)},
					"client_id":       {client.ID},
					"client_secret":   {secret},
				}
				req := httptest.NewRequest(http.MethodPost, ctx.EndpointPrefix+ctx.TokenRevocationEndpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()

				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.TokenIntrospectionEnabled = test.enableIntrospect
			ctx.TokenRevocationEnabled = test.enableRevoke
			if ctx.TokenIntrospectionEndpoint == "" {
				ctx.TokenIntrospectionEndpoint = "/introspect"
			}
			if ctx.TokenRevocationEndpoint == "" {
				ctx.TokenRevocationEndpoint = "/revoke"
			}

			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			test.validate(t, mux, ctx)
		})
	}
}

func TestTokenHandlersInvalidContentType(t *testing.T) {
	tests := []struct {
		name string
		path string
		fn   func(oidc.Context)
	}{
		{name: "create", path: "/token", fn: handleCreate},
		{name: "introspection", path: "/introspect", fn: handleIntrospection},
		{name: "revocation", path: "/revoke", fn: handleRevocation},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader("x"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			httpCtx := oidc.NewHTTPContext(rec, req, ctx.Configuration)
			test.fn(httpCtx)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if !strings.Contains(rec.Body.String(), string(goidc.ErrorCodeInvalidRequest)) {
				t.Fatalf("response = %s, want invalid_request", rec.Body.String())
			}
		})
	}
}

func TestTokenEndpointDPoPNonce(t *testing.T) {
	tests := []struct {
		name       string
		nonce      string
		rotateTo   string
		wantStatus int
		wantNonce  string
		wantError  goidc.ErrorCode
	}{
		{
			name:       "challenge",
			wantStatus: http.StatusBadRequest,
			wantNonce:  "challenge_nonce",
			wantError:  goidc.ErrorCodeUseDPoPNonce,
		},
		{
			name:       "success with reusable nonce",
			nonce:      "current_nonce",
			wantStatus: http.StatusOK,
		},
		{
			name:       "success rotates nonce when requested",
			nonce:      "current_nonce",
			rotateTo:   "next_nonce",
			wantStatus: http.StatusOK,
			wantNonce:  "next_nonce",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			var evidence []goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, value goidc.TokenEndpointEvidence) {
				evidence = append(evidence, value)
			}
			ctx.DPoPEnabled = true
			ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
			manager := oidctest.NewDPoPNonceManager(test.wantNonce)
			ctx.DPoPNonceManager = manager
			if test.nonce != "" {
				manager.Add(goidc.DPoPNonceScopeAuthorizationServer, test.nonce)
			}
			if test.rotateTo != "" {
				manager.RotateWith(test.rotateTo)
			}
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
				"scope":         {"scope1"},
			}
			req := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + ctx.TokenEndpoint,
				Nonce:  test.nonce,
			})
			req.Header.Set(goidc.HeaderDPoP, proof)
			rec := httptest.NewRecorder()
			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			mux.ServeHTTP(rec, req)

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, test.wantStatus, rec.Body.String())
			}
			gotNonces := rec.Header().Values(goidc.HeaderDPoPNonce)
			if test.wantNonce == "" && len(gotNonces) != 0 {
				t.Fatalf("%s = %v, want empty", goidc.HeaderDPoPNonce, gotNonces)
			}
			if test.wantNonce != "" && (len(gotNonces) != 1 || gotNonces[0] != test.wantNonce) {
				t.Fatalf("%s = %v, want [%s]", goidc.HeaderDPoPNonce, gotNonces, test.wantNonce)
			}
			if test.wantError != "" && !strings.Contains(rec.Body.String(), `"error":"`+string(test.wantError)+`"`) {
				t.Fatalf("body = %s, want error %q", rec.Body.String(), test.wantError)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q, want empty", got)
			}
			wantResult := goidc.TokenEndpointResultIssued
			if test.wantError == goidc.ErrorCodeUseDPoPNonce {
				wantResult = goidc.TokenEndpointResultUseDPoPNonce
			}
			wantEvidence := []goidc.TokenEndpointEvidence{{
				Result:                wantResult,
				AuthenticatedClientID: client.ID,
			}}
			if !reflect.DeepEqual(evidence, wantEvidence) {
				t.Fatalf("evidence = %#v, want %#v", evidence, wantEvidence)
			}
		})
	}
}

func TestTokenEndpointDPoPNonceStoreFailure(t *testing.T) {
	storeErr := errors.New("nonce store unavailable")
	tests := []struct {
		name  string
		nonce string
	}{
		{name: "issue", nonce: ""},
		{name: "validate", nonce: "current_nonce"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			var evidence []goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, value goidc.TokenEndpointEvidence) {
				evidence = append(evidence, value)
			}
			ctx.DPoPEnabled = true
			ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
			ctx.DPoPNonceManager = failingDPoPNonceManager{err: storeErr}
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)

			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
				"scope":         {"scope1"},
			}
			req := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + ctx.TokenEndpoint,
				Nonce:  test.nonce,
			})
			req.Header.Set(goidc.HeaderDPoP, proof)
			rec := httptest.NewRecorder()
			mux := http.NewServeMux()
			RegisterHandlers(mux, ctx.Configuration)

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"error":"server_error"`) {
				t.Fatalf("body = %s, want server_error", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), string(goidc.ErrorCodeUseDPoPNonce)) {
				t.Fatalf("body = %s, must not downgrade to use_dpop_nonce", rec.Body.String())
			}
			if got := rec.Header().Get(goidc.HeaderDPoPNonce); got != "" {
				t.Fatalf("%s = %q, want empty", goidc.HeaderDPoPNonce, got)
			}
			wantEvidence := []goidc.TokenEndpointEvidence{{
				Result:                goidc.TokenEndpointResultServerError,
				AuthenticatedClientID: client.ID,
			}}
			if !reflect.DeepEqual(evidence, wantEvidence) {
				t.Fatalf("evidence = %#v, want %#v", evidence, wantEvidence)
			}
		})
	}
}

func TestTokenEndpointEvidenceInvalidDPoPProof(t *testing.T) {
	ctx := oidctest.NewContext(t)
	ctx.DPoPEnabled = true
	ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	var got []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = append(got, evidence)
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(goidc.HeaderDPoP, "not-a-jwt")
	response := httptest.NewRecorder()
	handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), `"error":"invalid_dpop_proof"`) {
		t.Fatalf("response = (%d, %s), want invalid_dpop_proof", response.Code, response.Body.String())
	}
	want := []goidc.TokenEndpointEvidence{{
		Result:                goidc.TokenEndpointResultInvalidDPoPProof,
		AuthenticatedClientID: client.ID,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestTokenEndpointAttestationDPoPRefreshRequiresVerifiedProof(t *testing.T) {
	for _, test := range []struct {
		name             string
		boundGrant       bool
		corruptProof     bool
		reserveErr       error
		wantStatus       int
		wantResult       goidc.TokenEndpointResult
		wantClientID     bool
		wantReservations int
	}{
		{
			name:             "valid proof is consumed once",
			wantStatus:       http.StatusOK,
			wantResult:       goidc.TokenEndpointResultIssued,
			wantClientID:     true,
			wantReservations: 1,
		},
		{
			name:             "valid proof for bound grant is consumed once",
			boundGrant:       true,
			wantStatus:       http.StatusOK,
			wantResult:       goidc.TokenEndpointResultIssued,
			wantClientID:     true,
			wantReservations: 1,
		},
		{
			name:         "forged signature is rejected without attribution",
			corruptProof: true,
			wantStatus:   http.StatusBadRequest,
			wantResult:   goidc.TokenEndpointResultInvalidDPoPProof,
		},
		{
			name:             "replayed proof is attributed",
			reserveErr:       goidc.ErrJTIReplay,
			wantStatus:       http.StatusBadRequest,
			wantResult:       goidc.TokenEndpointResultInvalidDPoPProof,
			wantClientID:     true,
			wantReservations: 1,
		},
		{
			name:             "replay store failure is attributed",
			reserveErr:       errors.New("replay store unavailable"),
			wantStatus:       http.StatusInternalServerError,
			wantResult:       goidc.TokenEndpointResultServerError,
			wantClientID:     true,
			wantReservations: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.RefreshTokenManager = oidctest.Manager(t, ctx)
			ctx.AuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodAttestationJWT}
			ctx.DPoPEnabled = true
			ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgPS256}

			issuerKey := oidctest.PrivateRS256JWK(t, "attestation-issuer", goidc.KeyUsageSignature)
			issuerJWKS := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{issuerKey.Public()}}
			issuerServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(response).Encode(issuerJWKS); err != nil {
					t.Errorf("encode issuer JWKS: %v", err)
				}
			}))
			t.Cleanup(issuerServer.Close)
			ctx.HTTPClientFunc = func(context.Context) *http.Client { return issuerServer.Client() }
			ctx.AuthnMethodAttestationJWTIssuers = []goidc.AttestationIssuer{{
				Issuer:  "https://attester.example.com",
				JWKSURI: issuerServer.URL + "/jwks",
			}}

			client, _ := oidctest.NewClient(t)
			client.TokenAuthnMethod = goidc.AuthnMethodAttestationJWT
			client.GrantTypes = []goidc.GrantType{goidc.GrantRefreshToken}
			ctx.StaticClients = append(ctx.StaticClients, client)

			now := timeutil.TimestampNow()
			grant := &goidc.Grant{
				ID:                    "unbound-refresh-grant",
				RefreshToken:          "unbound-refresh-token",
				RefreshTokenExpiresAt: now + 60,
				CreatedAt:             now,
				Subject:               "subject",
				ClientID:              client.ID,
				Scopes:                client.ScopeIDs,
				Store:                 make(map[string]any),
			}
			if test.boundGrant {
				grant.JWKThumbprint = "existing-binding"
			}
			if err := ctx.SaveGrant(grant); err != nil {
				t.Fatalf("SaveGrant() error = %v", err)
			}

			clientKey := oidctest.PrivatePS256JWK(t, "attestation-client", goidc.KeyUsageSignature)
			attestation := oidctest.SignWithOptions(t, map[string]any{
				goidc.ClaimIssuer:  "https://attester.example.com",
				goidc.ClaimSubject: client.ID,
				goidc.ClaimExpiry:  now + 300,
				"cnf":              map[string]any{"jwk": clientKey.Public()},
			}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + ctx.TokenEndpoint,
				Key:    clientKey.Key,
			})
			if test.corruptProof {
				proof = corruptCompactJWSSignature(t, proof)
			}

			var reservations int
			ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
				if use.Purpose != goidc.JTIUsePurposeDPoPProof {
					t.Fatalf("JTI purpose = %q, want DPoP proof", use.Purpose)
				}
				reservations++
				return test.reserveErr
			}
			var evidence []goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, value goidc.TokenEndpointEvidence) {
				evidence = append(evidence, value)
			}

			form := url.Values{
				"grant_type":    {string(goidc.GrantRefreshToken)},
				"refresh_token": {grant.RefreshToken},
				"client_id":     {client.ID},
			}
			request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Oauth-Client-Attestation", attestation)
			request.Header.Set(goidc.HeaderDPoP, proof)
			response := httptest.NewRecorder()

			handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if reservations != test.wantReservations {
				t.Fatalf("DPoP JTI reservations = %d, want %d", reservations, test.wantReservations)
			}
			wantClientID := ""
			if test.wantClientID {
				wantClientID = client.ID
			}
			wantEvidence := []goidc.TokenEndpointEvidence{{
				Result:                test.wantResult,
				AuthenticatedClientID: wantClientID,
			}}
			if !reflect.DeepEqual(evidence, wantEvidence) {
				t.Fatalf("evidence = %#v, want %#v", evidence, wantEvidence)
			}
		})
	}
}

func corruptCompactJWSSignature(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("JWS = %q, want compact serialization", compact)
	}
	signature := []byte(parts[2])
	if signature[0] == 'A' {
		signature[0] = 'B'
	} else {
		signature[0] = 'A'
	}
	parts[2] = string(signature)
	return strings.Join(parts, ".")
}

type failingDPoPNonceManager struct {
	err error
}

func (m failingDPoPNonceManager) IssueNonce(context.Context, goidc.DPoPNonceScope) (string, error) {
	return "", m.err
}

func (m failingDPoPNonceManager) ValidateNonce(context.Context, goidc.DPoPNonceScope, string) (goidc.DPoPNonceValidation, error) {
	return goidc.DPoPNonceValidation{}, m.err
}

func TestTokenEndpointErrorStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*goidc.Client, url.Values)
		wantCode   goidc.ErrorCode
		wantStatus int
	}{
		{
			name: "invalid client authentication uses 401",
			setup: func(_ *goidc.Client, form url.Values) {
				form.Set("client_secret", "invalid_secret")
			},
			wantCode:   goidc.ErrorCodeInvalidClient,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unauthorized client uses 400",
			setup: func(client *goidc.Client, _ url.Values) {
				client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
			},
			wantCode:   goidc.ErrorCodeUnauthorizedClient,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
				"scope":         {"scope1"},
			}
			test.setup(client, form)

			req := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			handleCreate(oidc.NewHTTPContext(rec, req, ctx.Configuration))

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, test.wantStatus)
			}
			var body struct {
				Error goidc.ErrorCode `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Error != test.wantCode {
				t.Fatalf("error = %s, want %s", body.Error, test.wantCode)
			}
		})
	}
}

func TestTokenEndpointEvidenceSelectsClosedResultAndAuthenticationBoundary(t *testing.T) {
	tests := []struct {
		name             string
		setup            func(oidc.Context, *goidc.Client, url.Values) string
		wantResult       goidc.TokenEndpointResult
		wantClientID     bool
		wantStatus       int
		wantProtocolCode goidc.ErrorCode
	}{
		{
			name:         "issued",
			setup:        func(oidc.Context, *goidc.Client, url.Values) string { return "application/x-www-form-urlencoded" },
			wantResult:   goidc.TokenEndpointResultIssued,
			wantClientID: true,
			wantStatus:   http.StatusOK,
		},
		{
			name: "invalid content type before authentication",
			setup: func(oidc.Context, *goidc.Client, url.Values) string {
				return "application/json"
			},
			wantResult:       goidc.TokenEndpointResultInvalidRequest,
			wantStatus:       http.StatusBadRequest,
			wantProtocolCode: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "invalid client before authentication",
			setup: func(_ oidc.Context, _ *goidc.Client, form url.Values) string {
				form.Set("client_secret", "wrong-secret")
				return "application/x-www-form-urlencoded"
			},
			wantResult:       goidc.TokenEndpointResultInvalidClient,
			wantStatus:       http.StatusUnauthorized,
			wantProtocolCode: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "unauthorized grant after authentication",
			setup: func(_ oidc.Context, client *goidc.Client, _ url.Values) string {
				client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return "application/x-www-form-urlencoded"
			},
			wantResult:       goidc.TokenEndpointResultUnauthorizedClient,
			wantClientID:     true,
			wantStatus:       http.StatusBadRequest,
			wantProtocolCode: goidc.ErrorCodeUnauthorizedClient,
		},
		{
			name: "invalid scope after authentication",
			setup: func(_ oidc.Context, _ *goidc.Client, form url.Values) string {
				form.Set("scope", "unavailable")
				return "application/x-www-form-urlencoded"
			},
			wantResult:       goidc.TokenEndpointResultInvalidScope,
			wantClientID:     true,
			wantStatus:       http.StatusBadRequest,
			wantProtocolCode: goidc.ErrorCodeInvalidScope,
		},
		{
			name: "invalid target after authentication",
			setup: func(ctx oidc.Context, _ *goidc.Client, form url.Values) string {
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []goidc.ResourceIndicator{"https://resource.example/allowed"}
				form["resource"] = []string{"https://resource.example/denied"}
				return "application/x-www-form-urlencoded"
			},
			wantResult:       goidc.TokenEndpointResultInvalidTarget,
			wantClientID:     true,
			wantStatus:       http.StatusBadRequest,
			wantProtocolCode: goidc.ErrorCodeInvalidTarget,
		},
		{
			name: "unsupported grant before authentication",
			setup: func(_ oidc.Context, _ *goidc.Client, form url.Values) string {
				form.Set("grant_type", "future_grant")
				return "application/x-www-form-urlencoded"
			},
			wantResult:       goidc.TokenEndpointResultProtocolDenied,
			wantStatus:       http.StatusBadRequest,
			wantProtocolCode: goidc.ErrorCodeUnsupportedGrantType,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
				"scope":         {"scope1"},
			}
			contentType := test.setup(ctx, client, form)
			type contextKey struct{}
			requestContext := context.WithValue(t.Context(), contextKey{}, "context-canary")
			request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode())).WithContext(requestContext)
			request.Header.Set("Content-Type", contentType)
			response := httptest.NewRecorder()
			var evidence []goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(callbackContext context.Context, value goidc.TokenEndpointEvidence) {
				if callbackContext != requestContext {
					t.Errorf("callback context = %p, want exact request context %p", callbackContext, requestContext)
				}
				evidence = append(evidence, value)
			}

			handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if len(evidence) != 1 {
				t.Fatalf("evidence calls = %d, want 1", len(evidence))
			}
			wantClientID := ""
			if test.wantClientID {
				wantClientID = client.ID
			}
			wantEvidence := goidc.TokenEndpointEvidence{Result: test.wantResult, AuthenticatedClientID: wantClientID}
			if evidence[0] != wantEvidence {
				t.Fatalf("evidence = %#v, want %#v", evidence[0], wantEvidence)
			}
			if test.wantProtocolCode != "" {
				var body struct {
					Error goidc.ErrorCode `json:"error"`
				}
				if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if body.Error != test.wantProtocolCode {
					t.Fatalf("protocol error = %s, want %s", body.Error, test.wantProtocolCode)
				}
			}
		})
	}
}

func TestTokenEndpointEvidenceCallbackPanicCannotChangeProtocolResponse(t *testing.T) {
	run := func(t *testing.T, callback goidc.TokenEndpointEvidenceFunc) *httptest.ResponseRecorder {
		t.Helper()
		ctx := oidctest.NewContext(t)
		ctx.TokenEndpointEvidenceFunc = callback
		request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))
		return response
	}

	baseline := run(t, nil)
	var calls int
	withPanic := run(t, func(context.Context, goidc.TokenEndpointEvidence) {
		calls++
		panic("evidence callback panic canary")
	})
	if calls != 1 {
		t.Fatalf("callback calls = %d, want 1", calls)
	}
	if baseline.Code != withPanic.Code || baseline.Body.String() != withPanic.Body.String() ||
		!reflect.DeepEqual(baseline.Header(), withPanic.Header()) {
		t.Fatalf("callback panic changed response: baseline=(%d,%q,%v), got=(%d,%q,%v)",
			baseline.Code, baseline.Body.String(), baseline.Header(), withPanic.Code, withPanic.Body.String(), withPanic.Header())
	}
}

func TestTokenEndpointEvidenceCallbackPanicCannotChangeSuccessfulIssuance(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	var calls int
	ctx.TokenEndpointEvidenceFunc = func(context.Context, goidc.TokenEndpointEvidence) {
		calls++
		panic("evidence callback panic canary")
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

	if calls != 1 {
		t.Fatalf("callback calls = %d, want 1", calls)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AccessToken == "" || body.TokenType == "" {
		t.Fatalf("successful response = %#v, want token", body)
	}
}

func TestTokenEndpointEvidenceRetainsAuthenticatedClientSnapshotAfterMutation(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	originalClientID := client.ID
	ctx.StaticClients = append(ctx.StaticClients, client)
	originalTokenOptions := ctx.TokenOptionsFunc
	ctx.TokenOptionsFunc = func(callbackContext context.Context, grant *goidc.Grant, callbackClient *goidc.Client) goidc.TokenOptions {
		options := originalTokenOptions(callbackContext, grant, callbackClient)
		callbackClient.ID = "mutated-after-authentication"
		return options
	}
	var got goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = evidence
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {originalClientID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handleCreate(oidc.NewHTTPContext(response, request, ctx.Configuration))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	want := goidc.TokenEndpointEvidence{
		Result:                goidc.TokenEndpointResultIssued,
		AuthenticatedClientID: originalClientID,
	}
	if got != want {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestTokenEndpointEvidenceCallbackPanicPreservesEnginePanic(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	enginePanic := &struct{ name string }{name: "engine panic"}
	ctx.HandleGrantFunc = func(context.Context, goidc.GrantType, *goidc.Grant) error {
		panic(enginePanic)
	}
	var evidence []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, value goidc.TokenEndpointEvidence) {
		evidence = append(evidence, value)
		panic("evidence panic")
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handleCreate(oidc.NewHTTPContext(httptest.NewRecorder(), request, ctx.Configuration))
	}()

	if recovered != enginePanic {
		t.Fatalf("recovered panic = %#v, want original %#v", recovered, enginePanic)
	}
	want := []goidc.TokenEndpointEvidence{{
		Result:                goidc.TokenEndpointResultServerError,
		AuthenticatedClientID: client.ID,
	}}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("evidence = %#v, want %#v", evidence, want)
	}
}

func TestTokenEndpointEvidenceDoesNotObserveOtherTokenOperations(t *testing.T) {
	ctx := oidctest.NewContext(t)
	var calls int
	ctx.TokenEndpointEvidenceFunc = func(context.Context, goidc.TokenEndpointEvidence) { calls++ }

	for _, fn := range []func(oidc.Context){handleIntrospection, handleRevocation} {
		request := httptest.NewRequest(http.MethodPost, "/operation", strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		fn(oidc.NewHTTPContext(httptest.NewRecorder(), request, ctx.Configuration))
	}
	if calls != 0 {
		t.Fatalf("callback calls = %d, want 0 for introspection/revocation", calls)
	}
}

type tokenEvidenceFailingResponseWriter struct {
	header http.Header
}

func (writer *tokenEvidenceFailingResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (*tokenEvidenceFailingResponseWriter) WriteHeader(int) {}

func (*tokenEvidenceFailingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("response write failed")
}

type tokenEvidencePanickingResponseWriter struct {
	header http.Header
	panic  any
}

func (writer *tokenEvidencePanickingResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *tokenEvidencePanickingResponseWriter) WriteHeader(int) {
	panic(writer.panic)
}

func (*tokenEvidencePanickingResponseWriter) Write(value []byte) (int, error) {
	return len(value), nil
}

func TestTokenEndpointEvidenceResponseWriteFailureIsServerError(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	var got []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = append(got, evidence)
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleCreate(oidc.NewHTTPContext(&tokenEvidenceFailingResponseWriter{}, request, ctx.Configuration))

	want := []goidc.TokenEndpointEvidence{{
		Result:                goidc.TokenEndpointResultServerError,
		AuthenticatedClientID: client.ID,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestTokenEndpointEvidenceErrorRenderingFailureIsServerError(t *testing.T) {
	ctx := oidctest.NewContext(t)
	var got []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = append(got, evidence)
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	handleCreate(oidc.NewHTTPContext(&tokenEvidenceFailingResponseWriter{}, request, ctx.Configuration))

	want := []goidc.TokenEndpointEvidence{{Result: goidc.TokenEndpointResultServerError}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestTokenEndpointEvidenceResponseWriterPanicIsServerErrorAndPreserved(t *testing.T) {
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	ctx.StaticClients = append(ctx.StaticClients, client)
	var got []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = append(got, evidence)
	}
	form := url.Values{
		"grant_type":    {string(goidc.GrantClientCredentials)},
		"client_id":     {client.ID},
		"client_secret": {secret},
	}
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	writerPanic := &struct{ name string }{name: "writer panic"}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handleCreate(oidc.NewHTTPContext(
			&tokenEvidencePanickingResponseWriter{panic: writerPanic},
			request,
			ctx.Configuration,
		))
	}()

	if recovered != writerPanic {
		t.Fatalf("recovered panic = %#v, want original %#v", recovered, writerPanic)
	}
	want := []goidc.TokenEndpointEvidence{{
		Result:                goidc.TokenEndpointResultServerError,
		AuthenticatedClientID: client.ID,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

type tokenEvidenceCancelingResponseWriter struct {
	response *httptest.ResponseRecorder
	cancel   context.CancelFunc
}

func (writer tokenEvidenceCancelingResponseWriter) Header() http.Header {
	return writer.response.Header()
}

func (writer tokenEvidenceCancelingResponseWriter) WriteHeader(status int) {
	writer.response.WriteHeader(status)
	writer.cancel()
}

func (writer tokenEvidenceCancelingResponseWriter) Write(value []byte) (int, error) {
	return writer.response.Write(value)
}

func TestTokenEndpointEvidenceCancellationClassifiesByWriteCompletion(t *testing.T) {
	for _, test := range []struct {
		name         string
		cancelBefore bool
		want         goidc.TokenEndpointResult
	}{
		{name: "before write", cancelBefore: true, want: goidc.TokenEndpointResultServerError},
		{name: "during successful write", want: goidc.TokenEndpointResultIssued},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			client, secret := oidctest.NewClient(t)
			ctx.StaticClients = append(ctx.StaticClients, client)
			var got []goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
				got = append(got, evidence)
			}
			form := url.Values{
				"grant_type":    {string(goidc.GrantClientCredentials)},
				"client_id":     {client.ID},
				"client_secret": {secret},
			}
			requestContext, cancel := context.WithCancel(t.Context())
			request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader(form.Encode())).WithContext(requestContext)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			var writer http.ResponseWriter = response
			if test.cancelBefore {
				cancel()
			} else {
				writer = tokenEvidenceCancelingResponseWriter{response: response, cancel: cancel}
			}
			defer cancel()

			handleCreate(oidc.NewHTTPContext(writer, request, ctx.Configuration))

			if len(got) != 1 || got[0].Result != test.want {
				t.Fatalf("evidence = %#v, want one %v result", got, test.want)
			}
		})
	}
}

func TestTokenEndpointEvidenceCancellationDuringSuccessfulDenialWriteReportsDenial(t *testing.T) {
	ctx := oidctest.NewContext(t)
	var got []goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = append(got, evidence)
	}
	requestContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, ctx.TokenEndpoint, strings.NewReader("{}")).WithContext(requestContext)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handleCreate(oidc.NewHTTPContext(
		tokenEvidenceCancelingResponseWriter{response: response, cancel: cancel},
		request,
		ctx.Configuration,
	))

	want := []goidc.TokenEndpointEvidence{{Result: goidc.TokenEndpointResultInvalidRequest}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}
