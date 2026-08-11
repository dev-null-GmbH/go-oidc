package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/dpop"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
)

func TestValidateJWT(t *testing.T) {

	var testCases = []struct {
		name          string
		dpopJWT       string
		opts          dpop.ValidationOptions
		ctx           oidc.Context
		shouldBeValid bool
	}{
		{
			"valid_dpop_jwt",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			dpop.ValidationOptions{},
			oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgPS256, goidc.SigAlgES256},
					ConsumeJTIFunc:  func(_ context.Context, _ string) error { return nil },
					JWTLifetimeSecs: 99999999999,
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			},
			true,
		},
		{
			"valid_dpop_jwt_with_ath",
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
			dpop.ValidationOptions{
				AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
			},
			oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://resource.example.org",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgRS256, goidc.SigAlgPS256, goidc.SigAlgES256},
					ConsumeJTIFunc:  func(_ context.Context, _ string) error { return nil },
					JWTLifetimeSecs: 99999999999,
				},
				Request: httptest.NewRequest(http.MethodGet, "/protectedresource", nil),
			},
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				// When.
				err := dpop.ValidateJWT(testCase.ctx, testCase.dpopJWT, testCase.opts)

				// Then.
				isValid := err == nil
				if isValid != testCase.shouldBeValid {
					t.Errorf("isValid = %t, want %t", isValid, testCase.shouldBeValid)
				}
			},
		)
	}
}

func TestValidateJWTConsumesTypedJTIOnlyAfterProofValidation(t *testing.T) {
	const (
		lifetime = 60
		leeway   = 7
	)
	issuedAt := time.Now().UTC().Truncate(time.Second)
	proof, thumbprint := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method:   http.MethodPost,
		URI:      "https://server.example.com/token",
		IssuedAt: issuedAt,
	})
	request := httptest.NewRequest(http.MethodPost, "/token", nil)
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:              "https://server.example.com",
			DPoPEnabled:       true,
			DPoPSigAlgs:       []goidc.SignatureAlgorithm{goidc.SigAlgES256},
			JWTLifetimeSecs:   lifetime,
			JWTLeewayTimeSecs: leeway,
		},
		Request: request,
	}

	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}
	if err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
		TokenEndpoint: true,
	}); err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}

	if got.ID == "" {
		t.Fatal("typed JTI consumer was not called")
	}
	if got.Issuer != thumbprint {
		t.Errorf("JTI issuer = %q, want DPoP key thumbprint %q", got.Issuer, thumbprint)
	}
	if got.Purpose != goidc.JTIUsePurposeDPoPProof {
		t.Errorf("JTI purpose = %q, want %q", got.Purpose, goidc.JTIUsePurposeDPoPProof)
	}
	wantExpiry := issuedAt.Add((lifetime + leeway) * time.Second)
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("JTI expiry = %v, want %v", got.ExpiresAt, wantExpiry)
	}

	ctx.Request = httptest.NewRequest(http.MethodGet, "/token", nil)
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called before HTTP method validation")
		return nil
	}
	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
		TokenEndpoint: true,
	})
	if err == nil {
		t.Fatal("ValidateJWT() error = nil for invalid HTTP method")
	}
	var tokenEndpointErr goidc.Error
	if !errors.As(err, &tokenEndpointErr) || tokenEndpointErr.Code != goidc.ErrorCodeInvalidDPoPProof {
		t.Fatalf("token endpoint error = %v, want %q", err, goidc.ErrorCodeInvalidDPoPProof)
	}

	err = dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope: goidc.DPoPNonceScopeAuthorizationServer,
	})
	var authorizationEndpointErr goidc.Error
	if !errors.As(err, &authorizationEndpointErr) || authorizationEndpointErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Fatalf("authorization endpoint error = %v, want %q", err, goidc.ErrorCodeInvalidRequest)
	}
}

func TestValidateJWTCallsValidatedHookAfterNonceBeforeReplayReservation(t *testing.T) {
	var calls []string
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    "https://server.example.com/token",
		Nonce:  "current_nonce",
	})
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:             "https://server.example.com",
			DPoPEnabled:      true,
			DPoPSigAlgs:      []goidc.SignatureAlgorithm{goidc.SigAlgES256},
			JWTLifetimeSecs:  60,
			DPoPNonceManager: orderedDPoPNonceManager{calls: &calls},
			ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
				calls = append(calls, "reserve")
				return goidc.ErrJTIReplay
			},
		},
		Request:  httptest.NewRequest(http.MethodPost, "/token", nil),
		Response: httptest.NewRecorder(),
	}

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
		TokenEndpoint: true,
		OnProofValidated: func() {
			calls = append(calls, "validated")
		},
	})
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.Code != goidc.ErrorCodeInvalidDPoPProof {
		t.Fatalf("ValidateJWT() error = %v, want invalid_dpop_proof", err)
	}
	want := []string{"nonce", "validated", "reserve"}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

type orderedDPoPNonceManager struct {
	calls *[]string
}

func (orderedDPoPNonceManager) IssueNonce(context.Context, goidc.DPoPNonceScope) (string, error) {
	return "fresh_nonce", nil
}

func (manager orderedDPoPNonceManager) ValidateNonce(
	context.Context,
	goidc.DPoPNonceScope,
	string,
) (goidc.DPoPNonceValidation, error) {
	*manager.calls = append(*manager.calls, "nonce")
	return goidc.DPoPNonceValidation{}, nil
}

func TestValidateJWTComparesCanonicalHTUUsingRFC9449RulesByDefault(t *testing.T) {
	tests := []struct {
		name        string
		proofURI    string
		requestPath string
		wantValid   bool
	}{
		{
			name:      "scheme host and default port use RFC normalization",
			proofURI:  "HTTPS://SERVER.EXAMPLE.COM:443/oauth2/token",
			wantValid: true,
		},
		{
			name:        "request query is excluded from the comparison",
			proofURI:    "https://server.example.com/oauth2/token",
			requestPath: "/oauth2/token?request=value",
			wantValid:   true,
		},
		{
			name:     "nonempty trailing path slash remains significant",
			proofURI: "https://server.example.com/oauth2/token/",
		},
		{
			name:      "proof htu query is excluded from the comparison",
			proofURI:  "https://server.example.com/oauth2/token?proof=value",
			wantValid: true,
		},
		{
			name:      "proof htu empty query is excluded from the comparison",
			proofURI:  "https://server.example.com/oauth2/token?",
			wantValid: true,
		},
		{
			name:      "proof htu fragment is excluded from the comparison",
			proofURI:  "https://server.example.com/oauth2/token#proof",
			wantValid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    test.proofURI,
			})
			requestPath := test.requestPath
			if requestPath == "" {
				requestPath = "/oauth2/token"
			}
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return nil
					},
				},
				Request: httptest.NewRequest(http.MethodPost, requestPath, nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			if test.wantValid && err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("ValidateJWT() error = nil, want invalid_dpop_proof")
			}
		})
	}
}

func TestValidateJWTComparesCanonicalHTUUsingStrictRulesWhenConfigured(t *testing.T) {
	tests := []struct {
		name        string
		proofURI    string
		requestPath string
		wantValid   bool
	}{
		{
			name:      "scheme host and default port use RFC normalization",
			proofURI:  "HTTPS://SERVER.EXAMPLE.COM:443/oauth2/token",
			wantValid: true,
		},
		{
			name:        "request query is excluded from the comparison",
			proofURI:    "https://server.example.com/oauth2/token",
			requestPath: "/oauth2/token?request=value",
			wantValid:   true,
		},
		{
			name:     "nonempty trailing path slash remains significant",
			proofURI: "https://server.example.com/oauth2/token/",
		},
		{
			name:     "proof htu query is forbidden",
			proofURI: "https://server.example.com/oauth2/token?proof=value",
		},
		{
			name:     "proof htu empty query is forbidden",
			proofURI: "https://server.example.com/oauth2/token?",
		},
		{
			name:     "proof htu fragment is forbidden",
			proofURI: "https://server.example.com/oauth2/token#proof",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    test.proofURI,
			})
			requestPath := test.requestPath
			if requestPath == "" {
				requestPath = "/oauth2/token"
			}
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPStrictHTU:   true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return nil
					},
				},
				Request: httptest.NewRequest(http.MethodPost, requestPath, nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			if test.wantValid && err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("ValidateJWT() error = nil, want invalid_dpop_proof")
			}
		})
	}
}

func TestValidateJWTTypedJTIConsumerErrors(t *testing.T) {
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method: http.MethodPost,
		URI:    "https://server.example.com/token",
	})
	for _, tc := range []struct {
		name     string
		consume  error
		wantCode goidc.ErrorCode
		wantDesc string
	}{
		{name: "invalid reservation", consume: goidc.ErrInvalidJTIUse, wantCode: goidc.ErrorCodeInvalidDPoPProof, wantDesc: "invalid DPoP proof"},
		{name: "replay", consume: goidc.ErrJTIReplay, wantCode: goidc.ErrorCodeInvalidDPoPProof, wantDesc: "invalid DPoP proof"},
		{name: "operational failure", consume: errors.New("sensitive store detail"), wantCode: goidc.ErrorCodeServerError, wantDesc: "server error"},
		{name: "nested protocol error is bounded", consume: goidc.NewError(goidc.ErrorCodeInvalidClient, "sensitive store detail"), wantCode: goidc.ErrorCodeServerError, wantDesc: "server error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return tc.consume
					},
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("error = %v, want goidc.Error", err)
			}
			if oidcErr.Code != tc.wantCode {
				t.Fatalf("error code = %q, want %q (error: %v)", oidcErr.Code, tc.wantCode, err)
			}
			if oidcErr.StatusCode() != tc.wantCode.StatusCode() {
				t.Fatalf("HTTP status = %d, want %d", oidcErr.StatusCode(), tc.wantCode.StatusCode())
			}
			if oidcErr.Description != tc.wantDesc {
				t.Fatalf("error description = %q, want %q", oidcErr.Description, tc.wantDesc)
			}
			if tc.wantCode == goidc.ErrorCodeServerError && strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("error leaked manager detail: %v", err)
			}
		})
	}
}

func TestValidateJWTRejectsProofAtReservationExpiryBoundary(t *testing.T) {
	const (
		lifetime = 60
		leeway   = 7
	)
	issuedAt := time.Now().UTC().Truncate(time.Second).Add(-(lifetime + leeway) * time.Second)
	proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
		Method:   http.MethodPost,
		URI:      "https://server.example.com/token",
		IssuedAt: issuedAt,
	})
	ctx := oidc.Context{
		Configuration: &oidc.Configuration{
			Host:              "https://server.example.com",
			DPoPEnabled:       true,
			DPoPSigAlgs:       []goidc.SignatureAlgorithm{goidc.SigAlgES256},
			JWTLifetimeSecs:   lifetime,
			JWTLeewayTimeSecs: leeway,
			ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
				t.Fatal("expired DPoP proof was reserved")
				return nil
			},
		},
		Request: httptest.NewRequest(http.MethodPost, "/token", nil),
	}

	err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
		NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
		TokenEndpoint: true,
	})
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidDPoPProof {
		t.Fatalf("error code = %q, want %q", oidcErr.Code, goidc.ErrorCodeInvalidDPoPProof)
	}
}

func TestValidateJWTRequiresIntegerIATAndBoundedUTF8JTI(t *testing.T) {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	validMaxJTI := strings.Repeat("é", 256)
	overlongJTI := strings.Repeat("a", 513)
	invalidUTF8Payload := []byte(`{"jti":"`)
	invalidUTF8Payload = append(invalidUTF8Payload, 0xff)
	invalidUTF8Payload = append(
		invalidUTF8Payload,
		[]byte(`","htm":"POST","htu":"https://server.example.com/token","iat":`+now+`}`)...,
	)

	tests := []struct {
		name      string
		payload   []byte
		wantValid bool
	}{
		{
			name:      "integer iat and 512 byte UTF-8 jti",
			payload:   dpopPayload(strconv.Quote(validMaxJTI), now),
			wantValid: true,
		},
		{
			name:    "fractional iat",
			payload: dpopPayload(strconv.Quote("jti"), now+".5"),
		},
		{
			name:    "iat above JSON safe integer",
			payload: dpopPayload(strconv.Quote("jti"), "9007199254740992"),
		},
		{
			name:    "513 byte jti",
			payload: dpopPayload(strconv.Quote(overlongJTI), now),
		},
		{
			name:    "escaped lone high surrogate jti",
			payload: dpopPayload(`"\ud800"`, now),
		},
		{
			name:    "escaped lone low surrogate jti",
			payload: dpopPayload(`"\udc00"`, now),
		},
		{
			name:      "escaped surrogate pair jti",
			payload:   dpopPayload(`"\ud83d\ude00"`, now),
			wantValid: true,
		},
		{
			name:    "invalid UTF-8 jti",
			payload: invalidUTF8Payload,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := signDPoPPayload(t, test.payload)
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return nil
					},
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			if test.wantValid {
				if err != nil {
					t.Fatalf("ValidateJWT() error = %v", err)
				}
				return
			}

			var oidcErr goidc.Error
			if !errors.As(err, &oidcErr) {
				t.Fatalf("error = %v, want goidc.Error", err)
			}
			if oidcErr.Code != goidc.ErrorCodeInvalidDPoPProof {
				t.Fatalf("error code = %q, want %q", oidcErr.Code, goidc.ErrorCodeInvalidDPoPProof)
			}
		})
	}
}

func TestValidateJWTUsesOnlyExactLowercaseClaimNames(t *testing.T) {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	validURI := "https://server.example.com/token"

	tests := []struct {
		name      string
		payload   string
		wantValid bool
	}{
		{
			name: "uppercase required claims do not satisfy the profile",
			payload: `{"JTI":"jti","HTM":"POST","HTU":"` + validURI +
				`","IAT":` + now + `}`,
		},
		{
			name: "uppercase aliases cannot overwrite valid lowercase claims",
			payload: `{"jti":"jti","htm":"POST","htu":"` + validURI + `","iat":` + now +
				`,"JTI":"","HTM":"GET","HTU":"https://attacker.example/","IAT":0}`,
			wantValid: true,
		},
		{
			name: "uppercase aliases cannot repair invalid lowercase claims",
			payload: `{"jti":"","htm":"GET","htu":"https://attacker.example/","iat":0,` +
				`"JTI":"jti","HTM":"POST","HTU":"` + validURI + `","IAT":` + now + `}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := signDPoPPayload(t, []byte(test.payload))
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:            "https://server.example.com",
					DPoPEnabled:     true,
					DPoPSigAlgs:     []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs: 60,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error {
						return nil
					},
				},
				Request: httptest.NewRequest(http.MethodPost, "/token", nil),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			if test.wantValid && err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("ValidateJWT() error = nil, want invalid DPoP proof")
			}
		})
	}
}

func TestValidateJWTUsesOnlyExactLowercaseATHAndNonce(t *testing.T) {
	now := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	const (
		accessToken = "access-token"
		validNonce  = "valid-nonce"
	)
	validATH := "Pxa-1wifRlPl7yG_0oJNfzqq7MelmOfonFgOFgapzFI"
	base := `"jti":"jti","htm":"POST","htu":"https://server.example.com/token","iat":` + now

	tests := []struct {
		name      string
		members   string
		wantValid bool
	}{
		{
			name:      "uppercase aliases cannot overwrite lowercase ath and nonce",
			members:   base + `,"ath":"` + validATH + `","nonce":"` + validNonce + `","ATH":"bad","NONCE":"bad"`,
			wantValid: true,
		},
		{
			name:    "uppercase aliases cannot repair lowercase ath and nonce",
			members: base + `,"ath":"bad","nonce":"bad","ATH":"` + validATH + `","NONCE":"` + validNonce + `"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := signDPoPPayload(t, []byte(`{`+test.members+`}`))
			manager := oidctest.NewDPoPNonceManager("challenge-nonce")
			manager.Add(goidc.DPoPNonceScopeAuthorizationServer, validNonce)
			ctx := oidc.Context{
				Configuration: &oidc.Configuration{
					Host:              "https://server.example.com",
					DPoPEnabled:       true,
					DPoPSigAlgs:       []goidc.SignatureAlgorithm{goidc.SigAlgES256},
					JWTLifetimeSecs:   60,
					DPoPNonceManager:  manager,
					ConsumeJTIUseFunc: func(context.Context, goidc.JTIUse) error { return nil },
				},
				Request:  httptest.NewRequest(http.MethodPost, "/token", nil),
				Response: httptest.NewRecorder(),
			}

			err := dpop.ValidateJWT(ctx, proof, dpop.ValidationOptions{
				AccessToken:   accessToken,
				NonceScope:    goidc.DPoPNonceScopeAuthorizationServer,
				TokenEndpoint: true,
			})
			if test.wantValid && err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("ValidateJWT() error = nil, want invalid DPoP proof")
			}
		})
	}
}

func dpopPayload(jtiJSON, issuedAtJSON string) []byte {
	return []byte(`{"jti":` + jtiJSON + `,"htm":"POST","htu":"https://server.example.com/token","iat":` + issuedAtJSON + `}`)
}

func signDPoPPayload(t *testing.T, payload []byte) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	jwk := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256)}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	proof, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() error = %v", err)
	}
	return proof
}

func TestJWKThumbprint(t *testing.T) {
	// Given.
	dpopSigningAlgorithms := []goidc.SignatureAlgorithm{goidc.SigAlgES256}
	testCases := []struct {
		dpopJWT  string
		expected string
	}{
		{
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("case %v", i),
			func(t *testing.T) {
				// When.
				got := dpop.JWKThumbprint(testCase.dpopJWT, dpopSigningAlgorithms)

				// Then.
				if got != testCase.expected {
					t.Errorf("JWKThumbprint() = %s, want %s", got, testCase.expected)
				}
			},
		)
	}
}

func TestJWT(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Set(goidc.HeaderDPoP, "dpop_jwt")

	// When.
	dpopJWT, ok := dpop.JWT(ctx)

	// Then.
	if !ok {
		t.Fatal("the dpop header should be valid")
	}

	if dpopJWT != "dpop_jwt" {
		t.Errorf("JWT() = %s, want dpop_jwt", dpopJWT)
	}
}

func TestJWT_NonCanonical(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Set("dpOp", "dpop_jwt")

	// When.
	dpopJWT, ok := dpop.JWT(ctx)

	// Then.
	if !ok {
		t.Fatal("the dpop header should be valid")
	}

	if dpopJWT != "dpop_jwt" {
		t.Errorf("JWT() = %s, want dpop_jwt", dpopJWT)
	}
}

func TestJWT_NoHeader(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}

	// When.
	_, ok := dpop.JWT(ctx)

	// Then.
	if ok {
		t.Fatal("the dpop header should not be valid")
	}
}

func TestJWT_MoreThanOneValue(t *testing.T) {

	// Given.
	ctx := oidc.Context{
		Request: &http.Request{Header: map[string][]string{}},
	}
	ctx.Request.Header.Add(goidc.HeaderDPoP, "dpop_jwt")
	ctx.Request.Header.Add("dpOp", "dpop_jwt")

	// When.
	_, ok := dpop.JWT(ctx)

	// Then.
	if ok {
		t.Fatal("the dpop header should not be valid")
	}
}
