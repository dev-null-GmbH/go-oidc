package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dev-null-GmbH/go-oidc/internal/client"
	"github.com/dev-null-GmbH/go-oidc/internal/oidc"
	"github.com/dev-null-GmbH/go-oidc/internal/oidctest"
	"github.com/dev-null-GmbH/go-oidc/internal/timeutil"
	"github.com/dev-null-GmbH/go-oidc/internal/token"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
)

func TestPrivateKeyJWTAssertionPolicyRunsBeforeJTIConsumption(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	ctx.JWTLeewayTimeSecs = 7
	now := timeutil.TimestampNow()
	expiresAt := now + ctx.JWTLifetimeSecs - 10
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   expiresAt,
		goidc.ClaimTokenID:  "assertion-id",
		"custom":            "value",
	}
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {
			oidctest.SignWithOptions(t, claims, jwk, (&jose.SignerOptions{}).WithType("JWT")),
		},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	var calls []string
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, assertion goidc.VerifiedClientAssertion) error {
		calls = append(calls, "policy")
		if assertion.Authority != nil {
			t.Errorf("legacy JWKS assertion authority = %#v, want nil", assertion.Authority)
		}
		if assertion.AuthenticatedClientID != c.ID {
			t.Errorf("policy authenticated client ID = %q, want %q", assertion.AuthenticatedClientID, c.ID)
		}
		if assertion.Header.Algorithm != goidc.SigAlgRS256 {
			t.Errorf("policy header algorithm = %q, want %q", assertion.Header.Algorithm, goidc.SigAlgRS256)
		}
		if assertion.Header.KeyID != jwk.KeyID {
			t.Errorf("policy header kid = %q, want %q", assertion.Header.KeyID, jwk.KeyID)
		}
		if assertion.Header.Type != "JWT" {
			t.Errorf("policy header typ = %q, want JWT", assertion.Header.Type)
		}
		var gotClaims map[string]json.RawMessage
		if err := json.Unmarshal(assertion.Claims, &gotClaims); err != nil {
			t.Fatalf("unmarshal verified claims: %v", err)
		}
		if string(gotClaims["custom"]) != `"value"` {
			t.Errorf("policy custom claim = %s, want %q", gotClaims["custom"], "value")
		}
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		calls = append(calls, "consume")
		if use.ID != "assertion-id" {
			t.Errorf("JTI ID = %q, want assertion-id", use.ID)
		}
		if use.Issuer != c.ID {
			t.Errorf("JTI issuer = %q, want %q", use.Issuer, c.ID)
		}
		if use.Purpose != goidc.JTIUsePurposeClientAssertion {
			t.Errorf("JTI purpose = %q, want %q", use.Purpose, goidc.JTIUsePurposeClientAssertion)
		}
		wantExpiry := time.Unix(int64(expiresAt+ctx.JWTLeewayTimeSecs), 0).UTC()
		if !use.ExpiresAt.Equal(wantExpiry) {
			t.Errorf("JTI expiry = %v, want %v", use.ExpiresAt, wantExpiry)
		}
		return nil
	}

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	if want := []string{"policy", "consume"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestPrivateKeyJWTAssertionPolicyReceivesMatchedAuthorityBinding(t *testing.T) {
	ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
	legacyKey := oidctest.PrivateRS256JWK(t, signingKey.KeyID, goidc.KeyUsageSignature)
	decoyKey := oidctest.PrivateRS256JWK(t, "decoy-key", goidc.KeyUsageSignature)
	c.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{legacyKey.Public()}}
	c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
		SnapshotRevision: 23,
		Keys: []goidc.PrivateKeyJWTAuthorityKey{
			{
				Key:            decoyKey.Public(),
				KeyAuthorityID: "019c84de-89a7-7c86-840c-03670c737ee4",
			},
			{
				Key:            signingKey.Public(),
				KeyAuthorityID: "019c84de-c2d7-7d3b-9d90-b7ab9555112d",
			},
		},
	}

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
		goidc.ClaimTokenID:  "assertion-id",
		"snapshot_revision": 999,
		"key_authority_id":  "attacker-controlled-claim",
	}
	assertion := oidctest.SignWithOptions(t, claims, signingKey,
		(&jose.SignerOptions{}).
			WithHeader("snapshot_revision", 998).
			WithHeader("key_authority_id", "attacker-controlled-header"))
	ctx.Request.PostForm = map[string][]string{
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}

	ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, verified goidc.VerifiedClientAssertion) error {
		// Mutating the resolver-owned value after verification must not alter the
		// authority binding captured for this callback.
		c.PrivateKeyJWTAuthority.SnapshotRevision = 999
		c.PrivateKeyJWTAuthority.Keys[1].KeyAuthorityID = "mutated-after-verification"

		if verified.Authority == nil {
			t.Fatal("verified authority binding is nil")
		}
		if verified.Authority.SnapshotRevision != 23 {
			t.Errorf("authority snapshot revision = %d, want 23", verified.Authority.SnapshotRevision)
		}
		if verified.Authority.KeyAuthorityID != "019c84de-c2d7-7d3b-9d90-b7ab9555112d" {
			t.Errorf("authority key ID = %q, want resolver-owned key ID", verified.Authority.KeyAuthorityID)
		}
		if verified.Header.KeyID != signingKey.KeyID {
			t.Errorf("untrusted header kid = %q, want %q", verified.Header.KeyID, signingKey.KeyID)
		}
		return nil
	}

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
}

func TestPrivateKeyJWTAuthorityRejectsRotatedKeyWithReusedHeaderKeyID(t *testing.T) {
	ctx, c, rotatedKey := setUpPrivateKeyJWTAuthn(t)
	currentKey := oidctest.PrivateRS256JWK(t, rotatedKey.KeyID, goidc.KeyUsageSignature)
	c.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{rotatedKey.Public()}}
	c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
		SnapshotRevision: 24,
		Keys: []goidc.PrivateKeyJWTAuthorityKey{
			{
				Key:            currentKey.Public(),
				KeyAuthorityID: "019c84de-e9c2-7f87-9a41-a55ccf602edb",
			},
		},
	}
	ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, rotatedKey)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		t.Fatal("assertion signed by a rotated key reached policy")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("assertion signed by a rotated key consumed a JTI")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAuthorityEmptyKeySetDoesNotFallBackToLegacyJWKS(t *testing.T) {
	ctx, c, revokedKey := setUpPrivateKeyJWTAuthn(t)
	c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 25}
	ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, revokedKey)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		t.Fatal("assertion signed by a revoked key reached policy")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("assertion signed by a revoked key consumed a JTI")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAuthorityRejectsInvalidOrAmbiguousSnapshot(t *testing.T) {
	tests := []struct {
		name      string
		authority func(*testing.T, goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority
	}{
		{
			name: "zero snapshot revision",
			authority: func(_ *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				return &goidc.PrivateKeyJWTAuthority{Keys: []goidc.PrivateKeyJWTAuthorityKey{{
					Key: key.Public(), KeyAuthorityID: "authority-key",
				}}}
			},
		},
		{
			name: "empty authority key id",
			authority: func(_ *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{{
					Key: key.Public(),
				}}}
			},
		},
		{
			name: "empty JOSE key id",
			authority: func(_ *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				key.KeyID = ""
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{{
					Key: key.Public(), KeyAuthorityID: "authority-key",
				}}}
			},
		},
		{
			name: "unused private key material",
			authority: func(t *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				privateKey := oidctest.PrivateRS256JWK(t, "unused-private", goidc.KeyUsageSignature)
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: key.Public(), KeyAuthorityID: "authority-key"},
					{Key: privateKey, KeyAuthorityID: "private-authority-key"},
				}}
			},
		},
		{
			name: "unused symmetric key material",
			authority: func(_ *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: key.Public(), KeyAuthorityID: "authority-key"},
					{Key: goidc.JSONWebKey{
						Key: []byte("not-an-asymmetric-public-key"), KeyID: "unused-symmetric",
						Algorithm: string(goidc.SigAlgHS256), Use: string(goidc.KeyUsageSignature),
					}, KeyAuthorityID: "symmetric-authority-key"},
				}}
			},
		},
		{
			name: "duplicate authority key id",
			authority: func(t *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				other := oidctest.PrivateRS256JWK(t, "other-key", goidc.KeyUsageSignature)
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: key.Public(), KeyAuthorityID: "duplicate-authority-key"},
					{Key: other.Public(), KeyAuthorityID: "duplicate-authority-key"},
				}}
			},
		},
		{
			name: "duplicate header key id",
			authority: func(t *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				other := oidctest.PrivateRS256JWK(t, key.KeyID, goidc.KeyUsageSignature)
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: key.Public(), KeyAuthorityID: "authority-key"},
					{Key: other.Public(), KeyAuthorityID: "other-authority-key"},
				}}
			},
		},
		{
			name: "duplicate public key material under distinct identities",
			authority: func(_ *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				first := key.Public()
				second := key.Public()
				second.KeyID = "same-material-other-kid"
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: first, KeyAuthorityID: "first-authority-key"},
					{Key: second, KeyAuthorityID: "second-authority-key"},
				}}
			},
		},
		{
			name: "public key thumbprint failure",
			authority: func(t *testing.T, key goidc.JSONWebKey) *goidc.PrivateKeyJWTAuthority {
				unsupportedKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
				if err != nil {
					t.Fatalf("generate unsupported thumbprint key: %v", err)
				}
				return &goidc.PrivateKeyJWTAuthority{SnapshotRevision: 1, Keys: []goidc.PrivateKeyJWTAuthorityKey{
					{Key: key.Public(), KeyAuthorityID: "authority-key"},
					{Key: goidc.JSONWebKey{
						Key:   unsupportedKey.Public(),
						KeyID: "unsupported-thumbprint-key", Algorithm: string(goidc.SigAlgRS256),
						Use: string(goidc.KeyUsageSignature),
					}, KeyAuthorityID: "unsupported-thumbprint-authority-key"},
				}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
			c.PrivateKeyJWTAuthority = test.authority(t, signingKey)
			ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, signingKey)
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
				t.Fatal("invalid authority snapshot reached policy")
				return nil
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
				t.Fatal("invalid authority snapshot consumed a JTI")
				return nil
			}

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
		})
	}
}

func TestPrivateKeyJWTAuthorityRejectsKidlessAlgorithmAmbiguity(t *testing.T) {
	ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
	signingKey.KeyID = ""
	firstAuthorityKey := signingKey.Public()
	firstAuthorityKey.KeyID = "first-key"
	otherKey := oidctest.PrivateRS256JWK(t, "second-key", goidc.KeyUsageSignature)
	c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
		SnapshotRevision: 27,
		Keys: []goidc.PrivateKeyJWTAuthorityKey{
			{Key: firstAuthorityKey, KeyAuthorityID: "first-authority-key"},
			{Key: otherKey.Public(), KeyAuthorityID: "second-authority-key"},
		},
	}
	ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, signingKey)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		t.Fatal("kid-less ambiguous assertion reached policy")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("kid-less ambiguous assertion consumed a JTI")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAssertionPolicyCanRejectStaleAuthorityRevision(t *testing.T) {
	ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
	c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
		SnapshotRevision: 26,
		Keys: []goidc.PrivateKeyJWTAuthorityKey{{
			Key: signingKey.Public(), KeyAuthorityID: "019c84df-b88b-77f3-a99c-1d609062636d",
		}},
	}
	ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, signingKey)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, verified goidc.VerifiedClientAssertion) error {
		if verified.Authority == nil || verified.Authority.SnapshotRevision != 26 {
			t.Fatalf("verified authority = %#v, want stale revision 26", verified.Authority)
		}
		return errors.New("client authority snapshot is stale")
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("stale authority snapshot consumed a JTI")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAuthorityPARStateIsRecordedOnlyAfterCompleteAuthentication(t *testing.T) {
	tests := []struct {
		name             string
		configure        func(*testing.T, oidc.Context, *goidc.Client, goidc.JSONWebKey)
		policyError      error
		consumeError     error
		wantSuccess      bool
		wantPolicyCalls  int
		wantConsumeCalls int
	}{
		{
			name:             "success",
			wantSuccess:      true,
			wantPolicyCalls:  1,
			wantConsumeCalls: 1,
		},
		{
			name: "invalid signature",
			configure: func(t *testing.T, ctx oidc.Context, c *goidc.Client, signingKey goidc.JSONWebKey) {
				untrusted := oidctest.PrivateRS256JWK(t, signingKey.KeyID, goidc.KeyUsageSignature)
				ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, untrusted)
			},
		},
		{
			name:             "deployment policy rejection",
			policyError:      errors.New("policy rejected assertion"),
			wantPolicyCalls:  1,
			wantConsumeCalls: 0,
		},
		{
			name:             "JTI replay",
			consumeError:     goidc.ErrJTIReplay,
			wantPolicyCalls:  1,
			wantConsumeCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
			ctx = ctx.BeginPARClientAuthentication()
			c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
				SnapshotRevision: 91,
				Keys: []goidc.PrivateKeyJWTAuthorityKey{{
					Key: signingKey.Public(), KeyAuthorityID: "019c8a0a-63f6-7bf0-8c0d-f6b2f24d984a",
				}},
			}
			ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, signingKey)
			if test.configure != nil {
				test.configure(t, ctx, c, signingKey)
			}

			var policyCalls, consumeCalls int
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
				policyCalls++
				return test.policyError
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
				consumeCalls++
				return test.consumeError
			}

			err := client.Authenticate(ctx, c, client.AuthnContextPAR)
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("Authenticate() error = %v", err)
				}
				authority, authorityErr := ctx.PARClientAssertionAuthority(c)
				if authorityErr != nil {
					t.Fatalf("PARClientAssertionAuthority() error = %v", authorityErr)
				}
				if authority == nil || authority.SnapshotRevision != 91 ||
					authority.KeyAuthorityID != "019c8a0a-63f6-7bf0-8c0d-f6b2f24d984a" {
					t.Fatalf("captured authority = %#v, want exact verified authority", authority)
				}
			} else {
				if err == nil {
					t.Fatal("Authenticate() error = nil")
				}
				authority, authorityErr := ctx.PARClientAssertionAuthority(c)
				if authorityErr == nil || authority != nil {
					t.Fatalf("authority after failed authentication = %#v, error = %v; want absent failure", authority, authorityErr)
				}
			}
			if policyCalls != test.wantPolicyCalls || consumeCalls != test.wantConsumeCalls {
				t.Fatalf("policy/consume calls = %d/%d, want %d/%d",
					policyCalls, consumeCalls, test.wantPolicyCalls, test.wantConsumeCalls)
			}
		})
	}
}

func TestPrivateKeyJWTAuthorityPARStateDoesNotAliasPolicyEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*goidc.VerifiedClientAssertionAuthority, *goidc.VerifiedClientAssertionAuthority)
	}{
		{
			name: "immediate policy mutation",
			mutate: func(authority *goidc.VerifiedClientAssertionAuthority, _ *goidc.VerifiedClientAssertionAuthority) {
				authority.SnapshotRevision = 999
				authority.KeyAuthorityID = "policy-substituted-key"
			},
		},
		{
			name: "retained policy pointer mutation",
			mutate: func(_ *goidc.VerifiedClientAssertionAuthority, retained *goidc.VerifiedClientAssertionAuthority) {
				retained.SnapshotRevision = 998
				retained.KeyAuthorityID = "retained-policy-substituted-key"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, signingKey := setUpPrivateKeyJWTAuthn(t)
			ctx = ctx.BeginPARClientAuthentication()
			c.PrivateKeyJWTAuthority = &goidc.PrivateKeyJWTAuthority{
				SnapshotRevision: 92,
				Keys: []goidc.PrivateKeyJWTAuthorityKey{{
					Key: signingKey.Public(), KeyAuthorityID: "019c8a0b-e4b3-72d9-862d-fec7d9730e67",
				}},
			}
			ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, signingKey)

			var retained *goidc.VerifiedClientAssertionAuthority
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(_ context.Context, assertion goidc.VerifiedClientAssertion) error {
				retained = assertion.Authority
				if retained == nil {
					t.Fatal("policy authority = nil")
				}
				if test.name == "immediate policy mutation" {
					test.mutate(assertion.Authority, retained)
				}
				return nil
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
				if test.name == "retained policy pointer mutation" {
					test.mutate(nil, retained)
				}
				return nil
			}

			if err := client.Authenticate(ctx, c, client.AuthnContextPAR); err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			authority, err := ctx.PARClientAssertionAuthority(c)
			if err != nil {
				t.Fatalf("PARClientAssertionAuthority() error = %v", err)
			}
			if authority == nil || authority.SnapshotRevision != 92 ||
				authority.KeyAuthorityID != "019c8a0b-e4b3-72d9-862d-fec7d9730e67" {
				t.Fatalf("captured authority = %#v, want exact verified authority", authority)
			}
		})
	}
}

func TestNonPrivateKeyJWTAuthenticationLeavesFreshPARAuthorityStateAbsent(t *testing.T) {
	ctx, _, _ := setUpPrivateKeyJWTAuthn(t)
	ctx = ctx.BeginPARClientAuthentication()
	secretClient := &goidc.Client{
		ID:     "secret-client",
		Secret: "secret",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretPost,
		},
	}
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {secretClient.ID},
		"client_secret": {secretClient.Secret},
	}
	if err := client.Authenticate(ctx, secretClient, client.AuthnContextPAR); err != nil {
		t.Fatalf("client_secret_post Authenticate() error = %v", err)
	}
	authority, err := ctx.PARClientAssertionAuthority(secretClient)
	if err != nil {
		t.Fatalf("PARClientAssertionAuthority() error = %v", err)
	}
	if authority != nil {
		t.Fatalf("non-private_key_jwt authority = %#v, want nil", authority)
	}
}

func TestPrivateKeyJWTAssertionPolicyRejectsBeforeJTIConsumption(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		return errors.New("assertion violates deployment policy")
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called after assertion policy rejection")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestPrivateKeyJWTAssertionPolicyPreservesOperationalFailure(t *testing.T) {
	for _, code := range []goidc.ErrorCode{goidc.ErrorCodeServerError, goidc.ErrorCodeInternalError} {
		t.Run(string(code), func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			now := timeutil.TimestampNow()
			ctx.Request.PostForm = map[string][]string{
				"client_assertion": {oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "assertion-id",
				}, jwk)},
				"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
			}
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
				return goidc.WrapError(code, "server error", errors.New("policy store unavailable"))
			}

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, code)
		})
	}
}

func TestPrivateKeyJWTAssertionPolicyPanicFailsClosedBeforeJTIConsumption(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, jwk)
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		panic("policy panic canary")
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called after assertion policy panic")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeServerError)
}

func TestPrivateKeyJWTAssertionPolicyCancellationFailsClosedBeforeJTIConsumption(t *testing.T) {
	for _, tc := range []struct {
		name               string
		cancelBeforePolicy bool
	}{
		{name: "before policy", cancelBeforePolicy: true},
		{name: "during policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			requestContext, cancel := context.WithCancel(ctx.Request.Context())
			ctx.Request = ctx.Request.WithContext(requestContext)
			ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, jwk)
			if tc.cancelBeforePolicy {
				cancel()
			}
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(callbackContext context.Context, _ goidc.VerifiedClientAssertion) error {
				if tc.cancelBeforePolicy {
					t.Fatal("assertion policy called after request cancellation")
				}
				cancel()
				return callbackContext.Err()
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
				t.Fatal("JTI consumer called after request cancellation")
				return nil
			}

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, goidc.ErrorCodeServerError)
		})
	}
}

func TestTypedJTIConsumerDistinguishesReplayFromOperationalFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		consume  error
		wantCode goidc.ErrorCode
	}{
		{name: "replay", consume: goidc.ErrJTIReplay, wantCode: goidc.ErrorCodeInvalidClient},
		{name: "operational failure", consume: errors.New("store unavailable"), wantCode: goidc.ErrorCodeServerError},
		{name: "not found is operational", consume: goidc.ErrNotFound, wantCode: goidc.ErrorCodeServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			now := timeutil.TimestampNow()
			ctx.Request.PostForm = map[string][]string{
				"client_assertion": {oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "assertion-id",
				}, jwk)},
				"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error { return tc.consume }

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, tc.wantCode)
		})
	}
}

func TestInvalidPrivateKeyJWTClaimsAreNotConsumed(t *testing.T) {
	ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: "https://wrong.example",
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		t.Fatal("assertion policy called before standard claims validation")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called before claims validation")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestInvalidPrivateKeyJWTSignatureDoesNotReachPolicyOrJTIConsumption(t *testing.T) {
	ctx, c, trustedJWK := setUpPrivateKeyJWTAuthn(t)
	now := timeutil.TimestampNow()
	untrustedJWK := oidctest.PrivateRS256JWK(t, trustedJWK.KeyID, goidc.KeyUsageSignature)
	ctx.Request.PostForm = map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, untrustedJWK)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
	ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
		t.Fatal("assertion policy called before signature verification")
		return nil
	}
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error {
		t.Fatal("JTI consumer called before signature verification")
		return nil
	}

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
}

func TestTokenEndpointEvidenceAttributesPrivateKeyJWTReplayAfterPolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		consume  error
		wantCode goidc.ErrorCode
	}{
		{name: "replay", consume: goidc.ErrJTIReplay, wantCode: goidc.ErrorCodeInvalidClient},
		{name: "storage failure", consume: errors.New("replay store unavailable"), wantCode: goidc.ErrorCodeServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, jwk)
			ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
				return nil
			}
			ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error { return test.consume }
			var got goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
				got = evidence
			}
			ctx = ctx.BeginTokenEndpointEvidence()

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, test.wantCode)
			ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultInvalidClient)

			want := goidc.TokenEndpointEvidence{
				Result:                goidc.TokenEndpointResultInvalidClient,
				AuthenticatedClientID: c.ID,
			}
			if got != want {
				t.Fatalf("evidence = %#v, want %#v", got, want)
			}
		})
	}
}

func TestTokenEndpointEvidenceDoesNotAttributeUnverifiedPrivateKeyJWT(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, oidc.Context, *goidc.Client, goidc.JSONWebKey)
	}{
		{
			name: "signature failure",
			setup: func(t *testing.T, ctx oidc.Context, c *goidc.Client, trustedJWK goidc.JSONWebKey) {
				t.Helper()
				untrustedJWK := oidctest.PrivateRS256JWK(t, trustedJWK.KeyID, goidc.KeyUsageSignature)
				now := timeutil.TimestampNow()
				ctx.Request.PostForm = map[string][]string{
					"client_assertion": {oidctest.Sign(t, map[string]any{
						goidc.ClaimIssuer:   c.ID,
						goidc.ClaimSubject:  c.ID,
						goidc.ClaimAudience: ctx.Issuer(),
						goidc.ClaimIssuedAt: now,
						goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
						goidc.ClaimTokenID:  "assertion-id",
					}, untrustedJWK)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
			},
		},
		{
			name: "assertion policy denial",
			setup: func(t *testing.T, ctx oidc.Context, c *goidc.Client, jwk goidc.JSONWebKey) {
				t.Helper()
				ctx.Request.PostForm = validPrivateKeyJWTPolicyPostForm(t, ctx, c, jwk)
				ctx.PrivateKeyJWTAssertionPolicyFunc = func(context.Context, goidc.VerifiedClientAssertion) error {
					return errors.New("policy denied")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
			test.setup(t, ctx, c, jwk)
			var got goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
				got = evidence
			}
			ctx = ctx.BeginTokenEndpointEvidence()

			_, err := client.Authenticated(ctx, client.AuthnContextToken)
			assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
			ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultInvalidClient)

			want := goidc.TokenEndpointEvidence{Result: goidc.TokenEndpointResultInvalidClient}
			if got != want {
				t.Fatalf("evidence = %#v, want %#v", got, want)
			}
		})
	}
}

func TestSecretJWTConsumesTypedJTI(t *testing.T) {
	ctx, c, secret := setUpClientSecretJWTAuthn(t)
	ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "secret-assertion-id")
	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	if got.ID != "secret-assertion-id" {
		t.Errorf("JTI ID = %q, want secret-assertion-id", got.ID)
	}
	if got.Issuer != c.ID {
		t.Errorf("JTI issuer = %q, want %q", got.Issuer, c.ID)
	}
	if got.Purpose != goidc.JTIUsePurposeClientAssertion {
		t.Errorf("JTI purpose = %q, want %q", got.Purpose, goidc.JTIUsePurposeClientAssertion)
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Errorf("JTI expiry = %v, want a future time", got.ExpiresAt)
	}
}

func TestTokenEndpointEvidenceAttributesSecretJWTReplayAfterVerification(t *testing.T) {
	ctx, c, secret := setUpClientSecretJWTAuthn(t)
	ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "secret-assertion-id")
	ctx.ConsumeJTIUseFunc = func(context.Context, goidc.JTIUse) error { return goidc.ErrJTIReplay }
	var got goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = evidence
	}
	ctx = ctx.BeginTokenEndpointEvidence()

	_, err := client.Authenticated(ctx, client.AuthnContextToken)
	assertErrorCode(t, err, goidc.ErrorCodeInvalidClient)
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultInvalidClient)

	want := goidc.TokenEndpointEvidence{
		Result:                goidc.TokenEndpointResultInvalidClient,
		AuthenticatedClientID: c.ID,
	}
	if got != want {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestTokenEndpointEvidenceDefersAttestationDPoPAttributionUntilProofValidation(t *testing.T) {
	for _, test := range []struct {
		name         string
		corruptProof bool
		wantResult   goidc.TokenEndpointResult
		wantClientID bool
	}{
		{
			name:         "valid proof is attributed",
			wantResult:   goidc.TokenEndpointResultIssued,
			wantClientID: true,
		},
		{
			name:         "invalid signature is not attributed",
			corruptProof: true,
			wantResult:   goidc.TokenEndpointResultInvalidDPoPProof,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
			ctx.DPoPEnabled = true
			ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.SigAlgES256}
			ctx.Request.Method = http.MethodPost
			ctx.Request.RequestURI = ctx.TokenEndpoint

			cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.SigAlgES256)}
			attestation := oidctest.SignWithOptions(t, map[string]any{
				goidc.ClaimIssuer:  "https://attester.example.com",
				goidc.ClaimSubject: c.ID,
				goidc.ClaimExpiry:  timeutil.TimestampNow() + 300,
				"cnf":              map[string]any{"jwk": cnfJWK},
			}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
			ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

			proof, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
				Method: http.MethodPost,
				URI:    ctx.Host + ctx.TokenEndpoint,
				Key:    clientKey,
			})
			if test.corruptProof {
				parts := strings.Split(proof, ".")
				if len(parts) != 3 || len(parts[2]) == 0 {
					t.Fatalf("DPoP proof = %q, want compact JWS", proof)
				}
				signature := []byte(parts[2])
				if signature[0] == 'A' {
					signature[0] = 'B'
				} else {
					signature[0] = 'A'
				}
				parts[2] = string(signature)
				proof = strings.Join(parts, ".")
			}
			ctx.Request.Header.Set(goidc.HeaderDPoP, proof)

			var got goidc.TokenEndpointEvidence
			ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
				got = evidence
			}
			ctx = ctx.BeginTokenEndpointEvidence()

			authenticated, err := client.Authenticated(ctx, client.AuthnContextToken)
			if err != nil {
				t.Fatalf("Authenticated() error = %v", err)
			}
			err = token.ValidateBinding(ctx, authenticated, nil)
			if test.corruptProof {
				assertErrorCode(t, err, goidc.ErrorCodeInvalidDPoPProof)
			} else if err != nil {
				t.Fatalf("ValidateBinding() error = %v", err)
			}
			ctx.EmitTokenEndpointEvidence(test.wantResult)

			wantClientID := ""
			if test.wantClientID {
				wantClientID = c.ID
			}
			want := goidc.TokenEndpointEvidence{
				Result:                test.wantResult,
				AuthenticatedClientID: wantClientID,
			}
			if got != want {
				t.Fatalf("evidence = %#v, want %#v", got, want)
			}
		})
	}
}

func TestTokenEndpointEvidenceDoesNotAttributeUnauthenticatedClient(t *testing.T) {
	ctx := oidctest.NewContext(t)
	c := &goidc.Client{
		ID: "public-client",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodNone,
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)
	ctx.Request.PostForm = map[string][]string{"client_id": {c.ID}}
	var got goidc.TokenEndpointEvidence
	ctx.TokenEndpointEvidenceFunc = func(_ context.Context, evidence goidc.TokenEndpointEvidence) {
		got = evidence
	}
	ctx = ctx.BeginTokenEndpointEvidence()

	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	ctx.EmitTokenEndpointEvidence(goidc.TokenEndpointResultProtocolDenied)

	want := goidc.TokenEndpointEvidence{Result: goidc.TokenEndpointResultProtocolDenied}
	if got != want {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestAttestationPoPConsumesTypedJTI(t *testing.T) {
	ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
	cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.SigAlgES256)}
	clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.SigAlgES256)}
	attestation := oidctest.SignWithOptions(t, map[string]any{
		goidc.ClaimIssuer:  "https://attester.example.com",
		goidc.ClaimSubject: c.ID,
		goidc.ClaimExpiry:  timeutil.TimestampNow() + 300,
		"cnf":              map[string]any{"jwk": cnfJWK},
	}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
	ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

	expiresAt := timeutil.TimestampNow() + 60
	pop := oidctest.SignWithOptions(t, map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimExpiry:   expiresAt,
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimTokenID:  "attestation-pop-id",
	}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
	ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)

	var got goidc.JTIUse
	ctx.ConsumeJTIUseFunc = func(_ context.Context, use goidc.JTIUse) error {
		got = use
		return nil
	}
	if _, err := client.Authenticated(ctx, client.AuthnContextToken); err != nil {
		t.Fatalf("Authenticated() error = %v", err)
	}
	wantExpiry := time.Unix(int64(expiresAt+ctx.JWTLeewayTimeSecs), 0).UTC()
	if got.ID != "attestation-pop-id" || got.Issuer != c.ID || got.Purpose != goidc.JTIUsePurposeClientAttestationPoP {
		t.Fatalf("JTI use = %#v, want attestation PoP reservation", got)
	}
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("JTI expiry = %v, want %v", got.ExpiresAt, wantExpiry)
	}
}

func assertErrorCode(t *testing.T, err error, want goidc.ErrorCode) {
	t.Helper()
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error = %v, want goidc.Error", err)
	}
	if oidcErr.Code != want {
		t.Fatalf("error code = %q, want %q (error: %v)", oidcErr.Code, want, err)
	}
	if oidcErr.StatusCode() != want.StatusCode() {
		t.Fatalf("HTTP status = %d, want %d", oidcErr.StatusCode(), want.StatusCode())
	}
}

func validPrivateKeyJWTPolicyPostForm(
	t *testing.T,
	ctx oidc.Context,
	c *goidc.Client,
	jwk goidc.JSONWebKey,
) map[string][]string {
	t.Helper()
	now := timeutil.TimestampNow()
	return map[string][]string{
		"client_assertion": {oidctest.Sign(t, map[string]any{
			goidc.ClaimIssuer:   c.ID,
			goidc.ClaimSubject:  c.ID,
			goidc.ClaimAudience: ctx.Issuer(),
			goidc.ClaimIssuedAt: now,
			goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
			goidc.ClaimTokenID:  "assertion-id",
		}, jwk)},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
}
