package goidc_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestPrivateKeyJWTAuthorityIsExcludedFromClientMetadataJSON(t *testing.T) {
	client := goidc.Client{
		ID: "client",
		PrivateKeyJWTAuthority: &goidc.PrivateKeyJWTAuthority{
			SnapshotRevision: 41,
			Keys: []goidc.PrivateKeyJWTAuthorityKey{{
				KeyAuthorityID: "server-authority-key",
			}},
		},
	}

	encoded, err := json.Marshal(client)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "server-authority-key") || strings.Contains(string(encoded), "SnapshotRevision") {
		t.Fatalf("client metadata contains server authority binding: %s", encoded)
	}

	var decoded goidc.Client
	if err := json.Unmarshal([]byte(`{
		"id":"client",
		"PrivateKeyJWTAuthority":{"SnapshotRevision":99},
		"private_key_jwt_authority":{"snapshot_revision":100}
	}`), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if decoded.PrivateKeyJWTAuthority != nil {
		t.Fatalf("client-controlled JSON populated authority binding: %#v", decoded.PrivateKeyJWTAuthority)
	}
}

func TestAuthorizationRequestProfileIsServerOnlyClientAuthority(t *testing.T) {
	client := goidc.Client{
		ID:                          "human-confidential-bff",
		AuthorizationRequestProfile: goidc.AuthorizationRequestProfileHumanConfidentialBFF,
	}

	encoded, err := json.Marshal(client)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), "human_confidential_bff") ||
		strings.Contains(string(encoded), "AuthorizationRequestProfile") {
		t.Fatalf("client metadata contains authorization admission authority: %s", encoded)
	}

	var decoded goidc.Client
	if err := json.Unmarshal([]byte(`{
		"id":"client",
		"AuthorizationRequestProfile":"human_confidential_bff",
		"authorization_request_profile":"human_confidential_bff"
	}`), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if decoded.AuthorizationRequestProfile != goidc.AuthorizationRequestProfileDefault {
		t.Fatalf("client-controlled JSON populated authorization request profile: %q", decoded.AuthorizationRequestProfile)
	}
}
