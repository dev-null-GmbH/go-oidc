package goidc_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
)

func TestAuthnSessionPersistenceIDJSON(t *testing.T) {
	session := goidc.AuthnSession{
		ID:            "authn_session_id",
		PersistenceID: "authn_session_persistence_id",
	}

	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := payload["persistence_id"]; got != session.PersistenceID {
		t.Fatalf("persistence_id = %v, want %q", got, session.PersistenceID)
	}

	var decoded goidc.AuthnSession
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(AuthnSession) error = %v", err)
	}
	if decoded.PersistenceID != session.PersistenceID {
		t.Fatalf("decoded PersistenceID = %q, want %q", decoded.PersistenceID, session.PersistenceID)
	}

	emptyEncoded, err := json.Marshal(goidc.AuthnSession{ID: "authn_session_id"})
	if err != nil {
		t.Fatalf("json.Marshal(empty persistence ID) error = %v", err)
	}
	var emptyPayload map[string]any
	if err := json.Unmarshal(emptyEncoded, &emptyPayload); err != nil {
		t.Fatalf("json.Unmarshal(empty persistence ID) error = %v", err)
	}
	if _, ok := emptyPayload["persistence_id"]; ok {
		t.Fatal("persistence_id must be omitted when empty")
	}
}

func TestAuthnSessionClientAssertionAuthorityIsExcludedFromJSON(t *testing.T) {
	session := goidc.AuthnSession{
		ID: "authn_session_id",
		ClientAssertionAuthority: &goidc.VerifiedClientAssertionAuthority{
			SnapshotRevision: 71,
			KeyAuthorityID:   "019c8a03-696e-7a03-b08a-06dd73cb137d",
		},
	}

	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(encoded) == "" || json.Valid(encoded) == false {
		t.Fatalf("encoded session is invalid JSON: %s", encoded)
	}
	if bytes.Contains(encoded, []byte("client_assertion_authority")) ||
		bytes.Contains(encoded, []byte("019c8a03-696e-7a03-b08a-06dd73cb137d")) {
		t.Fatalf("session JSON exposes client assertion authority: %s", encoded)
	}

	var decoded goidc.AuthnSession
	if err := json.Unmarshal([]byte(`{
		"id":"authn_session_id",
		"client_assertion_authority":{"snapshot_revision":99,"key_authority_id":"injected-snake-case"},
		"ClientAssertionAuthority":{"SnapshotRevision":100,"KeyAuthorityID":"injected-go-name"}
	}`), &decoded); err != nil {
		t.Fatalf("json.Unmarshal(AuthnSession) error = %v", err)
	}
	if decoded.ClientAssertionAuthority != nil {
		t.Fatalf("client-controlled JSON populated authority evidence: %#v", decoded.ClientAssertionAuthority)
	}
}
