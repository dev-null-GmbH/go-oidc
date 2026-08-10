package goidc_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestTokenEndpointEvidenceContractIsClosed(t *testing.T) {
	t.Parallel()

	results := []goidc.TokenEndpointResult{
		goidc.TokenEndpointResultIssued,
		goidc.TokenEndpointResultInvalidRequest,
		goidc.TokenEndpointResultInvalidClient,
		goidc.TokenEndpointResultUnauthorizedClient,
		goidc.TokenEndpointResultInvalidScope,
		goidc.TokenEndpointResultInvalidTarget,
		goidc.TokenEndpointResultInvalidDPoPProof,
		goidc.TokenEndpointResultUseDPoPNonce,
		goidc.TokenEndpointResultServerError,
		goidc.TokenEndpointResultProtocolDenied,
	}
	for index, result := range results {
		if want := goidc.TokenEndpointResult(index + 1); result != want {
			t.Fatalf("result[%d] = %d, want %d", index, result, want)
		}
	}

	typeOfEvidence := reflect.TypeOf(goidc.TokenEndpointEvidence{})
	if typeOfEvidence.NumField() != 2 {
		t.Fatalf("TokenEndpointEvidence fields = %d, want exactly 2", typeOfEvidence.NumField())
	}
	wantFields := []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "Result", typeOf: reflect.TypeOf(goidc.TokenEndpointResult(0))},
		{name: "AuthenticatedClientID", typeOf: reflect.TypeOf("")},
	}
	for index, want := range wantFields {
		field := typeOfEvidence.Field(index)
		if field.Name != want.name || field.Type != want.typeOf {
			t.Fatalf("field[%d] = (%s, %v), want (%s, %v)", index, field.Name, field.Type, want.name, want.typeOf)
		}
	}

	var callback goidc.TokenEndpointEvidenceFunc = func(context.Context, goidc.TokenEndpointEvidence) {}
	if callback == nil {
		t.Fatal("TokenEndpointEvidenceFunc unexpectedly nil")
	}
}
