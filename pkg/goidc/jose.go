package goidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type SignatureAlgorithm = jose.SignatureAlgorithm

const (
	SigAlgNone  SignatureAlgorithm = "none"
	SigAlgHS256 SignatureAlgorithm = jose.HS256
	SigAlgHS384 SignatureAlgorithm = jose.HS384
	SigAlgHS512 SignatureAlgorithm = jose.HS512
	SigAlgRS256 SignatureAlgorithm = jose.RS256
	SigAlgRS384 SignatureAlgorithm = jose.RS384
	SigAlgRS512 SignatureAlgorithm = jose.RS512
	SigAlgES256 SignatureAlgorithm = jose.ES256
	SigAlgES384 SignatureAlgorithm = jose.ES384
	SigAlgES512 SignatureAlgorithm = jose.ES512
	SigAlgPS256 SignatureAlgorithm = jose.PS256
	SigAlgPS384 SignatureAlgorithm = jose.PS384
	SigAlgPS512 SignatureAlgorithm = jose.PS512
)

type KeyEncryptionAlgorithm = jose.KeyAlgorithm

const (
	KeyEncAlgRSA15   KeyEncryptionAlgorithm = jose.RSA1_5
	KeyEncRSAOAEP    KeyEncryptionAlgorithm = jose.RSA_OAEP
	KeyEncRSAOAEP256 KeyEncryptionAlgorithm = jose.RSA_OAEP_256
)

type ContentEncryptionAlgorithm = jose.ContentEncryption

const (
	ContentEncAlgA128CBCHS256 ContentEncryptionAlgorithm = jose.A128CBC_HS256
	ContentEncAlgA192CBCHS384 ContentEncryptionAlgorithm = jose.A192CBC_HS384
	ContentEncAlgA256CBCHS512 ContentEncryptionAlgorithm = jose.A256CBC_HS512
	ContentEncAlgA128GCM      ContentEncryptionAlgorithm = jose.A128GCM
	ContentEncAlgA192GCM      ContentEncryptionAlgorithm = jose.A192GCM
	ContentEncAlgA256GCM      ContentEncryptionAlgorithm = jose.A256GCM
)

type CompressionAlgorithm = jose.CompressionAlgorithm

const (
	CompressionAlgNone    CompressionAlgorithm = jose.NONE
	CompressionAlgDeflate CompressionAlgorithm = jose.DEFLATE
)

type JSONWebKey = jose.JSONWebKey

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

func (s *JSONWebKeySet) UnmarshalJSON(data []byte) error {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var validKeys []JSONWebKey
	for _, rawKey := range raw.Keys {
		var key JSONWebKey
		if err := json.Unmarshal(rawKey, &key); err == nil {
			validKeys = append(validKeys, key)
		}
	}

	if len(validKeys) == 0 {
		return errors.New("no valid keys found in jwks")
	}

	s.Keys = validKeys
	return nil
}

func (jwks JSONWebKeySet) ToJOSE() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: jwks.Keys,
	}
}

func (jwks JSONWebKeySet) Key(kid string) (JSONWebKey, error) {
	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			return key, nil
		}
	}

	return JSONWebKey{}, fmt.Errorf("could not find jwk with id: %s", kid)
}

func (jwks JSONWebKeySet) Public() JSONWebKeySet {
	publicKeys := []JSONWebKey{}
	for _, jwk := range jwks.Keys {
		publicKey := jwk.Public()
		// A JWK that cannot be made public is returned as the zero value.
		if publicKey.Key != nil {
			publicKeys = append(publicKeys, publicKey)
		}
	}

	return JSONWebKeySet{Keys: publicKeys}
}

func (jwks JSONWebKeySet) KeyByAlg(alg string) (JSONWebKey, error) {
	for _, jwk := range jwks.Keys {
		if jwk.Algorithm == alg {
			return jwk, nil
		}
	}

	return JSONWebKey{}, fmt.Errorf("could not find jwk matching the algorithm %s", alg)
}

// SignerFunc defines a function type for handling signing operations.
type SignerFunc func(ctx context.Context, alg SignatureAlgorithm) (kid string, signer crypto.Signer, err error)

// DecrypterFunc defines a function type for handling decryption operations.
type DecrypterFunc func(ctx context.Context, kid string, alg KeyEncryptionAlgorithm) (crypto.Decrypter, error)
