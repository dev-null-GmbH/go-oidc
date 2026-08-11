package joseutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/dev-null-GmbH/go-oidc/internal/hashutil"
	"github.com/dev-null-GmbH/go-oidc/pkg/goidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Sign(claims any, signer jose.SigningKey, opts *jose.SignerOptions) (string, error) {
	if opts == nil {
		opts = &jose.SignerOptions{}
	}
	if _, ok := opts.ExtraHeaders[jose.HeaderType]; !ok {
		opts = opts.WithType("JWT")
	}

	joseSigner, err := jose.NewSigner(signer, opts)
	if err != nil {
		return "", err
	}

	jws, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", err
	}

	return jws, nil
}

type OpaqueSigner struct {
	ID        string
	Algorithm goidc.SignatureAlgorithm
	Signer    crypto.Signer
}

func (s OpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     s.ID,
		Key:       s.Signer.Public(),
		Algorithm: string(s.Algorithm),
	}
}

func (s OpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{s.Algorithm}
}

func (s OpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	h := hashutil.HashAlg(alg)
	hasher := h.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	var opts crypto.SignerOpts = h
	if alg == jose.PS256 || alg == jose.PS384 || alg == jose.PS512 {
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       h,
		}
	}

	return s.Signer.Sign(rand.Reader, digest, opts)
}

type OpaqueDecrypter struct {
	Algorithm goidc.KeyEncryptionAlgorithm
	Decrypter crypto.Decrypter
}

func (o OpaqueDecrypter) DecryptKey(encryptedKey []byte, _ jose.Header) ([]byte, error) {
	var opts crypto.DecrypterOpts
	switch o.Algorithm {
	case goidc.KeyEncRSAOAEP:
		opts = &rsa.OAEPOptions{
			Hash: crypto.SHA1,
		}
	case goidc.KeyEncRSAOAEP256:
		opts = &rsa.OAEPOptions{
			Hash: crypto.SHA256,
		}
	default:
	}
	return o.Decrypter.Decrypt(rand.Reader, encryptedKey, opts)
}

func Encrypt(jws string, jwk goidc.JSONWebKey, alg goidc.ContentEncryptionAlgorithm, opts *jose.EncrypterOptions) (string, error) {
	if opts == nil {
		opts = &jose.EncrypterOptions{}
	}
	if opts.ExtraHeaders[jose.HeaderType] == nil {
		opts = opts.WithType("JWT")
	}
	if opts.ExtraHeaders[jose.HeaderContentType] == nil {
		opts = opts.WithContentType("JWT")
	}

	encrypter, err := jose.NewEncrypter(
		alg,
		jose.Recipient{
			Algorithm: goidc.KeyEncryptionAlgorithm(jwk.Algorithm),
			Key:       jwk.Key,
			KeyID:     jwk.KeyID,
		},
		opts,
	)
	if err != nil {
		return "", err
	}

	encContent, err := encrypter.Encrypt([]byte(jws))
	if err != nil {
		return "", err
	}

	encContentString, err := encContent.CompactSerialize()
	if err != nil {
		return "", err
	}

	return encContentString, nil
}

func Unsigned(claims any, opts *jose.SignerOptions) string {
	if opts == nil {
		opts = &jose.SignerOptions{}
	}
	if _, ok := opts.ExtraHeaders[jose.HeaderType]; !ok {
		opts = opts.WithType("JWT")
	}

	header := map[string]any{
		"alg": goidc.SigAlgNone,
		"typ": opts.ExtraHeaders[jose.HeaderType],
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64 + "."
}

func IsUnsignedJWT(token string) bool {
	isJWS, _ := regexp.MatchString(
		"(^[\\w-]+\\.[\\w-]+\\.$)",
		token,
	)
	return isJWS
}

func IsJWS(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]+\\.[\\w-]+\\.[\\w-]+$)", token)
	return isJWS
}

func IsJWE(token string) bool {
	isJWS, _ := regexp.MatchString("(^[\\w-]+\\.[\\w-]+\\.[\\w-]+\\.[\\w-]+\\.[\\w-]+$)", token)
	return isJWS
}

// KeyByAlgorithms returns the first JWK that matches the given algorithms.
func KeyByAlgorithms(jwks goidc.JSONWebKeySet, algs []goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	for _, alg := range algs {
		jwk, err := jwks.KeyByAlg(string(alg))
		if err != nil {
			continue
		}
		return jwk, nil
	}
	return goidc.JSONWebKey{}, errors.New("could not find a valid jwk matching the algorithms")
}

func KeyUsage(key goidc.JSONWebKey) goidc.KeyUsage {
	if key.Use != "" {
		return goidc.KeyUsage(key.Use)
	}

	switch key.Algorithm {
	case string(goidc.SigAlgRS256), string(goidc.SigAlgRS384), string(goidc.SigAlgRS512),
		string(goidc.SigAlgES256), string(goidc.SigAlgES384), string(goidc.SigAlgES512),
		string(goidc.SigAlgPS256), string(goidc.SigAlgPS384), string(goidc.SigAlgPS512),
		string(goidc.SigAlgHS256), string(goidc.SigAlgHS384), string(goidc.SigAlgHS512):
		return goidc.KeyUsageSignature
	case string(goidc.KeyEncAlgRSA15), string(goidc.KeyEncRSAOAEP), string(goidc.KeyEncRSAOAEP256):
		return goidc.KeyUsageEncryption
	default:
		return ""
	}
}
