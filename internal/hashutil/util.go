package hashutil

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

// Thumbprint generates a base64 URL-encoded SHA-256 hash (thumbprint) of a
// given string.
func Thumbprint(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// HalfHash generates a half-hash of a given claim using the given algorithm.
// [goidc.SigAlgNone] is not supported.
func HalfHash(claim string, alg goidc.SignatureAlgorithm) string {
	h := HashAlg(alg).New()
	h.Write([]byte(claim))
	halfHashedClaim := h.Sum(nil)[:h.Size()/2]
	return base64.RawURLEncoding.EncodeToString(halfHashedClaim)
}

func HashAlg(alg goidc.SignatureAlgorithm) crypto.Hash {
	switch alg {
	case goidc.SigAlgRS512, goidc.SigAlgES512, goidc.SigAlgPS512, goidc.SigAlgHS512:
		return crypto.SHA512
	case goidc.SigAlgRS384, goidc.SigAlgES384, goidc.SigAlgPS384, goidc.SigAlgHS384:
		return crypto.SHA384
	default:
		return crypto.SHA256
	}
}
