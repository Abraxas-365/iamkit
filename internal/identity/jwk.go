package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// publicJWK is the members of an RSA or EC public JSON Web Key.
type publicJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// KeyAlgorithms are the JWS algorithms a public key verifies: RS256–512
// and PS256–512 for RSA (2048 bits or more), the curve's ES algorithm for
// EC P-256/P-384/P-521.
func KeyAlgorithms(key crypto.PublicKey) []string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return []string{"ES256"}
		case elliptic.P384():
			return []string{"ES384"}
		case elliptic.P521():
			return []string{"ES512"}
		}
	}
	return nil
}

// ParsePublicJWK reads one public signing JSON Web Key (RSA of at least
// 2048 bits, or EC P-256/P-384/P-521). Private members, a use other than
// sig and unknown key types are refused.
func ParsePublicJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, errx.Validation("public_key must be a JSON Web Key")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := members[private]; ok {
			return nil, errx.Validation("public_key must not hold private key material")
		}
	}
	var jwk publicJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, errx.Validation("public_key must be a JSON Web Key")
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return nil, errx.Validation("public_key must be a signing key (use sig)")
	}
	switch jwk.Kty {
	case "RSA":
		n, err1 := base64.RawURLEncoding.DecodeString(jwk.N)
		e, err2 := base64.RawURLEncoding.DecodeString(jwk.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errx.Validation("public_key has an invalid RSA modulus or exponent")
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if key.N.BitLen() < 2048 {
			return nil, errx.Validation("public_key RSA keys must be at least 2048 bits")
		}
		if key.E < 3 || key.E%2 == 0 {
			return nil, errx.Validation("public_key has an invalid RSA exponent")
		}
		return key, nil
	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errx.Validation("public_key EC keys must use P-256, P-384 or P-521")
		}
		x, err1 := base64.RawURLEncoding.DecodeString(jwk.X)
		y, err2 := base64.RawURLEncoding.DecodeString(jwk.Y)
		size := (curve.Params().BitSize + 7) / 8
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return nil, errx.Validation("public_key has invalid EC coordinates")
		}
		key := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		// ECDH refuses points off the curve (and the point at infinity).
		if _, err := key.ECDH(); err != nil {
			return nil, errx.Validation("public_key is not a point on its curve")
		}
		return key, nil
	}
	return nil, errx.Validation("public_key must be an RSA or EC key")
}

// MarshalPublicJWK writes key as a JSON Web Key with use sig, the
// canonical form stored for machine user keys.
func MarshalPublicJWK(key crypto.PublicKey) (json.RawMessage, error) {
	var jwk publicJWK
	switch k := key.(type) {
	case *rsa.PublicKey:
		jwk = publicJWK{Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(k.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		jwk = publicJWK{Kty: "EC", Crv: k.Curve.Params().Name, X: base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, size))), Y: base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, size)))}
	default:
		return nil, errx.Validation("public_key must be an RSA or EC key")
	}
	jwk.Use = "sig"
	out, err := json.Marshal(jwk)
	if err != nil {
		return nil, errx.Wrap(err, "encode public key", errx.TypeInternal)
	}
	return out, nil
}
