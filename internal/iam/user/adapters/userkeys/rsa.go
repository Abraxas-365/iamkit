// Package userkeys generates machine user key pairs (stdlib crypto).
package userkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// RSA generates RSA 2048 pairs; the private key is PEM-encoded PKCS #8.
type RSA struct{}

var _ user.KeyPairs = RSA{}

func (RSA) Generate() (json.RawMessage, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", errx.Wrap(err, "generate key", errx.TypeInternal)
	}
	public, err := identity.MarshalPublicJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", errx.Wrap(err, "encode key", errx.TypeInternal)
	}
	return public, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
