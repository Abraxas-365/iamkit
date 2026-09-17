package mgmtsecret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

type Generator struct{}

func (Generator) Generate(prefix string) (string, []byte, error) { return Secret(prefix) }
func (Generator) Hash(raw string) []byte                         { return Hash(raw) }
func Secret(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, errx.Wrap(err, "credential generation failed", errx.TypeInternal)
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, Hash(raw), nil
}
func Hash(raw string) []byte { hash := sha256.Sum256([]byte(raw)); return hash[:] }
