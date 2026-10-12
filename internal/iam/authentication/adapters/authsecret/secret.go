package authsecret

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

type Generator struct{ cryptox.Generator }

func (Generator) Code() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", errx.Wrap(err, "generate challenge code", errx.TypeInternal)
	}
	return fmt.Sprintf("%08d", number), nil
}
