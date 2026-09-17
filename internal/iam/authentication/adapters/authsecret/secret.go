package authsecret

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
)

type Generator struct{ mgmtsecret.Generator }

func (Generator) Code() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", errx.Wrap(err, "generate challenge code", errx.TypeInternal)
	}
	return fmt.Sprintf("%08d", number), nil
}
