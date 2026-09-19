package mgmtbcrypt

import (
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Hasher implements management.Passwords using bcrypt.
type Hasher struct{}

var dummy = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte(uuid.NewString()), config.BcryptCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}()

func (Hasher) Compare(hash, password string) bool {
	missing := hash == ""
	if missing {
		hash = dummy
	}
	matches := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	return matches && !missing
}

func (Hasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), config.BcryptCost)
	if err != nil {
		return "", errx.Wrap(err, "hash password", errx.TypeInternal)
	}
	return string(hash), nil
}
