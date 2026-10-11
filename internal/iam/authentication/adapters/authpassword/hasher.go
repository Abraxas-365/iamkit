// Package authpassword hashes new passwords with bcrypt and verifies the
// hash formats operators import from other systems (bcrypt, argon2,
// pbkdf2, Firebase scrypt); see parse for the accepted strings.
package authpassword

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/subtle"
	"runtime"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Hasher implements authentication.Passwords.
type Hasher struct{}

var dummy = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte(uuid.NewString()), config.BcryptCost)
	if err != nil {
		panic(err)
	}
	return string(hash)
}()

// floor is how long one bcrypt compare at config.BcryptCost takes here.
// Compare never answers sooner, so an account still holding a cheaper
// imported hash (argon2, pbkdf2, low-cost bcrypt) is not told apart from
// an unknown one by timing.
var floor = func() time.Duration {
	start := time.Now()
	_ = bcrypt.CompareHashAndPassword([]byte(dummy), []byte(uuid.NewString()))
	return time.Since(start)
}()

// memoryHard bounds concurrent argon2 and scrypt verifications, each up to
// 64 MiB, so a burst of sign-ins cannot exhaust memory.
var memoryHard = make(chan struct{}, max(2, runtime.NumCPU()))

// Hash returns a bcrypt hash at config.BcryptCost.
func (Hasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), config.BcryptCost)
	if err != nil {
		return "", errx.Wrap(err, "hash password", errx.TypeInternal)
	}
	return string(hash), nil
}

// Compare reports whether password matches hash and whether the hash should
// be replaced by a fresh bcrypt one (stale: an imported format, or bcrypt
// at another cost). An empty, unknown or over-cap hash compares a dummy
// bcrypt hash, and no answer comes sooner than floor, so timing does not
// tell an unknown account or an imported hash apart.
func (Hasher) Compare(hash, password string) (matches, stale bool) {
	start := time.Now()
	defer func() {
		if wait := floor - time.Since(start); wait > 0 {
			time.Sleep(wait)
		}
	}()
	p, err := parse(hash)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword([]byte(dummy), []byte(password))
		return false, false
	}
	matches = p.verify(password)
	return matches, matches && p.stale
}

// CheckHash reports why hash cannot be stored in users.password_hash: a
// format that is not supported, parameters above the caps, or a malformed
// string. It computes nothing.
func (Hasher) CheckHash(hash string) error {
	if _, err := parse(hash); err != nil {
		return err
	}
	return nil
}

func (p parsed) verify(password string) bool {
	secret := []byte(password)
	switch p.scheme {
	case bcryptScheme:
		return bcrypt.CompareHashAndPassword([]byte(p.raw), secret) == nil
	case argon2Scheme:
		memoryHard <- struct{}{}
		defer func() { <-memoryHard }()
		derive := argon2.IDKey
		if !p.id {
			derive = argon2.Key
		}
		return equal(derive(secret, p.salt, p.turns, p.memory, p.threads, uint32(len(p.sum))), p.sum)
	case pbkdf2Scheme:
		key, err := pbkdf2.Key(p.digest, password, p.salt, p.iterations, len(p.sum))
		return err == nil && equal(key, p.sum)
	case firebaseScheme:
		memoryHard <- struct{}{}
		defer func() { <-memoryHard }()
		return p.verifyFirebase(secret)
	}
	return false
}

// verifyFirebase follows firebase/scrypt: the key scrypt derives from the
// password, salt and salt separator encrypts the signer key with AES-256-CTR
// under a zero IV; the result is the stored hash.
func (p parsed) verifyFirebase(password []byte) bool {
	salt := append(append(make([]byte, 0, len(p.salt)+len(p.separator)), p.salt...), p.separator...)
	key, err := scrypt.Key(password, salt, 1<<p.memCost, p.rounds, 1, 32)
	if err != nil {
		return false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	out := make([]byte, len(p.signer))
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(out, p.signer)
	return equal(out, p.sum)
}

func equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
