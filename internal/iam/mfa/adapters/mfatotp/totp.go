// Package mfatotp implements RFC 6238 time-based one-time passwords
// (HMAC-SHA1, 6 digits, 30-second steps) with the standard library.
package mfatotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
)

// SecretBytes is the secret size: 160 bits, as RFC 4226 recommends for SHA-1.
const SecretBytes = 20

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type TOTP struct{}

var _ mfa.TOTP = TOTP{}

func (TOTP) Secret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "secret generation failed", errx.TypeInternal)
	}
	return encoding.EncodeToString(b), nil
}

// URI follows the Key Uri Format understood by authenticator apps.
func (TOTP) URI(secret string, account mfa.Account) string {
	label := url.PathEscape(account.Issuer) + ":" + url.PathEscape(account.Email)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", account.Issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(config.TOTPDigits))
	q.Set("period", fmt.Sprint(config.TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Verify checks the code against the steps around now, newest last so the
// greatest matching step is returned, and refuses steps already used.
func (TOTP) Verify(secret, code string, lastStep int64, at time.Time) (int64, bool) {
	key, err := encoding.DecodeString(strings.ToUpper(secret))
	if err != nil || len(code) != config.TOTPDigits {
		return 0, false
	}
	now := at.Unix() / config.TOTPPeriod
	var matched int64
	ok := false
	for step := now - config.TOTPSkew; step <= now+config.TOTPSkew; step++ {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(Code(key, step)), []byte(code)) == 1 {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// Code is the HOTP value (RFC 4226) of a counter.
func Code(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range config.TOTPDigits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", config.TOTPDigits, value%mod)
}
