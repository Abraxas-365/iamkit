package usersvc

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// PurposePhone is the SMS purpose of phone verification codes.
const PurposePhone = "phone_verification"

// Phones implements self-service phone verification.
type Phones struct {
	repository user.PhoneRepository
	sms        user.SMS
	hasher     user.CodeHasher
	now        func() time.Time
}

func NewPhones(repository user.PhoneRepository, sms user.SMS, hasher user.CodeHasher) *Phones {
	return &Phones{repository: repository, sms: sms, hasher: hasher, now: time.Now}
}

var _ user.PhoneCommands = (*Phones)(nil)

// codeHash binds a code to the user it was sent to.
func (s *Phones) codeHash(id identity.UserID, code string) []byte {
	return s.hasher.Hash("phone:" + id.String() + ":" + code)
}

func (s *Phones) StartPhoneVerification(ctx context.Context, m user.Mutation, id identity.UserID, phone string) (user.PhoneCodeSent, error) {
	if id.IsZero() {
		return user.PhoneCodeSent{}, errx.NotFound("user not found")
	}
	phone, err := identity.Phone(phone)
	if err != nil {
		return user.PhoneCodeSent{}, err
	}
	if s.sms == nil {
		return user.PhoneCodeSent{}, errx.External("SMS delivery is not configured")
	}
	code, err := sixDigits()
	if err != nil {
		return user.PhoneCodeSent{}, err
	}
	var sent user.PhoneVerification
	err = s.repository.EditPhoneVerification(ctx, m.Environment, id, func(current user.PhoneVerification) (user.PhoneVerification, error) {
		next, err := current.Send(phone, s.codeHash(id, code), s.now())
		sent = next
		return next, err
	})
	if err != nil {
		return user.PhoneCodeSent{}, err
	}
	// The code is stored before it is sent: a failed text leaves nothing
	// usable, and the cooldown still applies.
	if err = s.sms.SendSMS(ctx, m.Environment, phone, PurposePhone, code); err != nil {
		return user.PhoneCodeSent{}, err
	}
	return user.PhoneCodeSent{Destination: user.MaskPhone(phone), ExpiresAt: sent.Expires.UTC()}, nil
}

func (s *Phones) VerifyPhone(ctx context.Context, m user.Mutation, id identity.UserID, code string) error {
	if id.IsZero() {
		return errx.NotFound("user not found")
	}
	if len(code) != 6 {
		return user.WrongPhoneCode()
	}
	m.Action, m.Target = user.ActionPhoneVerified, id.String()
	ok, err := s.repository.ConfirmPhone(ctx, m, id, s.codeHash(id, code))
	if err != nil || ok {
		return err
	}
	if err = s.repository.FailPhoneCode(ctx, m.Environment, id, config.MFAAttempts); err != nil {
		return err
	}
	return user.WrongPhoneCode()
}

func (s *Phones) RemovePhone(ctx context.Context, m user.Mutation, id identity.UserID) error {
	if id.IsZero() {
		return errx.NotFound("user not found")
	}
	m.Action, m.Target = user.ActionPhoneRemoved, id.String()
	return s.repository.RemovePhone(ctx, m, id)
}

func sixDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", errx.Wrap(err, "generate verification code", errx.TypeInternal)
	}
	return fmt.Sprintf("%06d", n), nil
}
