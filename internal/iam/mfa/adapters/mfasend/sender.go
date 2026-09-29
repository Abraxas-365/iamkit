// Package mfasend delivers second-factor codes through the authentication
// module: emails through the environment's email delivery (purpose "mfa"),
// texts through its SMS provider.
package mfasend

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Mail is the part of the authentication delivery service codes use.
type Mail interface {
	Send(ctx context.Context, environment identity.EnvironmentID, message authentication.Message) error
}

// Texts is the part of the SMS service codes use.
type Texts interface {
	SendSMS(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) error
}

type Sender struct {
	Mail  Mail
	Texts Texts // nil: SMS codes cannot be sent
}

var _ mfa.Sender = Sender{}

func (s Sender) Email(ctx context.Context, environment identity.EnvironmentID, email, purpose, code string) error {
	return s.Mail.Send(ctx, environment, authentication.Message{Email: email, Purpose: authentication.PurposeMFA, Code: code})
}

func (s Sender) SMS(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) error {
	if s.Texts == nil {
		return errx.External("SMS delivery is not available")
	}
	return s.Texts.SendSMS(ctx, environment, phone, purpose, code)
}
