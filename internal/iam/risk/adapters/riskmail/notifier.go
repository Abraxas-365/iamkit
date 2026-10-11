// Package riskmail emails users the security alerts of risk detections
// (email purpose security_alert) through the authentication delivery.
package riskmail

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Recipients resolves the address of a user's alerts (riskpg.Recipients).
type Recipients interface {
	Email(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (string, error)
}

// Mail is the part of the authentication delivery service alerts use
// (DeliveryService.Send: usage limits, provider and attempt record).
type Mail interface {
	Send(ctx context.Context, environment identity.EnvironmentID, message authentication.Message) error
}

// Notifier sends alerts after the sign-in answered: like code emails,
// delivery never delays the response, and a failure only logs.
type Notifier struct {
	Recipients Recipients
	Mail       Mail
	wg         sync.WaitGroup
}

var _ risk.Notifier = (*Notifier)(nil)

func New(recipients Recipients, mail Mail) *Notifier {
	return &Notifier{Recipients: recipients, Mail: mail}
}

// Alert queues the email and returns at once.
func (n *Notifier) Alert(ctx context.Context, a risk.Alert) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.ExternalHTTPTimeout)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(ctx, "security alert panicked", "panic", r)
			}
		}()
		if err := n.send(ctx, a); err != nil {
			slog.ErrorContext(ctx, "security alert failed", "environment", a.Environment, "user", a.User, "detection", a.Detection, "err", err)
		}
	}()
	return nil
}

func (n *Notifier) send(ctx context.Context, a risk.Alert) error {
	email, err := n.Recipients.Email(ctx, a.Environment, a.User)
	if err != nil || email == "" {
		return err
	}
	at := a.At
	if at.IsZero() {
		at = time.Now()
	}
	return n.Mail.Send(ctx, a.Environment, authentication.Message{
		Email: email, Purpose: authentication.PurposeSecurityAlert, Environment: a.Environment, Locale: a.Locale,
		Detection: a.Detection, IP: a.IP, Country: a.Country, UserAgent: a.UserAgent, OccurredAt: &at,
	})
}

// Wait waits up to timeout for alerts still being sent (shutdown, tests);
// false when some are left.
func (n *Notifier) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { n.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
