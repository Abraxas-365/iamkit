package authsvc

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Service struct {
	repository authentication.Repository
	passwords  authentication.Passwords
	secrets    authentication.Secrets
	delivery   authentication.Delivery
}

func New(repository authentication.Repository, passwords authentication.Passwords, secrets authentication.Secrets, delivery authentication.Delivery) *Service {
	return &Service{repository, passwords, secrets, delivery}
}
func canonical(c authentication.Context) authentication.Context {
	for _, id := range []*string{&c.EnvironmentID, &c.OrganizationID, &c.ApplicationID, &c.ResourceID} {
		if parsed, err := uuid.Parse(*id); err == nil {
			*id = parsed.String()
		}
	}
	return c
}
func (s *Service) Login(ctx context.Context, boundary authentication.Context, email, password string) (authentication.Issued, error) {
	var out authentication.Issued
	email, err := identity.Email(email)
	if err != nil || boundary.Validate() != nil || len(password) > config.PasswordMaxLength {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	user, hash, lookup := tx.PasswordUser(ctx, boundary, email)
	matches := s.passwords.Compare(hash, password)
	if lookup != nil {
		return out, lookup
	}
	if !matches {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	return s.NewSession(ctx, tx, boundary, user)
}

// NewSession participates in an existing transaction with the user already locked.
func (s *Service) NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user string) (authentication.Issued, error) {
	out := authentication.Issued{Context: canonical(boundary), User: user, Session: uuid.NewString()}
	access, err := tx.Resolve(ctx, boundary, user)
	if err != nil {
		return out, err
	}
	out.Access = access
	expires := time.Now().Add(config.SessionTTL)
	if err = tx.CreateSession(ctx, boundary, user, out.Session, expires); err != nil {
		return out, err
	}
	out.Refresh, err = s.saveRefresh(ctx, tx, out.Session, boundary.EnvironmentID, expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Service) saveRefresh(ctx context.Context, tx authentication.Transaction, session, environment string, expires time.Time) (string, error) {
	raw, hash, err := s.secrets.Generate("ik_refresh_")
	if err != nil {
		return "", err
	}
	if err = tx.SaveRefresh(ctx, hash, session, environment, expires); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) Refresh(ctx context.Context, boundary authentication.Context, token string) (authentication.Issued, error) {
	out := authentication.Issued{Context: canonical(boundary)}
	if boundary.Validate() != nil || !strings.HasPrefix(token, "ik_refresh_") {
		return out, errx.Unauthorized("invalid refresh token")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	row, err := tx.Refresh(ctx, boundary, s.secrets.Hash(token))
	if err != nil {
		return out, err
	}
	if row.Revoked || !row.Expires.After(time.Now()) {
		return out, errx.Unauthorized("invalid refresh token")
	}
	if row.Used {
		if err = tx.RevokeSession(ctx, row.ID); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, errx.Unauthorized("refresh token replay revoked session")
	}
	out.Access, err = tx.Resolve(ctx, boundary, row.User)
	if err != nil {
		return out, err
	}
	if err = tx.UseRefresh(ctx, s.secrets.Hash(token)); err != nil {
		return out, err
	}
	out.User, out.Session = row.User, row.ID
	out.Refresh, err = s.saveRefresh(ctx, tx, row.ID, boundary.EnvironmentID, row.Expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Service) InitiateChallenge(ctx context.Context, environment, email, purpose string) (string, error) {
	email, err := identity.Email(email)
	if err != nil || !identity.ValidID(environment) || (purpose != "login" && purpose != "password_reset" && purpose != "email_verification") {
		return "", errx.Validation("invalid challenge request")
	}
	if s.delivery == nil {
		return "", errx.External("email delivery is not configured")
	}
	id := uuid.NewString()
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	user, err := tx.EligibleChallengeUser(ctx, environment, email, purpose)
	if err != nil {
		return "", err
	}
	if user == "" {
		return id, nil
	}
	recent, err := tx.RecentChallenges(ctx, environment, user)
	if err != nil {
		return "", err
	}
	if recent >= 5 {
		return id, nil
	}
	code, err := s.secrets.Code()
	if err != nil {
		return "", err
	}
	if err = tx.CreateChallenge(ctx, id, environment, user, purpose, s.secrets.Hash(id+":"+code)); err != nil {
		return "", err
	}
	if err = s.delivery.Send(ctx, email, purpose, code); err != nil {
		// Never log the adapter error: it may contain recipient or challenge data.
		slog.ErrorContext(ctx, "challenge delivery failed")
		return id, nil
	}
	return id, tx.Commit()
}
func (s *Service) VerifyChallenge(ctx context.Context, boundary authentication.Context, id, code, purpose, password string) (authentication.Issued, error) {
	var out authentication.Issued
	if !identity.ValidID(boundary.EnvironmentID) || !identity.ValidID(id) || len(code) != 8 {
		return out, errx.Unauthorized("invalid challenge")
	}
	if purpose == "login" && boundary.Validate() != nil {
		return out, errx.Validation("login context required")
	}
	var hash string
	var err error
	if purpose == "password_reset" {
		if len(password) < config.PasswordMinLength || len(password) > config.PasswordMaxLength {
			return out, errx.Validation("12-72 byte password required")
		}
		hash, err = s.passwords.Hash(password)
		if err != nil {
			return out, err
		}
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	row, err := tx.Challenge(ctx, boundary.EnvironmentID, id, purpose)
	if err != nil {
		return out, err
	}
	if row.Attempts >= 5 {
		return out, errx.Unauthorized("invalid challenge")
	}
	if subtle.ConstantTimeCompare(row.Hash, s.secrets.Hash(id+":"+code)) != 1 {
		if err = tx.FailChallenge(ctx, id); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, errx.Unauthorized("invalid challenge")
	}
	if err = tx.CompleteChallenge(ctx, boundary.EnvironmentID, row.User, id, purpose, hash); err != nil {
		return out, err
	}
	if purpose == "login" {
		return s.NewSession(ctx, tx, boundary, row.User)
	}
	return out, tx.Commit()
}
