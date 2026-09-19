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
)

type Service struct {
	repository  authentication.Repository
	passwords   authentication.Passwords
	secrets     authentication.Secrets
	delivery    authentication.Delivery
	deliverySvc *DeliveryService
}

func New(repository authentication.Repository, passwords authentication.Passwords, secrets authentication.Secrets, delivery authentication.Delivery) *Service {
	return &Service{repository: repository, passwords: passwords, secrets: secrets, delivery: delivery}
}
func (s *Service) SetDeliveryService(ds *DeliveryService) { s.deliverySvc = ds }

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

func (s *Service) NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID) (authentication.Issued, error) {
	sessionID := identity.NewSessionID()
	out := authentication.Issued{Context: boundary, User: user, Session: sessionID}
	access, err := tx.Resolve(ctx, boundary, user)
	if err != nil {
		return out, err
	}
	out.Access = access
	expires := time.Now().Add(config.SessionTTL)
	if err = tx.CreateSession(ctx, boundary, user, sessionID, expires); err != nil {
		return out, err
	}
	out.Refresh, err = s.saveRefresh(ctx, tx, user, sessionID, expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Service) saveRefresh(ctx context.Context, tx authentication.Transaction, user identity.UserID, session identity.SessionID, expires time.Time) (string, error) {
	raw, hash, err := s.secrets.Generate("ik_refresh_")
	if err != nil {
		return "", err
	}
	if err = tx.SaveRefresh(ctx, hash, user, session, expires); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Service) Refresh(ctx context.Context, boundary authentication.Context, token string) (authentication.Issued, error) {
	out := authentication.Issued{Context: boundary}
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
	out.Refresh, err = s.saveRefresh(ctx, tx, row.User, row.ID, row.Expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Service) InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.ChallengeID, error) {
	email, err := identity.Email(email)
	if err != nil || environment.IsZero() || (purpose != "login" && purpose != "password_reset" && purpose != "email_verification") {
		return identity.ChallengeID{}, errx.Validation("invalid challenge request")
	}
	if s.deliverySvc == nil && s.delivery == nil {
		return identity.ChallengeID{}, errx.External("email delivery is not configured")
	}
	id := identity.NewChallengeID()
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	defer tx.Rollback()
	user, err := tx.EligibleChallengeUser(ctx, environment, email, purpose)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if user.IsZero() {
		return id, nil
	}
	recent, err := tx.RecentChallenges(ctx, user, purpose)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if recent >= 5 {
		return id, nil
	}
	code, err := s.secrets.Code()
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if err = tx.CreateChallenge(ctx, id, user, purpose, environment, s.secrets.Hash(id.String()+":"+code)); err != nil {
		return identity.ChallengeID{}, err
	}
	var sendErr error
	if s.deliverySvc != nil {
		sendErr = s.deliverySvc.Send(ctx, environment, email, purpose, code)
	} else {
		sendErr = s.delivery.Send(ctx, email, purpose, code)
	}
	if sendErr != nil {
		slog.ErrorContext(ctx, "challenge delivery failed",
			"challenge", id,
			"environment", environment,
			"purpose", purpose,
			"err", sendErr,
		)
		return id, nil
	}
	return id, tx.Commit()
}

func (s *Service) VerifyChallenge(ctx context.Context, boundary authentication.Context, challengeID identity.ChallengeID, code, purpose, password string) (authentication.Issued, error) {
	var out authentication.Issued
	if boundary.EnvironmentID.IsZero() || challengeID.IsZero() || len(code) != 8 {
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
	row, err := tx.Challenge(ctx, challengeID, identity.UserID{}, purpose)
	if err != nil {
		return out, err
	}
	if row.Attempts >= 5 {
		return out, errx.Unauthorized("invalid challenge")
	}
	if subtle.ConstantTimeCompare(row.Hash, s.secrets.Hash(challengeID.String()+":"+code)) != 1 {
		if err = tx.FailChallenge(ctx, challengeID); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, errx.Unauthorized("invalid challenge")
	}
	if err = tx.CompleteChallenge(ctx, challengeID, row.User, purpose, boundary.EnvironmentID, hash); err != nil {
		return out, err
	}
	if purpose == "login" {
		return s.NewSession(ctx, tx, boundary, row.User)
	}
	return out, tx.Commit()
}
