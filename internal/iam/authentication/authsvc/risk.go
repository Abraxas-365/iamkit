package authsvc

import (
	"context"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SetRisk applies risk evaluation (restrictions, detections, the attempt
// log) to sign-ins. Without it none of it runs.
func (s *Service) SetRisk(r authentication.Risk) { s.risk = r }

func (s *Service) signal(boundary authentication.Context, user identity.UserID, login, method string, mfa bool) risk.Signal {
	return risk.Signal{Environment: boundary.EnvironmentID, Organization: boundary.OrganizationID, User: user, Login: login, Method: method,
		MFA: mfa, EmailProof: method == authentication.MethodCode}
}

// screen refuses a sign-in a restriction denies, before any credential.
func (s *Service) screen(ctx context.Context, boundary authentication.Context, login, method string) error {
	if s.risk == nil {
		return nil
	}
	return s.risk.Screen(ctx, s.signal(boundary, identity.UserID{}, login, method, false))
}

// assess runs the detections; the zero decision (Off) when risk is not wired.
func (s *Service) assess(ctx context.Context, sig risk.Signal) risk.Decision {
	if s.risk == nil {
		return risk.Decision{Action: risk.ActionNone, Detections: []string{}, Off: true}
	}
	return s.risk.Assess(ctx, sig)
}

// record writes the attempt; it never fails the sign-in.
func (s *Service) record(ctx context.Context, sig risk.Signal, outcome string, d risk.Decision) {
	if s.risk == nil {
		return
	}
	s.risk.Record(ctx, sig, outcome, d)
}

// credentialFailed records a failed attempt when err is a credential
// refusal (401); other errors (lockout, blocked, infrastructure) are not
// wrong credentials.
func (s *Service) credentialFailed(ctx context.Context, boundary authentication.Context, login, method string, err error) {
	if s.risk == nil || err == nil {
		return
	}
	var e *errx.Error
	if !errx.As(err, &e) || e.Type != errx.TypeAuthorization || e.HTTPStatus != 401 {
		return
	}
	s.record(ctx, s.signal(boundary, identity.UserID{}, login, method, false), risk.OutcomeFailure, risk.Decision{Action: risk.ActionNone, Detections: []string{}})
}

// riskChallenge reports whether err is the pre_sign_in action's request
// for a challenge.
func riskChallenge(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == authentication.CodeRiskChallenge
}

// parkChallenge commits tx and parks the login until the emailed code. ok
// is false only when no challenge can be asked of the account (no verified
// email, no delivery): the sign-in then goes on without it. Any other
// failure to park is the error — it never signs in unchallenged.
func (s *Service) parkChallenge(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, amr []string, passwordHash string, sig risk.Signal, d risk.Decision) (authentication.Result, bool, error) {
	// Commit first, like the second factor: the pending login insert must
	// not wait on this transaction's row locks.
	if err := tx.Commit(); err != nil {
		return authentication.Result{}, false, err
	}
	if s.second == nil {
		return authentication.Result{}, false, nil
	}
	token, err := s.second.BeginChallenge(ctx, boundary, user, amr, passwordHash, d.Detections)
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == authentication.CodeChallengeUnavailable {
			return authentication.Result{}, false, nil
		}
		return authentication.Result{}, false, err
	}
	d.Action = risk.Stronger(d.Action, risk.ActionChallenge)
	s.record(ctx, sig, risk.OutcomeChallenged, d)
	return authentication.Result{MFA: &authentication.MFA{Token: token, Factors: []string{"email"}, Reason: authentication.ReasonRiskChallenge}}, true, nil
}

// methodOf is the sign-in method of a pending login's first-factor
// references.
func methodOf(amr []string) string {
	switch {
	case slices.Contains(amr, "hwk"):
		return authentication.MethodPasskey
	case slices.Contains(amr, "fed"):
		return authentication.MethodSSO
	case slices.Contains(amr, "email"):
		return authentication.MethodCode
	}
	return authentication.MethodPassword
}

// challengeAsked reports whether a pre_sign_in challenge must be parked:
// no second factor and no inbox proof in the session, nothing already
// answered or found unverifiable.
func challengeAsked(amr []string, d risk.Decision) bool {
	return !authentication.HasMFA(amr) && !slices.Contains(amr, "email") && !d.Challenged && d.SatisfiedBy == ""
}
