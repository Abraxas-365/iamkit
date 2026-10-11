package hostedsvc

import (
	"context"
	"log/slog"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// hostedCtx marks the request as the hosted surface (device id and CAPTCHA
// outcome, set by the pages, are kept).
func hostedCtx(ctx context.Context) context.Context {
	r := risk.RequestFrom(ctx)
	r.Surface = risk.SurfaceHosted
	return risk.WithRequest(ctx, r)
}

// screen refuses a sign-in a restriction denies, before the credential.
func (s *Service) screen(ctx context.Context, target authentication.Target, login, method string) error {
	if s.risk == nil {
		return nil
	}
	return s.risk.Screen(hostedCtx(ctx), risk.Signal{Environment: target.Environment, Login: login, Method: method})
}

// failed records a refused credential (401) as a failed attempt.
func (s *Service) failed(ctx context.Context, target authentication.Target, login, method string, err error) {
	if s.risk == nil || !unauthorized(err) {
		return
	}
	s.risk.Record(hostedCtx(ctx), risk.Signal{Environment: target.Environment, Login: login, Method: method}, risk.OutcomeFailure, risk.Decision{Action: risk.ActionNone, Detections: []string{}})
}

func (s *Service) record(ctx context.Context, sig risk.Signal, outcome string, d risk.Decision) {
	if s.risk != nil {
		s.risk.Record(hostedCtx(ctx), sig, outcome, d)
	}
}

// challengeAsked reports whether err is a pre_sign_in action's request for
// a risk challenge.
func challengeAsked(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == authentication.CodeRiskChallenge
}

// challengeDone: the inbox was proven by a risk challenge (an emailed code
// answers with "otp" but no second factor).
func challengeDone(v authentication.Verified) bool {
	return slices.Contains(v.AMR, "otp") && !authentication.HasMFA(v.AMR)
}

// assess runs the detections for a login that reached its organization.
// mfa says a second factor runs or ran. done is true when out is the
// answer (a block or a parked challenge); otherwise ctx carries the
// decision for the session and the pre_sign_in action.
func (s *Service) assess(ctx context.Context, r hosted.Request, target authentication.Target, login hosted.Login, organization identity.OrganizationID, mfaRuns bool) (context.Context, risk.Signal, risk.Decision, hosted.Result, bool, error) {
	v := login.Verified
	sig := risk.Signal{Environment: target.Environment, Organization: organization, User: v.User, Login: v.Email, Method: v.Method,
		MFA: mfaRuns, EmailProof: v.Method == authentication.MethodCode || challengeDone(v)}
	if s.risk == nil {
		d := risk.Decision{Action: risk.ActionNone, Detections: []string{}, Off: true}
		return risk.WithDecision(ctx, d), sig, d, hosted.Result{}, false, nil
	}
	ctx = hostedCtx(ctx)
	// The account's own address: email domain restrictions hold for
	// usernames, passkeys and federation too (a failed read is "").
	account, _ := s.authenticator.Account(ctx, target.Environment, v.User)
	sig.Email = account.Email
	d := s.risk.Assess(ctx, sig)
	d.Challenged = challengeDone(v)
	if d.Action == risk.ActionChallenge {
		d = d.Resolve(sig.MFA, sig.EmailProof, true)
		if d.Challenge() {
			d = d.Resolve(false, false, s.second != nil && account.EmailVerified && account.Email != "")
		}
	}
	if v.Method == authentication.MethodPasskey && d.SatisfiedBy == "mfa" {
		d.SatisfiedBy = "passkey"
	}
	if d.Block() {
		s.risk.Record(ctx, sig, risk.OutcomeBlocked, d)
		_ = s.repository.DeleteLogin(ctx, s.secrets.Hash(r.Ticket))
		return ctx, sig, d, hosted.Result{}, true, risk.ErrSignInBlocked()
	}
	if d.Challenge() {
		out, ok, err := s.challenge(ctx, r, target, login, sig, d)
		if err != nil || ok {
			return ctx, sig, d, out, true, err
		}
		d.SatisfiedBy = "unverifiable"
	}
	return risk.WithDecision(ctx, d), sig, d, hosted.Result{}, false, nil
}

// challenge parks the login until the code emailed to the user's verified
// address. ok is false only when none can be asked (no verified address or
// no sender: the sign-in then goes on). A code that could not be sent — a
// cooldown, the hourly cap, a delivery failure — never lets the sign-in
// through: it stays parked and the page offers to send the code again.
func (s *Service) challenge(ctx context.Context, r hosted.Request, target authentication.Target, login hosted.Login, sig risk.Signal, d risk.Decision) (hosted.Result, bool, error) {
	if s.second == nil {
		return hosted.Result{}, false, nil
	}
	result := hosted.Result{SecondFactor: true, Factors: []string{mfa.KindEmail}, RiskChallenge: true}
	sent, err := s.second.SendRisk(ctx, target.Boundary(login.Chosen), login.Verified.User)
	switch {
	case cannotChallenge(err):
		return hosted.Result{}, false, nil
	case err != nil:
		slog.WarnContext(ctx, "risk challenge code not sent; the sign-in stays parked", "err", err)
	default:
		result.Sent = &sent
	}
	login.RiskChallenge, login.RiskDetections = true, d.Detections
	if err = s.park(ctx, r, target, login); err != nil {
		return hosted.Result{}, false, err
	}
	d.Action = risk.Stronger(d.Action, risk.ActionChallenge)
	s.record(ctx, sig, risk.OutcomeChallenged, d)
	return result, true, nil
}

// cannotChallenge reports whether err says no risk challenge can be asked of
// the account (authentication.ErrChallengeUnavailable).
func cannotChallenge(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == authentication.CodeChallengeUnavailable
}
