package risksvc

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Owner: W1 (risk backend). Sign-in evaluation: Screen (restrictions,
// before any credential), Assess (detections, after the first factor) and
// Record (the attempt log, alerts). Every internal error fails open: the
// sign-in continues and Deps.OnError counts it. Only an explicit
// deny restriction (or a block detection) refuses.

// enabled reports whether the risk_signals feature applies to the
// environment (a lookup failure keeps it on: the flag is a kill switch).
func (s *Service) enabled(ctx context.Context, environment identity.EnvironmentID) bool {
	if s.features == nil {
		return true
	}
	on, err := s.features.Enabled(ctx, environment, config.FeatureRiskSignals)
	if err != nil {
		slog.WarnContext(ctx, "risk feature lookup failed", "environment", environment, "err", err)
		return true
	}
	return on
}

func (s *Service) failOpen(ctx context.Context, stage string, err error) {
	if s.onError != nil {
		s.onError(ctx, stage)
	}
	slog.WarnContext(ctx, "risk evaluation failed open", "stage", stage, "err", err)
}

// where is what is known about the client of the request.
type where struct {
	ip, agent, country string
	loc                risk.Location
}

func (s *Service) locate(ctx context.Context) where {
	info := identity.ClientInfoFrom(ctx)
	w := where{ip: info.IP, agent: info.UserAgent, country: info.Country}
	if s.geo != nil {
		if loc, ok := s.geo.Locate(info.IP, info.Country); ok {
			w.loc = loc
			if loc.Country != "" {
				w.country = loc.Country
			}
		}
	}
	return w
}

func (s *Service) hashLogin(environment identity.EnvironmentID, login string) []byte {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" || s.keys == nil {
		return nil
	}
	return s.keys.Hash(environment, "login", login)
}

func (s *Service) hashDevice(ctx context.Context, environment identity.EnvironmentID) []byte {
	device := risk.RequestFrom(ctx).Device
	if device == "" || s.keys == nil {
		return nil
	}
	return s.keys.Hash(environment, "device", device)
}

func emailOf(login string) string {
	login = strings.TrimSpace(login)
	if strings.Contains(login, "@") {
		return strings.ToLower(login)
	}
	return ""
}

// Screen applies the restrictions (and a blocking ip_velocity) before any
// credential is checked. A refusal is recorded and answered the same for
// known and unknown accounts.
func (s *Service) Screen(ctx context.Context, signal risk.Signal) error {
	if s.policies == nil || !s.enabled(ctx, signal.Environment) {
		return nil
	}
	w := s.locate(ctx)
	restrictions, err := s.policies.Restrictions(ctx, signal.Environment, risk.RestrictionFilter{})
	if err != nil {
		s.failOpen(ctx, "screen", err)
		return nil
	}
	denied, allowed, _ := risk.Decide(restrictions, risk.Subject{IP: w.ip, Country: w.country, Email: emailOf(signal.Login)})
	if denied {
		s.record(ctx, signal, w, risk.OutcomeBlocked, risk.ReasonRestriction, risk.Decision{Action: risk.ActionNone, Detections: []string{}})
		return risk.ErrSignInBlocked()
	}
	if allowed || signal.Method == risk.MethodSignup || s.attempts == nil {
		return nil
	}
	policy, err := s.policy(ctx, signal.Environment)
	if err != nil {
		s.failOpen(ctx, "screen", err)
		return nil
	}
	if policy.Action(risk.IPVelocity) != risk.ActionBlock || w.ip == "" {
		return nil
	}
	counts, err := s.attempts.Counts(ctx, signal.Environment, nil, w.ip, s.now().Add(-time.Hour))
	if err != nil {
		s.failOpen(ctx, "screen", err)
		return nil
	}
	if velocity(policy, counts) {
		s.record(ctx, signal, w, risk.OutcomeBlocked, risk.ReasonDetection,
			risk.Decision{Action: risk.ActionBlock, Detections: []string{risk.IPVelocity}, Counts: counts})
		return risk.ErrSignInBlocked()
	}
	return nil
}

func velocity(policy risk.Policy, c risk.Counts) bool {
	t := policy.Thresholds
	return (t.IPFailuresPerHour > 0 && c.IPFailures1h >= t.IPFailuresPerHour) ||
		(t.IPDistinctLoginsPerHour > 0 && c.IPDistinctLogins1h >= t.IPDistinctLoginsPerHour)
}

// savedOrDefault is the saved policy or the default.
func (s *Service) savedOrDefault(ctx context.Context, environment identity.EnvironmentID) (risk.Policy, error) {
	p, err := s.policies.Policy(ctx, environment)
	if err != nil {
		if isNotFound(err) {
			return risk.DefaultPolicy(environment), nil
		}
		return risk.Policy{}, err
	}
	return p, nil
}

func (s *Service) policy(ctx context.Context, environment identity.EnvironmentID) (risk.Policy, error) {
	return s.savedOrDefault(ctx, environment)
}

// Assess runs the detections of the policy for an identified user.
func (s *Service) Assess(ctx context.Context, signal risk.Signal) risk.Decision {
	w := s.locate(ctx)
	d := risk.Decision{Action: risk.ActionNone, Detections: []string{}, Country: w.country, Off: true}
	if s.policies == nil || s.attempts == nil || !s.enabled(ctx, signal.Environment) {
		return d
	}
	d.Off = false
	restrictions, rerr := s.policies.Restrictions(ctx, signal.Environment, risk.RestrictionFilter{})
	if rerr != nil {
		s.failOpen(ctx, "assess", rerr)
	}
	email := emailOf(signal.Login)
	if account := emailOf(signal.Email); account != "" {
		email = account
		// Screen saw only what was typed: an email domain deny also holds
		// for the account behind a username, passkey, code or federation.
		if denied, _, _ := risk.Decide(restrictions, risk.Subject{Email: account}); denied {
			d.Action, d.Restricted = risk.ActionBlock, true
			return d
		}
	}
	policy, err := s.policy(ctx, signal.Environment)
	if err != nil {
		s.failOpen(ctx, "assess", err)
		return d
	}
	d.BlockIfUnverifiable = policy.BlockIfUnverifiable
	hash := s.hashDevice(ctx, signal.Environment)
	if len(hash) > 0 && !signal.User.IsZero() {
		known, err := s.attempts.KnownDevice(ctx, signal.Environment, signal.User, hash)
		if err != nil {
			s.failOpen(ctx, "assess", err)
		}
		d.DeviceKnown = known
	}
	if !policy.Active() {
		return d
	}
	// An allow restriction skips every detection (denies were screened).
	allows := slices.DeleteFunc(slices.Clone(restrictions), func(r risk.Restriction) bool { return r.Action != risk.Allow })
	if _, allowed, _ := risk.Decide(allows, risk.Subject{IP: w.ip, Country: w.country, Email: email}); allowed {
		d.Allowed = true
		return d
	}
	now := s.now()
	fire := func(detection string) {
		action := policy.Action(detection)
		d.Detections = append(d.Detections, detection)
		d.Action = risk.Stronger(d.Action, action)
		if action == risk.ActionNotify && policy.NotifyUser {
			d.Notify = append(d.Notify, detection)
		}
	}
	if policy.Action(risk.IPVelocity) != risk.ActionOff || policy.Action(risk.UserBruteForce) != risk.ActionOff {
		counts, err := s.attempts.Counts(ctx, signal.Environment, s.hashLogin(signal.Environment, signal.Login), w.ip, now.Add(-time.Hour))
		if err != nil {
			s.failOpen(ctx, "assess", err)
		} else {
			d.Counts = counts
			if policy.Action(risk.IPVelocity) != risk.ActionOff && velocity(policy, counts) {
				fire(risk.IPVelocity)
			}
			if t := policy.Thresholds.UserFailuresPerHour; policy.Action(risk.UserBruteForce) != risk.ActionOff && t > 0 && counts.UserFailures1h >= t {
				fire(risk.UserBruteForce)
			}
		}
	}
	if policy.Action(risk.ImpossibleTravel) != risk.ActionOff && w.loc.Located() && !signal.User.IsZero() {
		last, found, err := s.attempts.LastLocated(ctx, signal.Environment, signal.User)
		if err != nil {
			s.failOpen(ctx, "assess", err)
		} else if found && risk.Traveled(last, w.loc, now, float64(policy.Thresholds.TravelSpeedKmh), config.ImpossibleTravelMinKm) {
			fire(risk.ImpossibleTravel)
		}
	}
	if policy.Action(risk.NewDevice) != risk.ActionOff && len(hash) > 0 && !d.DeviceKnown && !signal.User.IsZero() {
		fire(risk.NewDevice)
	}
	if policy.Action(risk.StaleAccount) != risk.ActionOff && !signal.User.IsZero() {
		last, err := s.attempts.LastSignedIn(ctx, signal.Environment, signal.User)
		if err != nil {
			s.failOpen(ctx, "assess", err)
		} else if days := policy.Thresholds.StaleAfterDays; last != nil && days > 0 && now.Sub(*last) > time.Duration(days)*24*time.Hour {
			fire(risk.StaleAccount)
		}
	}
	return d
}

// Record writes the attempt of a finished (or parked) sign-in and sends the
// alerts of notify detections after a success. It never fails the sign-in.
func (s *Service) Record(ctx context.Context, signal risk.Signal, outcome string, decision risk.Decision) {
	if s.attempts == nil || !s.enabled(ctx, signal.Environment) {
		return
	}
	w := s.locate(ctx)
	if outcome == risk.OutcomeSuccess && len(decision.Notify) > 0 {
		s.alert(ctx, signal, w, decision)
	}
	reason := ""
	if outcome == risk.OutcomeBlocked {
		reason = risk.ReasonDetection
		if decision.Restricted {
			reason = risk.ReasonRestriction
		}
	}
	s.record(ctx, signal, w, outcome, reason, decision)
}

func (s *Service) record(ctx context.Context, signal risk.Signal, w where, outcome, reason string, d risk.Decision) {
	if s.attempts == nil {
		return
	}
	if d.Detections == nil {
		d.Detections = []string{}
	}
	if d.Action == "" {
		d.Action = risk.ActionNone
	}
	req := risk.RequestFrom(ctx)
	a := risk.Attempt{ID: identity.NewSignInAttemptID(), Environment: signal.Environment, IP: w.ip, UserAgent: w.agent, Country: w.country,
		Latitude: w.loc.Latitude, Longitude: w.loc.Longitude, Method: signal.Method, Surface: req.Surface,
		Outcome: outcome, Reason: reason, Detections: d.Detections, Action: d.Action, Captcha: req.Captcha, CreatedAt: s.now()}
	if !signal.User.IsZero() {
		u := signal.User
		a.User = &u
	}
	if !signal.Organization.IsZero() {
		o := signal.Organization
		a.Organization = &o
	}
	if a.Method == "" {
		a.Method = "unknown"
	}
	// A write must outlive a canceled request: the sign-in has answered.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.ExternalHTTPTimeout)
	defer cancel()
	if err := s.attempts.Record(wctx, a, s.hashLogin(signal.Environment, signal.Login), s.hashDevice(ctx, signal.Environment)); err != nil {
		s.failOpen(ctx, "record", err)
	}
}

// alert emails the user once per detection per config.SecurityAlertInterval
// (the latest attempt that carried the detection is the memory).
func (s *Service) alert(ctx context.Context, signal risk.Signal, w where, d risk.Decision) {
	if s.notifier == nil || signal.User.IsZero() {
		return
	}
	now := s.now()
	for _, detection := range d.Notify {
		page, err := s.attempts.Attempts(ctx, signal.Environment, risk.AttemptFilter{User: &signal.User, Detection: detection, Limit: 1})
		if err != nil {
			s.failOpen(ctx, "alert", err)
			continue
		}
		if len(page) > 0 && now.Sub(page[0].CreatedAt) < config.SecurityAlertInterval {
			continue
		}
		if err := s.notifier.Alert(ctx, risk.Alert{Environment: signal.Environment, User: signal.User, Detection: detection,
			IP: w.ip, Country: w.country, UserAgent: w.agent, At: now}); err != nil {
			s.failOpen(ctx, "alert", err)
		}
	}
}
