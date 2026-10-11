package risksvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Owner: W1 (risk backend). Policy, restrictions, status and the attempt
// log reads.

func (s *Service) geoStatus() risk.GeoStatus {
	if s.geo == nil {
		return risk.GeoStatus{Source: risk.GeoNone}
	}
	return s.geo.Status()
}

func (s *Service) SavePolicy(ctx context.Context, m risk.Mutation, input risk.PolicyInput) (risk.Policy, error) {
	if m.Environment.IsZero() {
		return risk.Policy{}, errx.Validation("environment is required")
	}
	if err := input.Validate(); err != nil {
		return risk.Policy{}, err
	}
	policy := input.Policy(m.Environment)
	if policy.Action(risk.ImpossibleTravel) != risk.ActionOff && !s.geoStatus().Travel {
		return risk.Policy{}, risk.ErrGeoIPRequired("impossible_travel")
	}
	m.Action, m.Target = risk.ActionPolicyUpdate, m.Environment.String()
	if err := s.policies.SavePolicy(ctx, m, policy); err != nil {
		return risk.Policy{}, err
	}
	return s.policies.Policy(ctx, m.Environment)
}

func (s *Service) DeletePolicy(ctx context.Context, m risk.Mutation) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment is required")
	}
	m.Action, m.Target = risk.ActionPolicyDelete, m.Environment.String()
	return s.policies.DeletePolicy(ctx, m)
}

func (s *Service) CreateRestriction(ctx context.Context, m risk.Mutation, input risk.NewRestriction) (risk.Restriction, error) {
	if m.Environment.IsZero() {
		return risk.Restriction{}, errx.Validation("environment is required")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return risk.Restriction{}, err
	}
	if input.Kind == risk.RestrictCountry && !s.geoStatus().Countries {
		return risk.Restriction{}, risk.ErrGeoIPRequired("a country restriction")
	}
	r := risk.Restriction{ID: identity.NewRestrictionID(), Environment: m.Environment, Kind: input.Kind, Value: input.Value,
		Action: input.Action, Note: input.Note, CreatedAt: s.now()}
	m.Action, m.Target = risk.ActionRestrictionCreate, r.ID.String()
	if err := s.policies.CreateRestriction(ctx, m, r); err != nil {
		return risk.Restriction{}, err
	}
	// The stored row carries the database's clock.
	list, err := s.policies.Restrictions(ctx, m.Environment, risk.RestrictionFilter{Kind: r.Kind})
	if err == nil {
		for _, x := range list {
			if x.ID == r.ID {
				return x, nil
			}
		}
	}
	return r, nil
}

func (s *Service) DeleteRestriction(ctx context.Context, m risk.Mutation, restriction identity.RestrictionID) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment is required")
	}
	m.Action, m.Target = risk.ActionRestrictionDelete, restriction.String()
	return s.policies.DeleteRestriction(ctx, m, restriction)
}

func (s *Service) Policy(ctx context.Context, environment identity.EnvironmentID) (risk.Policy, error) {
	return s.savedOrDefault(ctx, environment)
}

func (s *Service) Restrictions(ctx context.Context, environment identity.EnvironmentID, filter risk.RestrictionFilter) ([]risk.Restriction, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	return s.policies.Restrictions(ctx, environment, filter)
}

func (s *Service) Status(ctx context.Context, environment identity.EnvironmentID) (risk.Status, error) {
	out := risk.Status{GeoIP: s.geoStatus(), Captcha: true, RiskSignals: true}
	if s.features != nil {
		if on, err := s.features.Enabled(ctx, environment, config.FeatureCaptcha); err == nil {
			out.Captcha = on
		}
		if on, err := s.features.Enabled(ctx, environment, config.FeatureRiskSignals); err == nil {
			out.RiskSignals = on
		}
	}
	return out, nil
}

// Prune deletes the attempts older than the retention.
func (s *Service) Prune(ctx context.Context) (int, error) {
	return s.attempts.Prune(ctx, s.now().Add(-s.retention))
}

func (s *Service) Attempts(ctx context.Context, environment identity.EnvironmentID, filter risk.AttemptFilter) (risk.AttemptPage, error) {
	if err := filter.Validate(); err != nil {
		return risk.AttemptPage{}, err
	}
	limit := risk.AttemptLimit(filter.Limit)
	filter.Limit = limit + 1
	rows, err := s.attempts.Attempts(ctx, environment, filter)
	if err != nil {
		return risk.AttemptPage{}, err
	}
	page := risk.AttemptPage{Items: rows}
	if len(rows) > limit {
		page.Items = rows[:limit]
		next := rows[limit-1].ID
		page.Next = &next
	}
	if page.Items == nil {
		page.Items = []risk.Attempt{}
	}
	return page, nil
}

func (s *Service) Attempt(ctx context.Context, environment identity.EnvironmentID, attempt identity.SignInAttemptID) (risk.Attempt, error) {
	return s.attempts.Attempt(ctx, environment, attempt)
}

func (s *Service) Devices(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) ([]risk.Device, error) {
	out, err := s.attempts.Devices(ctx, environment, user)
	if out == nil && err == nil {
		out = []risk.Device{}
	}
	return out, err
}
