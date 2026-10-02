// Package actionsvc implements actions: target and execution management
// and the Runner flows call at their conditions.
package actionsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository action.Repository
	caller     action.Caller
	cipher     action.Cipher
	secrets    action.Secrets
	features   action.Features
	breaker    *action.Breaker
	now        func() time.Time
	// background runs async targets (tests make it synchronous).
	background func(func())
	usage      action.Usage
	cache      cache.Store
}

// SetUsage limits and counts target calls per environment.
func (s *Service) SetUsage(u action.Usage) { s.usage = u }

// SetCache keeps the targets bound to each condition in store (nil: read
// the database on every flow).
func (s *Service) SetCache(store cache.Store) { s.cache = store }

func boundKey(environment identity.EnvironmentID, condition string) string {
	return "action:" + environment.String() + ":" + condition
}

// bound reads the targets bound to condition, through the cache.
func (s *Service) bound(ctx context.Context, environment identity.EnvironmentID, condition string) ([]action.Bound, error) {
	return cache.Read(ctx, s.cache, boundKey(environment, condition), config.CacheTTL, func() ([]action.Bound, error) {
		return s.repository.Bound(ctx, environment, condition)
	})
}

// forget drops the environment's cached bindings: a target change reaches
// every condition it is bound to.
func (s *Service) forget(ctx context.Context, environment identity.EnvironmentID) {
	if s.cache == nil {
		return
	}
	keys := make([]string, len(action.Conditions))
	for i, c := range action.Conditions {
		keys[i] = boundKey(environment, c.Name)
	}
	cache.Forget(ctx, s.cache, keys...)
}

var (
	_ action.Commands = (*Service)(nil)
	_ action.Queries  = (*Service)(nil)
	_ action.Runner   = (*Service)(nil)
)

// New builds the service; features may be nil (actions always on).
func New(repository action.Repository, caller action.Caller, cipher action.Cipher, secrets action.Secrets, features action.Features) *Service {
	return &Service{repository: repository, caller: caller, cipher: cipher, secrets: secrets, features: features,
		breaker: &action.Breaker{}, now: time.Now, background: func(f func()) { go f() }}
}

func (s *Service) newSecret() (plain, sealed string, err error) {
	plain, err = s.secrets.Generate()
	if err != nil {
		return "", "", err
	}
	sealed, err = s.cipher.Seal([]byte(plain))
	return plain, sealed, err
}

func (s *Service) CreateTarget(ctx context.Context, m action.Mutation, input action.TargetCreate) (action.TargetSecret, error) {
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return action.TargetSecret{}, err
	}
	n, err := s.repository.CountTargets(ctx, m.Environment)
	if err != nil {
		return action.TargetSecret{}, err
	}
	if n >= action.MaxTargets {
		return action.TargetSecret{}, errx.Business("an environment can have at most 20 action targets")
	}
	plain, sealed, err := s.newSecret()
	if err != nil {
		return action.TargetSecret{}, err
	}
	target := action.Target{ID: identity.NewTargetID(), Environment: m.Environment, Name: input.Name, URL: input.URL,
		Kind: input.Kind, TimeoutMS: input.TimeoutMS, InterruptOnError: input.InterruptOnError}
	m.Target = target.ID.String()
	if err = s.repository.CreateTarget(ctx, m, target, sealed); err != nil {
		return action.TargetSecret{}, err
	}
	return action.TargetSecret{ID: target.ID, Secret: plain}, nil
}

func (s *Service) UpdateTarget(ctx context.Context, m action.Mutation, id identity.TargetID, input action.TargetUpdate) (action.Target, error) {
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return action.Target{}, err
	}
	current, err := s.FindTarget(ctx, m.Environment, id)
	if err != nil {
		return action.Target{}, err
	}
	next, err := input.Apply(current)
	if err != nil {
		return action.Target{}, err
	}
	m.Target = id.String()
	if err = s.repository.UpdateTarget(ctx, m, next); err != nil {
		return action.Target{}, err
	}
	s.forget(ctx, m.Environment)
	return s.repository.FindTarget(ctx, m.Environment, id)
}

func (s *Service) DeleteTarget(ctx context.Context, m action.Mutation, id identity.TargetID) error {
	if id.IsZero() {
		return errx.NotFound("action target not found")
	}
	m.Target = id.String()
	if err := s.repository.DeleteTarget(ctx, m, id); err != nil {
		return err
	}
	s.forget(ctx, m.Environment)
	return nil
}

func (s *Service) RotateTargetSecret(ctx context.Context, m action.Mutation, id identity.TargetID) (action.TargetSecret, error) {
	if id.IsZero() {
		return action.TargetSecret{}, errx.NotFound("action target not found")
	}
	plain, sealed, err := s.newSecret()
	if err != nil {
		return action.TargetSecret{}, err
	}
	m.Target = id.String()
	if err = s.repository.RotateTargetSecret(ctx, m, id, sealed, s.now().Add(config.EventWebhookSecretOverlap)); err != nil {
		return action.TargetSecret{}, err
	}
	s.forget(ctx, m.Environment)
	return action.TargetSecret{ID: id, Secret: plain}, nil
}

func (s *Service) SetExecution(ctx context.Context, m action.Mutation, condition string, input action.ExecutionSet) (action.Execution, error) {
	if _, ok := action.FindCondition(condition); !ok {
		return action.Execution{}, action.ErrUnknownCondition()
	}
	if err := input.Validate(); err != nil {
		return action.Execution{}, err
	}
	m.Target = condition
	out, err := s.repository.SetExecution(ctx, m, condition, input.Targets)
	if err == nil {
		cache.Forget(ctx, s.cache, boundKey(m.Environment, condition))
	}
	return out, err
}

func (s *Service) DeleteExecution(ctx context.Context, m action.Mutation, condition string) error {
	if _, ok := action.FindCondition(condition); !ok {
		return action.ErrUnknownCondition()
	}
	m.Target = condition
	if err := s.repository.DeleteExecution(ctx, m, condition); err != nil {
		return err
	}
	cache.Forget(ctx, s.cache, boundKey(m.Environment, condition))
	return nil
}

func (s *Service) PruneCalls(ctx context.Context) error {
	return s.repository.PruneCalls(ctx, s.now().Add(-config.ActionCallRetention))
}

func (s *Service) ListTargets(ctx context.Context, environment identity.EnvironmentID) ([]action.Target, error) {
	return s.repository.ListTargets(ctx, environment)
}

func (s *Service) FindTarget(ctx context.Context, environment identity.EnvironmentID, id identity.TargetID) (action.Target, error) {
	if id.IsZero() {
		return action.Target{}, errx.NotFound("action target not found")
	}
	return s.repository.FindTarget(ctx, environment, id)
}

func (s *Service) ListExecutions(ctx context.Context, environment identity.EnvironmentID) ([]action.Execution, error) {
	return s.repository.ListExecutions(ctx, environment)
}

func (s *Service) ListCalls(ctx context.Context, environment identity.EnvironmentID, filter action.CallFilter, limit int) ([]action.Call, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	return s.repository.ListCalls(ctx, environment, filter, limit)
}

// TestTarget calls the target with the sample input, checks the answer
// like a real call of the condition and logs it; nothing is applied.
func (s *Service) TestTarget(ctx context.Context, environment identity.EnvironmentID, id identity.TargetID, input action.Test) (action.TestResult, error) {
	if err := input.Validate(); err != nil {
		return action.TestResult{}, err
	}
	if id.IsZero() {
		return action.TestResult{}, errx.NotFound("action target not found")
	}
	target, sealed, err := s.repository.TargetSecrets(ctx, environment, id)
	if err != nil {
		return action.TestResult{}, err
	}
	condition, _ := action.FindCondition(input.Condition)
	in := input.Input
	in.Condition, in.Environment = input.Condition, environment
	call, response := s.call(ctx, action.Bound{Target: target, Sealed: sealed}, condition, in)
	s.record(ctx, call)
	return action.TestResult{Outcome: call.Outcome, Status: call.Status, DurationMS: call.DurationMS, Error: call.Error, Response: response}, nil
}

// Run calls the condition's targets in order and merges their answers.
// A denial stops at once (ErrDenied); a failing target stops the flow
// only with interrupt_on_error (ErrFailed), else it is skipped. Async
// targets are sent in the background and never change the result.
func (s *Service) Run(ctx context.Context, environment identity.EnvironmentID, name string, build func() action.Input) (action.Result, error) {
	condition, ok := action.FindCondition(name)
	if !ok {
		return action.Result{}, errx.Internal("unknown action condition " + name)
	}
	targets, err := s.bound(ctx, environment, name)
	if err != nil || len(targets) == 0 {
		return action.Result{}, err
	}
	if s.features != nil {
		on, err := s.features.Enabled(ctx, environment, config.FeatureActions)
		if err != nil {
			return action.Result{}, err
		}
		if !on {
			return action.Result{}, nil
		}
	}
	input := build()
	input.Condition, input.Environment = name, environment
	var result action.Result
	for _, target := range targets {
		if target.Kind == action.KindAsync {
			detached := context.WithoutCancel(ctx)
			s.background(func() {
				call, _ := s.call(detached, target, condition, input)
				s.record(detached, call)
			})
			continue
		}
		call, response := s.call(ctx, target, condition, input)
		s.record(ctx, call)
		switch call.Outcome {
		case action.OutcomeDenied:
			return action.Result{}, action.ErrDenied(response.DenyMessage())
		case action.OutcomeOK:
			if target.Kind == action.KindCall {
				result.Merge(response)
			}
		default:
			if target.InterruptOnError {
				return action.Result{}, action.ErrFailed()
			}
		}
	}
	return result, nil
}

// call sends one hook and classifies its answer.
func (s *Service) call(ctx context.Context, target action.Bound, condition action.Condition, input action.Input) (action.Call, action.Response) {
	call := action.Call{Environment: target.Environment, Target: target.ID, Condition: condition.Name, Interrupted: target.InterruptOnError}
	start := s.now()
	if !s.breaker.Allow(target.ID, start) {
		call.Outcome, call.Error = action.OutcomeSkipped, "circuit open after repeated failures"
		return call, action.Response{}
	}
	if s.usage != nil {
		if err := s.usage.Admit(ctx, target.Environment, usage.LimitActionCalls); err != nil {
			call.Outcome, call.Error = action.OutcomeSkipped, "the environment reached its action_calls_per_minute limit"
			return call, action.Response{}
		}
		s.usage.Count(ctx, target.Environment, usage.MetricActionCalls, 1)
	}
	var response action.Response
	fail := func(reason string) (action.Call, action.Response) {
		call.Outcome, call.Error = action.OutcomeFailed, reason
		s.breaker.Record(target.ID, false, s.now())
		return call, action.Response{}
	}
	secrets := make([]string, 0, len(target.Sealed))
	for _, sealed := range target.Sealed {
		plain, err := s.cipher.Open(sealed)
		if err != nil {
			return fail("the target secret cannot be opened")
		}
		secrets = append(secrets, string(plain))
	}
	body, err := json.Marshal(input)
	if err != nil {
		return fail("encode input")
	}
	answer := s.caller.Call(ctx, action.Outbound{ID: messageID(), URL: target.URL, Secrets: secrets, Timeout: target.Timeout(), Body: body})
	call.DurationMS = int(s.now().Sub(start) / time.Millisecond)
	if answer.Status != 0 {
		status := answer.Status
		call.Status = &status
	}
	if !answer.OK() {
		if answer.Error != "" {
			return fail(answer.Error)
		}
		return fail("endpoint answered " + strconv.Itoa(answer.Status))
	}
	if target.Kind == action.KindCall && len(strings.TrimSpace(string(answer.Body))) > 0 {
		if err := json.Unmarshal(answer.Body, &response); err != nil {
			return fail("the response is not a JSON object")
		}
		if err := response.Check(condition); err != nil {
			reason := "invalid response"
			var e *errx.Error
			if errx.As(err, &e) {
				reason += ": " + e.Message
			}
			return fail(reason)
		}
	}
	s.breaker.Record(target.ID, true, s.now())
	call.Outcome = action.OutcomeOK
	if response.Deny {
		call.Outcome = action.OutcomeDenied
	}
	return call, response
}

// record logs a call; the log is best effort and never fails the flow.
func (s *Service) record(ctx context.Context, call action.Call) {
	if err := s.repository.RecordCall(ctx, call); err != nil {
		slog.WarnContext(ctx, "action call not logged", "target", call.Target.String(), "err", err)
	}
}

func messageID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "act_" + hex.EncodeToString(b)
}
