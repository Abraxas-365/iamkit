package action

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Commands manage targets and executions.
type Commands interface {
	CreateTarget(ctx context.Context, m Mutation, input TargetCreate) (TargetSecret, error)
	UpdateTarget(ctx context.Context, m Mutation, target identity.TargetID, input TargetUpdate) (Target, error)
	DeleteTarget(ctx context.Context, m Mutation, target identity.TargetID) error
	// RotateTargetSecret issues a new secret; the previous one keeps
	// signing for config.EventWebhookSecretOverlap.
	RotateTargetSecret(ctx context.Context, m Mutation, target identity.TargetID) (TargetSecret, error)
	// TestTarget calls the target once with a sample input (logged, never
	// applied).
	TestTarget(ctx context.Context, environment identity.EnvironmentID, target identity.TargetID, input Test) (TestResult, error)
	SetExecution(ctx context.Context, m Mutation, condition string, input ExecutionSet) (Execution, error)
	DeleteExecution(ctx context.Context, m Mutation, condition string) error
	// PruneCalls deletes calls past config.ActionCallRetention (worker job).
	PruneCalls(ctx context.Context) error
}

// Queries read targets, executions and the recent-calls log.
type Queries interface {
	ListTargets(ctx context.Context, environment identity.EnvironmentID) ([]Target, error)
	FindTarget(ctx context.Context, environment identity.EnvironmentID, target identity.TargetID) (Target, error)
	ListExecutions(ctx context.Context, environment identity.EnvironmentID) ([]Execution, error)
	ListCalls(ctx context.Context, environment identity.EnvironmentID, filter CallFilter, limit int) ([]Call, error)
}

// Runner runs a condition's targets for a flow. build is called only
// when the condition has targets (and the actions feature is on), so
// flows without actions pay one lookup. A denial is ErrDenied; a failing
// interrupting target ErrFailed.
type Runner interface {
	Run(ctx context.Context, environment identity.EnvironmentID, condition string, build func() Input) (Result, error)
}

// Repository persists targets, executions and calls.
type Repository interface {
	CountTargets(ctx context.Context, environment identity.EnvironmentID) (int, error)
	CreateTarget(ctx context.Context, m Mutation, target Target, sealed string) error
	FindTarget(ctx context.Context, environment identity.EnvironmentID, target identity.TargetID) (Target, error)
	ListTargets(ctx context.Context, environment identity.EnvironmentID) ([]Target, error)
	UpdateTarget(ctx context.Context, m Mutation, target Target) error
	DeleteTarget(ctx context.Context, m Mutation, target identity.TargetID) error
	RotateTargetSecret(ctx context.Context, m Mutation, target identity.TargetID, sealed string, previousExpires time.Time) error
	// TargetSecrets are the target with its live sealed secrets (current
	// first).
	TargetSecrets(ctx context.Context, environment identity.EnvironmentID, target identity.TargetID) (Target, []string, error)
	// SetExecution stores the condition's targets; NotFound when one is not
	// a target of the environment.
	SetExecution(ctx context.Context, m Mutation, condition string, targets []identity.TargetID) (Execution, error)
	DeleteExecution(ctx context.Context, m Mutation, condition string) error
	ListExecutions(ctx context.Context, environment identity.EnvironmentID) ([]Execution, error)
	// Bound returns the targets the condition calls, in order, with their
	// live sealed secrets; none when it has no execution.
	Bound(ctx context.Context, environment identity.EnvironmentID, condition string) ([]Bound, error)
	// RecordCall logs a call; a failure also writes action.failed.
	RecordCall(ctx context.Context, call Call) error
	ListCalls(ctx context.Context, environment identity.EnvironmentID, filter CallFilter, limit int) ([]Call, error)
	PruneCalls(ctx context.Context, cutoff time.Time) error
}

// Caller posts one signed hook and reads its answer.
type Caller interface {
	Call(ctx context.Context, request Outbound) Answer
}

// Cipher seals target secrets at rest.
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

// Secrets generates target secrets (whsec_ + base64 key).
type Secrets interface {
	Generate() (string, error)
}

// Features tells whether the actions feature is on in an environment.
type Features interface {
	Enabled(ctx context.Context, environment identity.EnvironmentID, name string) (bool, error)
}

// Usage meters target calls (usage.Commands): Admit takes a slot of the
// environment's action_calls_per_minute (refused calls are skipped like an
// open breaker), Count adds made calls to today's usage.
type Usage interface {
	Admit(ctx context.Context, environment identity.EnvironmentID, limit string) error
	Count(ctx context.Context, environment identity.EnvironmentID, metric string, n int64)
}
