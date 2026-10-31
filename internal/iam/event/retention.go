package event

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Retention classes. Every event has one, fixed when it is inserted from
// the catalog below (events.retention_class, set by the trigger
// event_retention_class), so how long an event lives never depends on a
// pattern evaluated when pruning.
const (
	// ClassSecurity events are the sign-in, session, token, credential and
	// consent trail: kept for the security ceiling
	// (IAMKIT_SECURITY_EVENT_RETENTION, default one year).
	ClassSecurity = "security"
	// ClassDefault events are everything else (IAMKIT_EVENT_RETENTION).
	ClassDefault = "default"
)

// Classes lists the retention classes.
var Classes = []string{ClassSecurity, ClassDefault}

// SecurityFamilies are the event families (the part before the first dot)
// whose events are security class.
var SecurityFamilies = []string{
	"session", "sign_in", "login", "risk", "impersonation", "token", "device",
	"oauth_client", "oauth_consent", "api_key", "mfa", "identity", "signing_key", "saml",
}

// SecurityTypes are single event types of other families that are security
// class.
var SecurityTypes = []string{
	UserLocked, UserUnlocked, UserPasswordChanged, UserPasswordChangeRequired, UserSessionsRevoked,
}

// RetentionClassOf is the class of an event type: the source of truth the
// SQL function event_retention_class repeats (an architecture test keeps
// the two lists equal).
func RetentionClassOf(typ string) string {
	family, _, _ := strings.Cut(typ, ".")
	if slices.Contains(SecurityFamilies, family) || slices.Contains(SecurityTypes, typ) {
		return ClassSecurity
	}
	return ClassDefault
}

// MinRetention is the least an environment may keep events of a class
// (config.MinSecurityEventRetention).
const MinRetention = config.MinSecurityEventRetention

// Ceilings are the deployment's retention per class
// (IAMKIT_SECURITY_EVENT_RETENTION, IAMKIT_EVENT_RETENTION). An
// environment may keep events for less, never for longer.
type Ceilings struct {
	Security time.Duration
	Default  time.Duration
}

// Of is the ceiling of a class.
func (c Ceilings) Of(class string) time.Duration {
	if class == ClassSecurity {
		return c.Security
	}
	return c.Default
}

// RetentionPolicy is an environment's own retention, in seconds per class;
// nil keeps the deployment ceiling. It can only shorten.
type RetentionPolicy struct {
	SecuritySeconds *int64 `json:"security_retention_seconds"`
	DefaultSeconds  *int64 `json:"default_retention_seconds"`
}

// Seconds is the override of a class (nil: none).
func (p RetentionPolicy) Seconds(class string) *int64 {
	if class == ClassSecurity {
		return p.SecuritySeconds
	}
	return p.DefaultSeconds
}

// Validate accepts each value between MinRetention and the class's
// ceiling.
func (p RetentionPolicy) Validate(c Ceilings) error {
	for _, class := range Classes {
		v := p.Seconds(class)
		if v == nil {
			continue
		}
		ceiling := c.Of(class)
		if *v < int64(MinRetention.Seconds()) || *v > int64(ceiling.Seconds()) {
			e := errx.Business(class + "_retention_seconds must be between " + MinRetention.String() + " and the deployment ceiling of " + ceiling.String() + ", or null for the ceiling")
			e.Code = "RETENTION_OUT_OF_RANGE"
			return e
		}
	}
	return nil
}

// Effective is how long events of a class are kept: the override, never
// above the ceiling (a ceiling lowered below a stored override rules).
func (p RetentionPolicy) Effective(c Ceilings, class string) time.Duration {
	ceiling := c.Of(class)
	if v := p.Seconds(class); v != nil {
		return min(time.Duration(*v)*time.Second, ceiling)
	}
	return ceiling
}

// RetentionSeconds is a value per class, in seconds.
type RetentionSeconds struct {
	Security int64 `json:"security"`
	Default  int64 `json:"default"`
}

// Retention is what …/event-retention answers: the environment's own
// values (null: the deployment's ceiling), the deployment ceilings and the
// effective retention each class is pruned by.
type Retention struct {
	SecuritySeconds *int64           `json:"security_retention_seconds"`
	DefaultSeconds  *int64           `json:"default_retention_seconds"`
	Ceilings        RetentionSeconds `json:"ceilings"`
	Effective       RetentionSeconds `json:"effective"`
}

// Describe builds the answer for a policy under the ceilings.
func (p RetentionPolicy) Describe(c Ceilings) Retention {
	return Retention{
		SecuritySeconds: p.SecuritySeconds,
		DefaultSeconds:  p.DefaultSeconds,
		Ceilings:        RetentionSeconds{Security: int64(c.Security.Seconds()), Default: int64(c.Default.Seconds())},
		Effective: RetentionSeconds{
			Security: int64(p.Effective(c, ClassSecurity).Seconds()),
			Default:  int64(p.Effective(c, ClassDefault).Seconds()),
		},
	}
}

// EnvironmentPolicy is the stored policy of one environment, as the prune
// job reads them all.
type EnvironmentPolicy struct {
	Environment identity.EnvironmentID
	Policy      RetentionPolicy
}

// PruneBatch bounds the rows one prune statement deletes.
const PruneBatch = 5000
