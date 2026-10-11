package risk

import (
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Detections.
const (
	// IPVelocity: many failed sign-ins, or many distinct logins tried,
	// from one IP address within an hour.
	IPVelocity = "ip_velocity"
	// UserBruteForce: many failed sign-ins on one login within an hour,
	// from any address.
	UserBruteForce = "user_brute_force"
	// ImpossibleTravel: the previous successful sign-in was too far away
	// for the time between them (needs GeoIP City data).
	ImpossibleTravel = "impossible_travel"
	// NewDevice: a device the user never signed in from (needs a device
	// id: the hosted cookie or a headless device_id).
	NewDevice = "new_device"
	// StaleAccount: the user has not signed in for StaleAfterDays.
	StaleAccount = "stale_account"
)

// Detections lists every detection, in display order.
var Detections = []string{IPVelocity, UserBruteForce, ImpossibleTravel, NewDevice, StaleAccount}

// Actions a detection may take, weakest first. None is "nothing detected".
const (
	ActionNone      = "none"
	ActionOff       = "off"
	ActionLog       = "log"
	ActionNotify    = "notify"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

// Weight orders actions: the strongest detection decides.
func Weight(action string) int {
	switch action {
	case ActionLog:
		return 1
	case ActionNotify:
		return 2
	case ActionChallenge:
		return 3
	case ActionBlock:
		return 4
	}
	return 0
}

// Stronger returns the stronger of two actions.
func Stronger(a, b string) string {
	if Weight(b) > Weight(a) {
		return b
	}
	return a
}

// AllowedActions are the actions each detection may be set to: notify only
// where the user can tell (new_device, stale_account), block not there —
// they describe the legitimate user, not an attacker.
func AllowedActions(detection string) []string {
	switch detection {
	case NewDevice, StaleAccount:
		return []string{ActionOff, ActionLog, ActionNotify, ActionChallenge}
	}
	return []string{ActionOff, ActionLog, ActionChallenge, ActionBlock}
}

// Policy is an environment's risk policy. The zero policy (no row) has
// every detection off.
type Policy struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	// Actions maps each detection to its action (every detection present).
	Actions    map[string]string `json:"actions"`
	Thresholds Thresholds        `json:"thresholds"`
	// NotifyUser sends the security_alert email for detections whose
	// action is notify.
	NotifyUser bool `json:"notify_user"`
	// BlockIfUnverifiable blocks, instead of logging, a challenge the user
	// cannot answer (no verified email).
	BlockIfUnverifiable bool `json:"block_if_unverifiable"`
	// Saved is false for the default policy (no row stored).
	Saved     bool       `json:"saved"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// Thresholds tune the detections.
type Thresholds struct {
	IPFailuresPerHour       int `json:"ip_failures_per_hour"`
	IPDistinctLoginsPerHour int `json:"ip_distinct_logins_per_hour"`
	UserFailuresPerHour     int `json:"user_failures_per_hour"`
	StaleAfterDays          int `json:"stale_after_days"`
	TravelSpeedKmh          int `json:"travel_speed_kmh"`
}

// DefaultThresholds are the thresholds of a new policy.
func DefaultThresholds() Thresholds {
	return Thresholds{IPFailuresPerHour: 20, IPDistinctLoginsPerHour: 10, UserFailuresPerHour: 10, StaleAfterDays: 60, TravelSpeedKmh: 1000}
}

// DefaultPolicy is the policy of an environment without a saved one:
// every detection off.
func DefaultPolicy(environment identity.EnvironmentID) Policy {
	actions := make(map[string]string, len(Detections))
	for _, d := range Detections {
		actions[d] = ActionOff
	}
	return Policy{Environment: environment, Actions: actions, Thresholds: DefaultThresholds(), NotifyUser: true}
}

// Action is what detection does under the policy (off when unset).
func (p Policy) Action(detection string) string {
	if a, ok := p.Actions[detection]; ok && a != "" {
		return a
	}
	return ActionOff
}

// Active reports whether any detection is on.
func (p Policy) Active() bool {
	for _, d := range Detections {
		if p.Action(d) != ActionOff {
			return true
		}
	}
	return false
}

// PolicyInput sets the policy (PUT). Omitted detections are off, omitted
// thresholds their default, NotifyUser nil = true.
type PolicyInput struct {
	Actions             map[string]string `json:"actions"`
	Thresholds          *Thresholds       `json:"thresholds,omitempty"`
	NotifyUser          *bool             `json:"notify_user,omitempty"`
	BlockIfUnverifiable bool              `json:"block_if_unverifiable"`
}

// Policy returns the policy the input describes.
func (in PolicyInput) Policy(environment identity.EnvironmentID) Policy {
	p := DefaultPolicy(environment)
	for d, a := range in.Actions {
		p.Actions[d] = a
	}
	if in.Thresholds != nil {
		t, def := *in.Thresholds, DefaultThresholds()
		if t.IPFailuresPerHour == 0 {
			t.IPFailuresPerHour = def.IPFailuresPerHour
		}
		if t.IPDistinctLoginsPerHour == 0 {
			t.IPDistinctLoginsPerHour = def.IPDistinctLoginsPerHour
		}
		if t.UserFailuresPerHour == 0 {
			t.UserFailuresPerHour = def.UserFailuresPerHour
		}
		if t.StaleAfterDays == 0 {
			t.StaleAfterDays = def.StaleAfterDays
		}
		if t.TravelSpeedKmh == 0 {
			t.TravelSpeedKmh = def.TravelSpeedKmh
		}
		p.Thresholds = t
	}
	if in.NotifyUser != nil {
		p.NotifyUser = *in.NotifyUser
	}
	p.BlockIfUnverifiable = in.BlockIfUnverifiable
	return p
}

// Validate checks the input.
func (in PolicyInput) Validate() error {
	for d, a := range in.Actions {
		if !slices.Contains(Detections, d) {
			return errx.Validation("unknown detection " + d)
		}
		if !slices.Contains(AllowedActions(d), a) {
			return errx.Validation(d + " cannot be " + a)
		}
	}
	if in.Thresholds != nil {
		t := *in.Thresholds
		switch {
		case t.IPFailuresPerHour < 0 || t.IPFailuresPerHour > 10000:
			return errx.Validation("ip_failures_per_hour must be 1 to 10000")
		case t.IPDistinctLoginsPerHour < 0 || t.IPDistinctLoginsPerHour > 10000:
			return errx.Validation("ip_distinct_logins_per_hour must be 1 to 10000")
		case t.UserFailuresPerHour < 0 || t.UserFailuresPerHour > 1000:
			return errx.Validation("user_failures_per_hour must be 1 to 1000")
		case t.StaleAfterDays != 0 && (t.StaleAfterDays < 7 || t.StaleAfterDays > 3650):
			return errx.Validation("stale_after_days must be 7 to 3650")
		case t.TravelSpeedKmh != 0 && (t.TravelSpeedKmh < 100 || t.TravelSpeedKmh > 20000):
			return errx.Validation("travel_speed_kmh must be 100 to 20000")
		}
	}
	return nil
}

// ErrGeoIPRequired refuses a setting that needs GeoIP (impossible travel,
// country restrictions) on a deployment without it.
func ErrGeoIPRequired(what string) error {
	e := errx.Business(what + " needs GeoIP (IAMKIT_GEOIP_DB or IAMKIT_GEOIP_HEADER)")
	e.Code = "GEOIP_REQUIRED"
	return e
}
