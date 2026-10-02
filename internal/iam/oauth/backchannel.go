package oauth

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// BackchannelLogoutEvent is the events member of an OpenID Connect
// Back-Channel Logout token.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// Audit action of a logout notification given up on (actor: the user whose
// session ended; target: the client).
const ActionBackchannelFailed = "oauth.backchannel_failed"

// Delivery states of a logout notification.
const (
	LogoutPending   = "pending"
	LogoutDelivered = "delivered"
	LogoutFailed    = "failed"
)

// Retry policy: the first retry after LogoutRetryBase, doubling up to
// LogoutRetryMax; the notification is given up after LogoutMaxAttempts.
const (
	LogoutRetryBase   = 30 * time.Second
	LogoutRetryMax    = time.Hour
	LogoutMaxAttempts = 8
)

// ValidateBackchannelURI accepts empty (no back-channel logout) or an
// absolute HTTPS URL without credentials or fragment.
func ValidateBackchannelURI(uri string) error {
	if uri == "" {
		return nil
	}
	if identity.ValidateHTTPS([]string{uri}) != nil {
		return errx.Validation("backchannel_logout_uri must be an absolute HTTPS URL without credentials or fragment")
	}
	return nil
}

// LogoutNotification is one claimed outbox row: a session of Subject that
// ended and the client to tell. URI is the client's current
// backchannel_logout_uri (empty when it was removed or the client disabled).
type LogoutNotification struct {
	ID          int64
	Environment identity.EnvironmentID
	Client      identity.ClientID
	Session     identity.SessionID
	Subject     identity.UserID
	// Attempts counts this one.
	Attempts int
	URI      string
}

// RetryAfter is when the next attempt of a notification that failed its
// attempts-th try is due; ok is false once it is given up.
func RetryAfter(attempts int) (time.Duration, bool) {
	if attempts >= LogoutMaxAttempts {
		return 0, false
	}
	wait := LogoutRetryBase
	for i := 1; i < attempts && wait < LogoutRetryMax; i++ {
		wait *= 2
	}
	return min(wait, LogoutRetryMax), true
}

// LogoutFilter narrows the logout delivery list; zero fields match all.
type LogoutFilter struct {
	Status string
	Client identity.ClientID
}

// Validate accepts an empty or known status.
func (f LogoutFilter) Validate() error {
	switch f.Status {
	case "", LogoutPending, LogoutDelivered, LogoutFailed:
		return nil
	}
	return errx.Validation("status must be pending, delivered or failed")
}

// LogoutDelivery is a logout notification as operators see it.
type LogoutDelivery struct {
	ID              int64                  `json:"id,string" db:"id"`
	Client          identity.ClientID      `json:"client_id" db:"client_id"`
	ApplicationName string                 `json:"application_name" db:"application_name"`
	Session         identity.SessionID     `json:"session_id" db:"session_id"`
	User            identity.UserID        `json:"user_id" db:"subject"`
	UserEmail       string                 `json:"user_email" db:"user_email"`
	Status          string                 `json:"status" db:"status"`
	Attempts        int                    `json:"attempts" db:"attempts"`
	LastError       string                 `json:"last_error" db:"last_error"`
	Created         time.Time              `json:"created_at" db:"created_at"`
	NextAttempt     *time.Time             `json:"next_attempt_at" db:"next_attempt_at"`
	Delivered       *time.Time             `json:"delivered_at" db:"delivered_at"`
	Failed          *time.Time             `json:"failed_at" db:"failed_at"`
	Environment     identity.EnvironmentID `json:"-" db:"environment_id"`
}
