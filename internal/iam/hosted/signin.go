package hosted

import (
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// MaxSignInConnections bounds the connections a client lists.
const MaxSignInConnections = 50

// SignIn is which sign-in methods a hosted client offers. A client without
// stored options (Custom false) offers all of them.
//
// Password, EmailCode and OrganizationSSO start from the email form: its
// password step, the email code, and the single sign-on of the
// organization that verified the email's domain. The environment
// connections ("Continue with ...") shown are all active ones when
// AllConnections, otherwise those listed in Connections.
type SignIn struct {
	Environment     identity.EnvironmentID  `json:"environment_id"`
	Client          identity.ClientID       `json:"client_id"`
	Password        bool                    `json:"password"`
	EmailCode       bool                    `json:"email_code"`
	OrganizationSSO bool                    `json:"organization_sso"`
	AllConnections  bool                    `json:"all_connections"`
	Connections     []identity.ConnectionID `json:"connection_ids"`
	Custom          bool                    `json:"custom"`
	UpdatedAt       *time.Time              `json:"updated_at,omitempty"`
}

// DefaultSignIn offers every method.
func DefaultSignIn(environment identity.EnvironmentID, client identity.ClientID) SignIn {
	return SignIn{Environment: environment, Client: client, Password: true, EmailCode: true, OrganizationSSO: true, AllConnections: true, Connections: []identity.ConnectionID{}}
}

// Normalize drops duplicate connections and the list when all are shown.
func (s *SignIn) Normalize() {
	if s.AllConnections || s.Connections == nil {
		s.Connections = []identity.ConnectionID{}
	}
	out := make([]identity.ConnectionID, 0, len(s.Connections))
	for _, c := range s.Connections {
		if !c.IsZero() && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	s.Connections = out
}

func (s SignIn) Validate() error {
	if len(s.Connections) > MaxSignInConnections {
		return errx.Validation("connection_ids has at most 50 connections")
	}
	if !s.EmailForm() && !s.AllConnections && len(s.Connections) == 0 {
		return errx.Validation("enable at least one sign-in method")
	}
	return nil
}

// EmailForm reports whether the page asks for the email.
func (s SignIn) EmailForm() bool { return s.Password || s.EmailCode || s.OrganizationSSO }

// Shows reports whether the environment connection is offered.
func (s SignIn) Shows(connection identity.ConnectionID) bool {
	return s.AllConnections || slices.Contains(s.Connections, connection)
}

// Offered narrows the environment connections to the offered ones.
func (s SignIn) Offered(connections []federation.ConnectionSummary) []federation.ConnectionSummary {
	out := make([]federation.ConnectionSummary, 0, len(connections))
	for _, c := range connections {
		if s.Shows(c.ID) {
			out = append(out, c)
		}
	}
	return out
}

// ErrMethodUnavailable is returned for a sign-in method the client does not
// offer.
func ErrMethodUnavailable() error {
	e := errx.Forbidden("this sign-in method is not available for this application")
	e.Code = "SIGN_IN_METHOD_UNAVAILABLE"
	return e
}
