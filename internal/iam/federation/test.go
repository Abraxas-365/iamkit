package federation

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// TestPrefix starts the one-time ticket that begins a test sign-in
// (ik_fedtest_): only its hash is stored, bound to one environment and
// connection, valid for config.FederationTestTTL.
const TestPrefix = "ik_fedtest_"

// MaxTestGroups bounds the groups a test result page lists.
const MaxTestGroups = 50

// MaxTestAttributes bounds the attribute names a test result lists.
const MaxTestAttributes = 100

// TestTicket is what asking for a test connection returns: the URL to open
// in a new browser tab (it carries the ticket) and when it stops working.
type TestTicket struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TestLink is what the interstitial of a test connection link carries: the
// path's environment and connection and the ticket of its query, none of
// them checked against the database (opening the link spends nothing).
type TestLink struct {
	Environment identity.EnvironmentID
	Connection  identity.ConnectionID
	Ticket      string
}

// TestResult is the outcome of a test sign-in, rendered as a page and
// recorded as the connection.tested event. It never carries secrets, and
// producing it creates no session, user, link or action run.
type TestResult struct {
	Environment    identity.EnvironmentID
	Connection     identity.ConnectionID
	Organization   identity.OrganizationID
	ConnectionName string
	Provider       string
	Success        bool
	// Error says why the test failed (an errx message, never a secret).
	Error string
	// What the identity provider sent, after the connection's attribute
	// mapping: the values a real sign-in would use.
	Subject       string
	Email         string
	EmailVerified string
	DisplayName   string
	Groups        []string
	// Attributes names the attributes a SAML assertion carried (names
	// only); NameIDFormat is its subject's format.
	Attributes   []string
	NameIDFormat string
}
