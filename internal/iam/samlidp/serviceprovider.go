// Package samlidp makes IAMKit a SAML 2.0 identity provider for
// applications: service providers (SaaS tools and other SAML applications)
// registered per environment send an AuthnRequest to
// /saml/:environment/sso, the user signs in on the hosted pages, and the
// browser posts a signed response to the provider's assertion consumer
// service.
package samlidp

import (
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// NameID formats: the user's email address or their stable user ID.
const (
	NameIDEmail      = "email"
	NameIDPersistent = "persistent"
)

// Attribute sources a service provider may receive.
const (
	SourceEmail        = "email"
	SourceName         = "name"
	SourceUserID       = "user_id"
	SourceOrganization = "organization_id"
	SourcePermissions  = "permissions"
)

var sources = map[string]bool{SourceEmail: true, SourceName: true, SourceUserID: true, SourceOrganization: true, SourcePermissions: true}

// Audit actions.
const (
	ActionCreate = "saml_service_provider.create"
	ActionUpdate = "saml_service_provider.update"
	ActionDelete = "saml_service_provider.delete"
	// ActionAssertion is recorded (actor = the user) whenever a response
	// is sent to a service provider.
	ActionAssertion = "saml.assertion_issued"
)

// TicketPrefix starts the hosted-login ticket of a SAML sign-in; the
// hosted pages tell it apart from an OAuth authorization ticket by it
// (federation's ik_saml_ handles are parked SP-side assertions).
const TicketPrefix = "ik_samlreq_"

// RequestTTL bounds the time between the AuthnRequest and the response.
const RequestTTL = 10 * time.Minute

// Limits.
const (
	maxEntityID   = 1024
	maxACS        = 10
	maxAttributes = 32
	maxName       = 200
	// MaxRelayState is the longest RelayState kept (the specification
	// asks for 80 bytes; some providers send more).
	MaxRelayState = 1024
)

// ServiceProvider is a registered SAML application.
type ServiceProvider struct {
	ID              identity.ServiceProviderID `json:"id"`
	Environment     identity.EnvironmentID     `json:"environment_id"`
	Name            string                     `json:"name"`
	Application     identity.ApplicationID     `json:"application_id"`
	ApplicationName string                     `json:"application_name"`
	Resource        identity.ResourceID        `json:"resource_id"`
	ResourceName    string                     `json:"resource_name"`
	EntityID        string                     `json:"entity_id"`
	ACSURLs         []string                   `json:"acs_urls"`
	NameIDFormat    string                     `json:"name_id_format"`
	// Attributes maps SAML attribute names to sources.
	Attributes map[string]string `json:"attributes"`
	CreatedAt  time.Time         `json:"created_at"`
}

// Create registers a service provider.
type Create struct {
	Name         string                 `json:"name"`
	Application  identity.ApplicationID `json:"application_id"`
	Resource     identity.ResourceID    `json:"resource_id"`
	EntityID     string                 `json:"entity_id"`
	ACSURLs      []string               `json:"acs_urls"`
	NameIDFormat string                 `json:"name_id_format"`
	Attributes   map[string]string      `json:"attributes"`
}

// WithDefaults fills the NameID format and an empty attribute map.
func (c Create) WithDefaults() Create {
	if c.NameIDFormat == "" {
		c.NameIDFormat = NameIDEmail
	}
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	c.Name = strings.TrimSpace(c.Name)
	c.EntityID = strings.TrimSpace(c.EntityID)
	return c
}

func (c Create) Validate() error {
	if err := validName(c.Name); err != nil {
		return err
	}
	if c.Application.IsZero() {
		return errx.Validation("application_id must be a valid UUID")
	}
	if c.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if err := ValidateEntityID(c.EntityID); err != nil {
		return err
	}
	if err := ValidateACS(c.ACSURLs); err != nil {
		return err
	}
	if c.NameIDFormat != "" {
		if err := validNameID(c.NameIDFormat); err != nil {
			return err
		}
	}
	return ValidateAttributes(c.Attributes)
}

// Update changes a service provider; nil fields stay unchanged. The entity
// ID and the application/resource pair are fixed.
type Update struct {
	Name         *string            `json:"name"`
	ACSURLs      *[]string          `json:"acs_urls"`
	NameIDFormat *string            `json:"name_id_format"`
	Attributes   *map[string]string `json:"attributes"`
}

func (u Update) Validate() error {
	if u.Name == nil && u.ACSURLs == nil && u.NameIDFormat == nil && u.Attributes == nil {
		return errx.Validation("name, acs_urls, name_id_format or attributes is required")
	}
	if u.Name != nil {
		if err := validName(strings.TrimSpace(*u.Name)); err != nil {
			return err
		}
	}
	if u.ACSURLs != nil {
		if err := ValidateACS(*u.ACSURLs); err != nil {
			return err
		}
	}
	if u.NameIDFormat != nil {
		if err := validNameID(*u.NameIDFormat); err != nil {
			return err
		}
	}
	if u.Attributes != nil {
		return ValidateAttributes(*u.Attributes)
	}
	return nil
}

func validName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > maxName {
		return errx.Validation("name is required (at most 200 characters)")
	}
	return nil
}

func validNameID(format string) error {
	if format != NameIDEmail && format != NameIDPersistent {
		return errx.Validation("name_id_format must be email or persistent")
	}
	return nil
}

// ValidateEntityID accepts an absolute URI (a URL or a URN) without spaces.
func ValidateEntityID(entity string) error {
	u, err := url.Parse(entity)
	if entity == "" || len(entity) > maxEntityID || err != nil || u.Scheme == "" || strings.ContainsAny(entity, " \t\r\n") {
		return errx.Validation("entity_id must be an absolute URI (at most 1024 characters)")
	}
	return nil
}

// ValidateACS checks the assertion consumer service URLs: one to ten
// absolute HTTPS URLs, without duplicates.
func ValidateACS(urls []string) error {
	if len(urls) == 0 || len(urls) > maxACS {
		return errx.Validation("acs_urls needs one to ten URLs")
	}
	seen := map[string]bool{}
	for _, v := range urls {
		if seen[v] {
			return errx.Validation("acs_urls must not repeat a URL")
		}
		seen[v] = true
	}
	if err := identity.ValidateHTTPS(urls); err != nil {
		return errx.Validation("acs_urls must be absolute HTTPS URLs without credentials or fragments")
	}
	return nil
}

// ValidateAttributes checks the attribute mapping.
func ValidateAttributes(attributes map[string]string) error {
	if len(attributes) > maxAttributes {
		return errx.Validation("attributes may map at most 32 names")
	}
	for name, source := range attributes {
		if strings.TrimSpace(name) == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n") {
			return errx.Validation("attribute names must be 1 to 256 characters")
		}
		if !sources[source] {
			return errx.Validation("attribute sources are email, name, user_id, organization_id or permissions")
		}
	}
	return nil
}

// Mutation is an audited change.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// IdentityProvider is what an operator configures in a service provider.
type IdentityProvider struct {
	EntityID    string `json:"entity_id"`
	SSOURL      string `json:"sso_url"`
	MetadataURL string `json:"metadata_url"`
	// Certificate is the signing certificate (PEM); it changes when the
	// environment's signing key is rotated.
	Certificate string `json:"certificate"`
}

// Message is an AuthnRequest as the browser brought it: deflated in the
// query string (HTTP-Redirect) or base64 in a form (HTTP-POST).
type Message struct {
	Redirect    bool
	SAMLRequest string
	RelayState  string
}

// Request is a checked AuthnRequest: its ID, the service provider that sent
// it and the registered ACS URL the response goes to.
type Request struct {
	ID              string
	ServiceProvider identity.ServiceProviderID
	ACSURL          string
	RelayState      string
}

// Pending is a stored request waiting for the hosted sign-in.
type Pending struct {
	Request
	Environment identity.EnvironmentID
	Binding     []byte
}

// Login is the session the hosted sign-in completed.
type Login struct {
	User         identity.UserID
	Organization identity.OrganizationID
	Session      identity.SessionID
	Permissions  []string
}

// Subject is the signed-in user as the assertion names them.
type Subject struct {
	Email string
	Name  string
}

// Attribute is one assertion attribute.
type Attribute struct {
	Name   string
	Values []string
}

// Assertion is what the response asserts about the user.
type Assertion struct {
	NameID       string
	NameIDFormat string
	Session      identity.SessionID
	Attributes   []Attribute
}

// Assert builds the assertion content for a login.
func (sp ServiceProvider) Assert(login Login, subject Subject) Assertion {
	out := Assertion{NameID: subject.Email, NameIDFormat: NameIDEmail, Session: login.Session, Attributes: []Attribute{}}
	if sp.NameIDFormat == NameIDPersistent {
		out.NameID, out.NameIDFormat = login.User.String(), NameIDPersistent
	}
	for _, name := range slices.Sorted(maps.Keys(sp.Attributes)) {
		var values []string
		switch sp.Attributes[name] {
		case SourceEmail:
			values = []string{subject.Email}
		case SourceName:
			values = []string{subject.Name}
		case SourceUserID:
			values = []string{login.User.String()}
		case SourceOrganization:
			if !login.Organization.IsZero() {
				values = []string{login.Organization.String()}
			}
		case SourcePermissions:
			values = append([]string{}, login.Permissions...)
		}
		// An attribute without values (no organization chosen, no
		// permissions) is left out.
		if len(values) == 0 {
			continue
		}
		out.Attributes = append(out.Attributes, Attribute{Name: name, Values: values})
	}
	return out
}

// Response is the POST-binding form the browser submits to the ACS.
type Response struct {
	Environment  identity.EnvironmentID
	ACSURL       string
	SAMLResponse string
	RelayState   string
}

// Filter narrows the service provider list.
type Filter struct {
	Application identity.ApplicationID
}
