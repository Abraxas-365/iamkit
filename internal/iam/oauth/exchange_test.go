package oauth

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func exchangeCode(err error) string {
	if e, ok := err.(*errx.Error); ok {
		return e.Code
	}
	return ""
}

func TestExchangeValidate(t *testing.T) {
	client := &Client{Environment: identity.NewEnvironmentID(), Application: identity.NewApplicationID()}
	subject := authentication.Token{
		Access:    identity.Access{EnvironmentID: client.Environment, OrganizationID: identity.NewOrganizationID(), ApplicationID: client.Application},
		Purpose:   "application",
		SessionID: identity.NewSessionID(),
		Subject:   identity.NewUserID(),
	}
	if err := (Exchange{Subject: subject, Audience: "https://api"}).Validate(client); err != nil {
		t.Fatalf("valid exchange: %v", err)
	}
	cases := map[string]struct {
		mutate func(*Exchange)
		code   string
	}{
		"no audience":     {func(e *Exchange) { e.Audience = " " }, ExchangeInvalidTarget},
		"machine token":   {func(e *Exchange) { e.Subject.Purpose = "machine" }, ExchangeInvalidRequest},
		"no session":      {func(e *Exchange) { e.Subject.SessionID = identity.SessionID{} }, ExchangeInvalidRequest},
		"operator actor":  {func(e *Exchange) { e.Subject.ActorID = identity.NewOperatorID() }, ExchangeInvalidRequest},
		"account actor":   {func(e *Exchange) { e.Subject.ActorAccount = identity.NewAccountID() }, ExchangeInvalidRequest},
		"other app":       {func(e *Exchange) { e.Subject.ApplicationID = identity.NewApplicationID() }, ExchangeInvalidRequest},
		"other env":       {func(e *Exchange) { e.Subject.EnvironmentID = identity.NewEnvironmentID() }, ExchangeInvalidRequest},
		"no organization": {func(e *Exchange) { e.Subject.OrganizationID = identity.OrganizationID{} }, ExchangeInvalidRequest},
	}
	for name, c := range cases {
		e := Exchange{Subject: subject, Audience: "https://api"}
		c.mutate(&e)
		err := e.Validate(client)
		if got := exchangeCode(err); got != c.code {
			t.Errorf("%s: code %q (%v), want %q", name, got, err, c.code)
		}
	}
}

func TestImpersonationValidate(t *testing.T) {
	ok := Impersonation{Account: identity.NewAccountID(), User: identity.NewUserID(), Organization: identity.NewOrganizationID(), Reason: "support ticket 1234"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid impersonation: %v", err)
	}
	for name, mutate := range map[string]func(*Impersonation){
		"no user":         func(i *Impersonation) { i.User = identity.UserID{} },
		"no organization": func(i *Impersonation) { i.Organization = identity.OrganizationID{} },
		"short reason":    func(i *Impersonation) { i.Reason = "   short   " },
	} {
		i := ok
		mutate(&i)
		if got := exchangeCode(i.Validate()); got != ExchangeInvalidRequest {
			t.Errorf("%s: code %q", name, got)
		}
	}
}

func TestExchangeClientAndGrants(t *testing.T) {
	if err := ValidateGrantTypes([]string{GrantTokenExchange}, false); err != nil {
		t.Errorf("token exchange alone: %v", err)
	}
	if err := ValidateExchangeClient([]string{GrantTokenExchange}, true); err == nil {
		t.Error("public client allowed token exchange")
	}
	if err := ValidateExchangeClient([]string{GrantAuthorizationCode}, true); err != nil {
		t.Errorf("public code client: %v", err)
	}
}

func TestExchangeSessionToken(t *testing.T) {
	s := ExchangeSession{Environment: identity.NewEnvironmentID(), User: identity.NewUserID(), ActorAccount: identity.NewAccountID(), Session: identity.NewSessionID(), Organization: identity.NewOrganizationID(), Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), Permissions: []string{"a:read"}}
	tok := s.Token()
	if tok.Purpose != "application" || tok.SessionID != s.Session || tok.Subject != s.User || tok.ResourceID != s.Resource || !tok.Impersonated() || tok.AuthTime != 0 {
		t.Fatalf("token: %+v", tok)
	}
}
