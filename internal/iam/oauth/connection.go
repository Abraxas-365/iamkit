package oauth

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ParamConnection is the authorize parameter that names the federation
// connection to sign in with (third-party initiated login, WorkOS-style
// connection_id). It is stored with the authorization like the
// organization hint; the sign-in pages start that connection directly when
// it is usable by the client, and ignore it otherwise.
const ParamConnection = "connection_id"

// ConnectionHint reads the connection an authorize request form names
// (zero when none). A malformed ID is a validation error.
func ConnectionHint(form url.Values) (identity.ConnectionID, error) {
	raw := form.Get(ParamConnection)
	if raw == "" {
		return identity.ConnectionID{}, nil
	}
	id, err := identity.ParseConnectionID(raw)
	if err != nil {
		return identity.ConnectionID{}, errx.Validation("connection_id must be a connection ID")
	}
	return id, nil
}

// FormConnection is the connection hint of a stored authorize form (zero
// when none or unreadable: the form was checked when the authorization
// started).
func FormConnection(form string) identity.ConnectionID {
	values, err := url.ParseQuery(form)
	if err != nil {
		return identity.ConnectionID{}
	}
	out, _ := ConnectionHint(values)
	return out
}
