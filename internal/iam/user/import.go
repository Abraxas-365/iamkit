package user

import "github.com/Abraxas-365/iamkit/internal/identity"

// MaxImportRows is the most users one Import call takes.
const MaxImportRows = 100

// ImportRequest is the body of the import routes.
type ImportRequest struct {
	Users []Create `json:"users"`
}

// ImportResult answers Import: one entry per row, in request order.
type ImportResult struct {
	Results []ImportRowResult `json:"results"`
	Created int               `json:"created"`
	Failed  int               `json:"failed"`
}

// ImportRowResult is the outcome of one row: the new user's id, or the
// error that refused it (Code is the errx code, e.g. CONFLICT).
type ImportRowResult struct {
	Index int              `json:"index"`
	ID    *identity.UserID `json:"id,omitempty"`
	Error *ImportRowError  `json:"error,omitempty"`
}

// ImportRowError is why a row failed.
type ImportRowError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
