package errx

import (
	"encoding/json"
	"net/http"
)

// HTTPErrorResponse represents a standard HTTP error response
type HTTPErrorResponse struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Type       string                 `json:"type"`
	Details    map[string]interface{} `json:"details,omitempty"`
	StatusCode int                    `json:"status_code"`
}

// ToHTTPResponse converts an Error to an HTTPErrorResponse
func (e *Error) ToHTTPResponse() HTTPErrorResponse {
	return HTTPErrorResponse{
		Code:       e.Code,
		Message:    e.Message,
		Type:       string(e.Type),
		Details:    e.Details,
		StatusCode: e.HTTPStatus,
	}
}

// WriteHTTP writes the error as an HTTP response
func (e *Error) WriteHTTP(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus)
	json.NewEncoder(w).Encode(e.ToHTTPResponse())
}

// HandleError is a helper to write errors to HTTP responses
func HandleError(w http.ResponseWriter, err error) {
	var customErr *Error
	if As(err, &customErr) {
		customErr.WriteHTTP(w)
		return
	}

	// Default internal server error
	internalErr := New(err.Error(), TypeInternal)
	internalErr.WriteHTTP(w)
}
