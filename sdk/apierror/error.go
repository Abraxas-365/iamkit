// Package apierror mirrors the public errx response without importing server internals.
package apierror

import "fmt"

type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Type       string `json:"type"`
	HTTPStatus int    `json:"http_status"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s (HTTP %d)", e.Code, e.Message, e.HTTPStatus)
}
