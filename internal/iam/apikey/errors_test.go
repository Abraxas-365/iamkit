package apikey

import "errors"

func errAs(err error, target any) bool { return errors.As(err, target) }
