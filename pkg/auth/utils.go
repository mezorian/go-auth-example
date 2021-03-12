package auth

import (
	"errors"

	log "github.com/sirupsen/logrus"
)

// create and return a new error object and while
// doing this writing the error message to the log
func LogNewError(errorMessage string) error {
	log.Error(errorMessage)
	return errors.New(errorMessage)
}
