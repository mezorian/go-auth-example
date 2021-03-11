package main

import (
	"testing"

	"github.com/mezorian/go-auth-example/pkg/auth"
	"github.com/stretchr/testify/assert"
)

// Test Event for correct attribute setting

func TestSignUpDoesNotWorkForEmptyUsernameAndPassword(t *testing.T) {
	var username string = ""
	var password string = ""
	var authH auth.AuthHandler
	success, error := authH.SignUp(username, password)
	assert.Equal(t, success, false)
	assert.Equal(t, error, "Error : Please enter a valid username and password!")
}
