package main

import (
	"testing"

	"github.com/mezorian/go-auth-example/pkg/auth"
	"github.com/stretchr/testify/assert"
)

// Test Event for correct attribute setting

func TestLoginUpReturnsFalseAndErrorMessageForEmptyInputValues(t *testing.T) {
	testCaseValues := []struct {
		username string
		password string
	}{
		{"", ""},
		{"peter", ""},
		{"", "password"},
	}

	for _, testCaseValue := range testCaseValues {
		authH := auth.NewAuthHandler()
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, false, success)
		assert.Equal(t, "Error : Please enter a valid username and password!", error.Error())
	}
}

func TestLoginUpReturnsFalseForNonExistingUsers(t *testing.T) {
	testCaseValues := []struct {
		username string
		password string
	}{
		{"anna", "password"},
		{"peter", "password"},
		{"melanie", "password"},
	}

	for _, testCaseValue := range testCaseValues {
		authH := auth.NewAuthHandler()
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, false, success)
		assert.Equal(t, "Error : Please enter a valid username and password!", error.Error())
	}
}

func TestLoginOnlySuccesfulForCorrectPasswords(t *testing.T) {
	testCaseValues := []struct {
		username        string
		correctPassword string
		wrongPassword   string
	}{
		{"anna", "hello world", "hello  world"},
		{"peter", "i am a password", "password"},
		{"melanie", "superS3cre1P0ssw8rd", "admin"},
	}
	authH := auth.NewAuthHandler()

	for _, testCaseValue := range testCaseValues {
		// sign up new user
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.correctPassword)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// try to login with wrong password --> this will fail
		success, error = authH.LogIn(testCaseValue.username, testCaseValue.wrongPassword)
		assert.Equal(t, false, success)
		assert.Equal(t, "Error : Please enter a valid username and password!", error.Error())

		// try to login with correct password --> this will be successful
		success, error = authH.LogIn(testCaseValue.username, testCaseValue.correctPassword)
		assert.Equal(t, true, success)
		assert.Equal(t, nil, error)
	}
}
