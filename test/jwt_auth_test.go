package main

import (
	"testing"

	"github.com/mezorian/go-auth-example/pkg/auth"
	"github.com/stretchr/testify/assert"
)

func TestAuthWithJWTIsSuccessfulAfterLogin(t *testing.T) {
	setUpTestEnvironment()

	testCaseValues := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"peter", "supersecret"},
		{"anna", "password"},
	}
	authH := auth.NewAuthHandler()

	// sign up users
	for _, testCaseValue := range testCaseValues {
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}

	// login and after this JWT authorize
	for _, testCaseValue := range testCaseValues {
		// login
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// authorize
		user, _ := authH.GetUserByUserName(testCaseValue.username)
		success, error = authH.AuthenticateByJWT(user.AccessToken)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}
}

func TestAuthWithJWTIsNotSuccessfulWithWrongJWT(t *testing.T) {
	setUpTestEnvironment()

	testCaseValues := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"peter", "supersecret"},
		{"anna", "password"},
	}
	authH := auth.NewAuthHandler()

	// sign up users
	for _, testCaseValue := range testCaseValues {
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}

	// login and after this JWT authorize
	for _, testCaseValue := range testCaseValues {
		// login
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// authorize
		success, error = authH.AuthenticateByJWT("RandomStringWhichIsNoRealJWT")
		assert.Equal(t, success, false)
		assert.Equal(t, error.Error(), "Error : Authentication Failed. JWT AccessToken is not valid!")
	}
}
