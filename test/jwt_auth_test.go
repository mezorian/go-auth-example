package main

import (
	"os"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
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

	// login and after this JWT authenticate
	for _, testCaseValue := range testCaseValues {
		// login
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// authenticate
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

	// login and after this JWT authenticate
	for _, testCaseValue := range testCaseValues {
		// login
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// authenticate
		success, error = authH.AuthenticateByJWT("RandomStringWhichIsNoRealJWT")
		assert.Equal(t, success, false)
		assert.Equal(t, error.Error(), "Error : Authentication Failed. JWT AccessToken is not valid!")
	}
}

func TestAuthWithJWTIsNotSuccessfulForTheorecticalValidJWTWhichIsNotAssignedToUser(t *testing.T) {
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

	// login and after this JWT authenticate
	for _, testCaseValue := range testCaseValues {
		// login
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)

		// generate theoretically valid JWT
		secret := os.Getenv("SECRET")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"UserName": "UserIWantToHack",
			"Test":     "Hello World",
		})

		hackedToken, _ := token.SignedString([]byte(secret))

		// try to authenticate with theoretically valid JWT
		// --> this will fail
		success, error = authH.AuthenticateByJWT(hackedToken)
		assert.Equal(t, success, false)
		assert.Equal(t, error.Error(), "Error : Authentication Failed. JWT AccessToken is not valid!")
	}
}
