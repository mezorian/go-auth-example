package main

import (
	"os"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mezorian/go-auth-example/pkg/auth"
	"github.com/stretchr/testify/assert"
)

func setUpTestEnvironment() {
	// generate jwt
	os.Setenv("SECRET", "super_secret_example_text")
}

func TestLoginUpReturnsFalseAndErrorMessageForEmptyInputValues(t *testing.T) {
	setUpTestEnvironment()

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
	setUpTestEnvironment()

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
	setUpTestEnvironment()

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

func TestLoginDoesNotWorkWithThePasswordsOfOtherUsers(t *testing.T) {
	setUpTestEnvironment()

	testCaseValues := []struct {
		username string
		password string
	}{
		{"anna", "hello world"},
		{"peter", "i am a password"},
		{"melanie", "superS3cre1P0ssw8rd"},
	}
	authH := auth.NewAuthHandler()

	// sign up new user
	success, error := authH.SignUp("anon", "anon's password")
	assert.Equal(t, success, true)
	assert.Equal(t, error, nil)

	// sign up other users
	for _, testCaseValue := range testCaseValues {
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}

	// try to login user anon with passwords of other users
	for _, testCaseValue := range testCaseValues {
		// try to login with wrong password --> this will fail
		success, error = authH.LogIn("anon", testCaseValue.password)
		assert.Equal(t, false, success)
		assert.Equal(t, "Error : Please enter a valid username and password!", error.Error())
	}
}

func TestLoginWorksEvenIfSomeUsersHaveTheSamePasswords(t *testing.T) {
	setUpTestEnvironment()

	testCaseValues := []struct {
		username string
		password string
	}{
		{"anna", "password"},
		{"peter", "long password"},
		{"melanie", "password"},
		{"anon", "password"},
		{"john", "some other password"},
		{"peter2", "long password"},
	}
	authH := auth.NewAuthHandler()

	// sign up all users
	for _, testCaseValue := range testCaseValues {
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}

	// login all users
	for _, testCaseValue := range testCaseValues {
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, true, success)
		assert.Equal(t, nil, error)
	}
}

func TestLoginReturnsValidJWToken(t *testing.T) {
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

	for _, testCaseValue := range testCaseValues {
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}

	for _, testCaseValue := range testCaseValues {
		secret := os.Getenv("SECRET")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"UserName": testCaseValue.username,
			"Test":     "Hello World",
		})

		tokenString, _ := token.SignedString([]byte(secret))
		success, error := authH.LogIn(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
		user, _ := authH.GetUserByUserName(testCaseValue.username)
		assert.Equal(t, tokenString, user.AccessToken)
	}
}
