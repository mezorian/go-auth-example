package main

import (
	"testing"

	"github.com/mezorian/go-auth-example/pkg/auth"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Test Event for correct attribute setting

func TestSignUpReturnsFalseAndErrorMessageForEmptyInputValues(t *testing.T) {
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
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, false)
		assert.Equal(t, error.Error(), "Error : Please enter a valid username and password!")
	}
}

func TestSignUpReturnsTrueAndNoErrorMessageForValidInputValues(t *testing.T) {
	testCaseValues := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"peter", "supersecret"},
		{"anna", "password"},
	}

	for _, testCaseValue := range testCaseValues {
		authH := auth.NewAuthHandler()
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
	}
}

func TestSignUpCreatesNewUserInAuthHandler(t *testing.T) {
	testCaseValues := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"peter", "supersecret"},
		{"anna", "password"},
	}

	for _, testCaseValue := range testCaseValues {
		authH := auth.NewAuthHandler()
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
		user, error := authH.GetUserByUserName(testCaseValue.username)
		assert.NotEqual(t, user, nil)
		assert.Equal(t, error, nil)
		assert.Equal(t, user.UserName, testCaseValue.username)
		err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(testCaseValue.password))
		assert.Equal(t, err, nil)
	}
}

func TestSignUpDoesNotAllowTwoTimesTheSameUserName(t *testing.T) {
	testCaseValues := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"peter", "supersecret"},
		{"anna", "password"},
	}

	for _, testCaseValue := range testCaseValues {
		authH := auth.NewAuthHandler()
		// do first sign up (which is successful)
		success, error := authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, true)
		assert.Equal(t, error, nil)
		user, error := authH.GetUserByUserName(testCaseValue.username)
		assert.NotEqual(t, user, nil)
		assert.Equal(t, error, nil)
		assert.Equal(t, user.UserName, testCaseValue.username)
		err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(testCaseValue.password))
		assert.Equal(t, err, nil)
		// do second sign up (which fails)
		success, error = authH.SignUp(testCaseValue.username, testCaseValue.password)
		assert.Equal(t, success, false)
		assert.Equal(t, error.Error(), "Error : Username '"+testCaseValue.username+"' already used. Please choose a different Username!")
	}
}
