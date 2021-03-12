package main

//"testing"

//"github.com/mezorian/go-auth-example/pkg/auth"
//"github.com/stretchr/testify/assert"

// TODO : from here --> continue with User and password rule

// Test Event for correct attribute setting

// func TestCheckingOfUserRule(t *testing.T) {
//
// 	regex := "^[a-zA-Z]{5,20}$"
// 	errorUser := "Error : Username does not comply to rules. Please make sure it fits to the following regular expression : " + regex
//
// 	var authH auth.AuthHandler
// 	authH.AddUserRule(regex)
//
// 	testCaseValues := []struct {
// 		username string
// 		success  bool
// 		error    string
// 	}{
// 		{"peter", true, ""},
// 		{"Peter", true, ""},
// 		{"PETER", true, ""},
// 		{"PeTer", true, ""},
// 		{"special$$", false, errorUser},
// 		{"bl ank", false, errorUser},
// 		{"toooooooooooomanycharacters", false, errorUser},
// 		{"numbers2", false, errorUser},
// 	}
//
// 	for _, testCaseValue := range testCaseValues {
// 		success, error := authH.CheckUserNameRule(testCaseValue.username)
// 		assert.Equal(t, success, testCaseValue.success)
// 		assert.Equal(t, error, testCaseValue.error)
// 	}
//
// }

//regexPassword := "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[*.!@$%^&(){}[]:;<>,.?/~_+-=|\\]).{8,32}$"
// TODO : to here --> continue with User and password rule
