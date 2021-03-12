package auth

import (
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	passwordRuleRegex string
	userNameRuleRegex string
	UsersByID         map[string]*User
	userIDsByUserName map[string]*string
}

func NewAuthHandler() *AuthHandler {
	authH := new(AuthHandler)
	authH.passwordRuleRegex = ""
	authH.userNameRuleRegex = ""
	authH.UsersByID = make(map[string]*User)
	authH.userIDsByUserName = make(map[string]*string)

	return authH
}

// GetUserByUserName : Get user struct by user name
func (a *AuthHandler) GetUserByUserName(userName string) (user *User, error error) {

	if userID, userIDFound := a.userIDsByUserName[userName]; userIDFound {
		user = a.UsersByID[*userID]
		if user == nil {
			error = LogNewError("Error : No user found for ID : '" + *userID + "' !")
		}
	} else {
		error = LogNewError("Error : No user found for UserName : '" + userName + "' !")
	}

	return user, error

}

// TODO : from here --> continue with User and password rule

// func (a *AuthHandler) AddUserRule(regex string) {
// 	a.userNameRuleRegex = regex
// }
//
// func (a *AuthHandler) AddPasswordRule(regex string) {
// 	a.passwordRuleRegex = regex
// }
//
// // check if username parameter is a valid username
// func (a *AuthHandler) CheckUserNameRule(username string) (successful bool, error string) {
// 	return a.CheckRegexRule(a.userNameRuleRegex, username, "UserName")
// }
//
// // check if password parameter is a valid password
// func (a *AuthHandler) CheckPasswordRule(password string) (successful bool, error string) {
// 	return a.CheckRegexRule(a.passwordRuleRegex, password, "Password")
// }
//
// // Check if a value is matching a given regular expression
// func (a *AuthHandler) CheckRegexRule(regex string, value string, nameOfRule string) (successful bool, error string) {
//
// 	// try to match value string againts regex
// 	matched, err := regexp.MatchString(regex, value)
//
// 	// check if regex is a valid regular expression
// 	if err != nil {
// 		print("1\n")
// 		successful = false
// 		error = "Error : Cannot apply invalid regex rule for " + nameOfRule + " : " + err.Error()
// 		// check if value matched with regex
// 	} else if matched {
// 		print("2\n")
// 		successful = true
// 		error = ""
// 		// check if value does not match with regex
// 	} else {
// 		print("3\n" + regex + "xxx" + value)
// 		successful = false
// 		error = "Error : " + nameOfRule + " does not comply to rules. Please make sure it fits to the following regular expression : " + regex
// 	}
//
// 	return successful, error
// }

// TODO : to here --> continue with User and password rule

// CheckIfUserNameIsFree : check if user name is not used yet
func (a *AuthHandler) CheckIfUserNameIsFree(userName string) (successful bool, error error) {
	// try to get user by user name
	user, _ := a.GetUserByUserName(userName)

	// if user was not found everything is fine
	// otherwise return error
	if user == nil {
		successful = true
		error = nil
	} else {
		successful = false
		error = LogNewError("Error : Username '" + userName + "' already used. Please choose a different Username!")
	}

	return successful, error
}

// PreSignUpCheck : Do pre checks to verify if user can be created
func (a *AuthHandler) PreSignUpCheck(userName string, password string) (successful bool, error error) {

	// check if user name or password is not empty
	if len(userName) > 0 && len(password) > 0 {
		successful = true
		error = nil
	} else {
		successful = false
		error = LogNewError("Error : Please enter a valid username and password!")
	}

	// TODO : from here --> continue with User and password rule
	// if successful {
	// 	successful, error = a.CheckUserNameRule(username)
	// }
	//
	// if successful {
	// 	successful, error = a.CheckPasswordRule(password)
	// }
	// TODO : to here --> continue with User and password rule

	if successful {
		successful, error = a.CheckIfUserNameIsFree(userName)
	}

	return successful, error
}

// CreateNewUser : Create a new user and add it to the User maps
func (a *AuthHandler) CreateNewUser(userName string, password string) (successful bool, error error) {
	var user User

	// set ID and UserName
	user.ID = uuid.New().String()
	user.UserName = userName

	// hash and set password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err == nil {
		user.HashedPassword = string(hashedPassword)
		successful = true
		error = nil
	} else {
		successful = false
		error = LogNewError("Error : Unable to hash password for user '" + userName + "' !")
	}

	// add new user to user maps
	if successful {
		a.UsersByID[user.ID] = &user
		a.userIDsByUserName[user.UserName] = &user.ID
	}

	return successful, error
}

// SignUp : sign up / register a new user
func (a *AuthHandler) SignUp(userName string, password string) (successful bool, error error) {

	successful, error = a.PreSignUpCheck(userName, password)
	if successful {
		successful, error = a.CreateNewUser(userName, password)
	}

	return successful, error
}

// PreLogInCheck : Do pre checks to verify if login can be performed
func (a *AuthHandler) PreLogInCheck(userName string, password string) (successful bool, error error) {

	// check if user name or password is not empty
	if len(userName) > 0 && len(password) > 0 {
		successful = true
		error = nil
	} else {
		successful = false
		error = LogNewError("Error : Please enter a valid username and password!")
	}

	return successful, error
}

func (a *AuthHandler) Authenticate(userName string, password string) (successful bool, error error) {
	// try to get user by user name
	user, _ := a.GetUserByUserName(userName)

	// if user is existing try to validate the password
	// if not exit with error
	if user != nil {
		comparisonError := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
		if comparisonError == nil {
			successful = true
			error = nil
		} else {
			successful = false
			error = LogNewError("Error : Please enter a valid username and password!")
		}
	} else {
		successful = false
		error = LogNewError("Error : Please enter a valid username and password!")
	}

	return successful, error
}

func (a *AuthHandler) LogIn(userName string, password string) (successful bool, error error) {

	successful, error = a.PreLogInCheck(userName, password)
	if successful {
		successful, error = a.Authenticate(userName, password)
	}

	return successful, error
}
