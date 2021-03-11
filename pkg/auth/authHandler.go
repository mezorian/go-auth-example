package auth

type AuthHandler struct {
}

// SignUp / register a new user
func (a *AuthHandler) SignUp(username string, password string) (bool, string) {
	return false, "Error : Please enter a valid username and password!"
}
