package auth

type User struct {
	ID             string
	UserName       string
	HashedPassword string
	AccessToken    string
}
