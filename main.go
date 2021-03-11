package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

type Credentials struct {
	Username string
	Password string
}

var Creds []*Credentials

func main() {
	http.HandleFunc("/", Home)
	http.HandleFunc("/SignUp", SignUp)
	http.ListenAndServe(":8081", nil)
}

func Home(w http.ResponseWriter, r *http.Request) {
	render(w, "index.html")
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	log.Print("SignUP")
	c := &Credentials{}
	c.Username = r.FormValue("Username")
	c.Password = r.FormValue("Password")
	if UsernameNotYetExisting(c.Username) {
		Creds = append(Creds, c)
		render(w, "SingIn.html")
	} else {
		render(w, "ErrorSignUp.html")
	}
}

func UsernameNotYetExisting(username string) bool {
	result := true
	for _, cred := range Creds {
		log.Printf("Expected Username : %s", username)
		log.Printf("Username : %s", cred.Username)
		log.Printf("Password : %s", cred.Password)
		if cred.Username == username {
			result = false
		}
	}
	return result
}

func Validate(username string, password string) bool {
	return true
}

func render(w http.ResponseWriter, path string) {
	parsedTemplate, _ := template.ParseFiles(path)
	err := parsedTemplate.Execute(w, nil)
	if err != nil {
		fmt.Println("error parsing template: ", err)
		return
	}
}
