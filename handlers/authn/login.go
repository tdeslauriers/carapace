package authn

import "net/http"

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginHandler struct {
	
}

func handleAuthentication(w http.ResponseWriter, r *http.Request) {

}
