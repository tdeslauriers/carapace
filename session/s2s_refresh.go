package session

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// refresh table data
type Refresh struct {
	Uuid         string    `db:"uuid"`
	RefreshToken string    `db:"refresh_token"`
	ClientId     string    `db:"client_uuid"`
	CreatedAt    time.Time `db:"created_at"`
	Revoked      bool      `db:"revoked"`
}

type RefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
}

type S2sRefreshHandler struct {
	LoginService S2sLoginService
}

func NewS2sRefreshHandler(service S2sLoginService) *S2sRefreshHandler {
	return &S2sRefreshHandler{
		LoginService: service,
	}
}

func (h *S2sRefreshHandler) HandleS2sRefresh(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd RefreshCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// lookup -> replace single-use refresh
	refresh, err := h.LoginService.RefreshToken(cmd.RefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid refresh token: %v", err), http.StatusUnauthorized)
	}

	// mint new token/s2s access token
	token, err := h.LoginService.MintToken(refresh.ClientId)
	if err != nil {
		log.Printf("unable to mint new jwt for client id %s: %v", refresh.ClientId, err)
		http.Error(w, fmt.Sprintf("unable to create new s2s token from refresh: %v", err), http.StatusBadRequest)
		return
	}

	// respond with authorization data
	authz := &Authorization{
		Jti:            token.Claims.Jti,
		ServiceToken:   token.Token,
		TokenExpires:   time.Unix(token.Claims.Expires, 0),
		RefreshToken:   refresh.RefreshToken,                 // new refresh token
		RefreshExpires: refresh.CreatedAt.Add(1 * time.Hour), //  same expiry
	}
	authzJson, err := json.Marshal(authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(authzJson)
}
