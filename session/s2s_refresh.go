package session

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/data"
)

// refresh table data
type Refresh struct {
	Uuid         string          `db:"uuid"`
	RefreshToken string          `db:"refresh_token"`
	ClientId     string          `db:"client_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

type RefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
}



type S2sRefreshHandler struct {
	AuthService AuthService
}

func NewS2sRefreshHandler(service AuthService) *S2sRefreshHandler {
	return &S2sRefreshHandler{
		AuthService: service,
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

	// lookup refresh
	refresh, err := h.AuthService.GetRefreshToken(cmd.RefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid refresh token: %v", err), http.StatusUnauthorized)
	}

	if refresh != nil {
		// mint new token/s2s access token
		token, err := h.AuthService.MintAuthzToken(refresh.ClientId)
		if err != nil {
			log.Printf("unable to mint new jwt for client id %v: %v", &refresh.ClientId, err)
			http.Error(w, fmt.Sprintf("unable to create new s2s token from refresh: %v", err), http.StatusBadRequest)
			return
		}

		// respond with authorization data
		authz := &S2sAuthorization{
			Jti:            token.Claims.Jti,
			ServiceToken:   token.Token,
			TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
			RefreshToken:   refresh.RefreshToken,
			RefreshExpires: data.CustomTime{Time: refresh.CreatedAt.Add(1 * time.Hour)}, //  same expiry
		}
		authzJson, err := json.Marshal(authz)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(authzJson)
	}
}
