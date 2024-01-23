package session

import (
	"encoding/json"
	"fmt"
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

	// look up refresh
	refresh, err := h.LoginService.RefreshToken(cmd.RefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid refresh token: %v", err), http.StatusUnauthorized)
	}

}
