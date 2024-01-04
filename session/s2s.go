package session

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/data"
)

type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type S2sClientData struct {
	Uuid           string    `db:"uuid"`
	Password       string    `db:"password"`
	Name           string    `db:"name"`
	Owner          string    `db:"owner"`
	CreatedAt      time.Time `db:"created_at"`
	Enabled        bool      `db:"enabled"`
	AccountExpired bool      `db:"acccount_expired"`
	AccountLocked  bool      `db:"account_locked"`
}

// s2s login service
type LoginService interface {
	ValidateCredentials(creds S2sLoginCmd) (bool, error)
}

type S2sLoginService struct {
	Sql data.SqlDbConnector
}

func NewS2SLoginService(sql data.SqlDbConnector) *S2sLoginService {
	return &S2sLoginService{
		Sql: sql,
	}
}

func (s *S2sLoginService) ValidateCredentials(creds S2sLoginCmd) (bool, error) {

}

// s2s login handler
type S2sLoginHandler struct {
	Service LoginService
}

func NewS2sLoginHandler(service LoginService) *S2sLoginHandler {
	return &S2sLoginHandler{
		Service: service,
	}
}

func (h *S2sLoginHandler) HandleS2sLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd S2sLoginCmd
	err := json.NewDecoder(r.Body).Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// valid, err := h.Service.ValidateCredentials(cmd)
}
