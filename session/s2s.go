package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/tdeslauriers/carapace/data"
	"golang.org/x/crypto/bcrypt"
)

type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type S2sClientData struct {
	Uuid           string `db:"uuid"`
	Password       string `db:"password"`
	Name           string `db:"name"`
	Owner          string `db:"owner"`
	CreatedAt      string `db:"created_at"`
	Enabled        bool   `db:"enabled"`
	AccountExpired bool   `db:"acccount_expired"`
	AccountLocked  bool   `db:"account_locked"`
}

// s2s login service
type S2sLoginService interface {
	ValidateCredentials(creds S2sLoginCmd) error
}

type MariaS2sLoginService struct {
	Dao data.SqlRepository
}

func NewS2SLoginService(sql data.SqlRepository) *MariaS2sLoginService {
	return &MariaS2sLoginService{
		Dao: sql,
	}
}

func (s *MariaS2sLoginService) ValidateCredentials(creds S2sLoginCmd) error {

	var s2sClient S2sClientData
	qry := "SELECT * FROM client WHERE uuid = ?"

	if err := s.Dao.SelectRecord(qry, &s2sClient, creds.ClientId); err != nil {
		log.Panicf("unable to retrieve s2s client record: %v", err)
		return err
	}

	secret := []byte(creds.ClientSecret)
	hash := []byte(s2sClient.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		return err
	}

	if !s2sClient.Enabled {
		return errors.New("service account disabled")
	}

	if s2sClient.AccountLocked {
		return errors.New("service account locked")
	}

	if s2sClient.AccountExpired {
		return errors.New("service account expired")
	}

	return nil
}

// s2s login handler
type S2sLoginHandler struct {
	Service S2sLoginService
}

func NewS2sLoginHandler(service S2sLoginService) *S2sLoginHandler {
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

	if err := h.Service.ValidateCredentials(cmd); err != nil {
		http.Error(w, fmt.Sprintf("invalid credentials: %s", err), http.StatusUnauthorized)
		return
	}

}
