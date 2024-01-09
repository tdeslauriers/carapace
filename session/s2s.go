package session

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/data"
	"golang.org/x/crypto/bcrypt"
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

// repository functions
func FindRecord[T any](db *sql.DB, query string, args ...interface{}) (*S2sClientData, error) {
	var record S2sClientData

	// returns only first row => uuids should be unique.
	row := db.QueryRow(query, args...)
	err := row.Scan(&record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func FindRecords[T any](db *sql.DB, query string, args ...interface{}) ([]T, error) {
	var records []T
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var record T
		if err := rows.Scan(any(&record)); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	// error check
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// s2s login service
type S2sLoginService interface {
	ValidateCredentials(creds S2sLoginCmd) error
}

type MariaS2sLoginService struct {
	Db *data.MariaDbConnector
}

func NewS2SLoginService(sql *data.MariaDbConnector) *MariaS2sLoginService {
	return &MariaS2sLoginService{
		Db: sql,
	}
}

func (s *MariaS2sLoginService) ValidateCredentials(creds S2sLoginCmd) error {

	db, err := s.Db.Connect()
	if err != nil {
		log.Panicf("unable to connect to s2s auth database: %v", err)
		return err
	}

	qry := "SELECT * FROM client WHERE uuid = ?"

	client, err := FindRecord[S2sClientData](db, qry, creds.ClientId)
	if err != nil {
		log.Panicf("unable to find s2s client record: %v", err)
		return err
	}

	if !client.Enabled {
		return errors.New("service account disabled")
	}

	if client.AccountLocked {
		return errors.New("service account locked")
	}

	if client.AccountExpired {
		return errors.New("service account expired")
	}

	secret := []byte(creds.ClientSecret)
	hash := []byte(client.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		return err
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
