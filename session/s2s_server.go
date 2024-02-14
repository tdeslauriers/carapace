package session

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/validate"
	"golang.org/x/crypto/bcrypt"
)

// s2s login service -> validates incoming login
type LoginService interface {
	ValidateCredentials(id, secret string) error
	GetUserScopes(uuid string) ([]Scope, error)
	MintToken(subject string) (*jwt.JwtToken, error) // assumes valid creds
	GetRefreshToken(token string) (*Refresh, error)
	PersistRefresh(refresh Refresh) error
}

type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type S2sClientData struct {
	Uuid           string `db:"uuid" json:"client_id"`
	Password       string `db:"password" json:"client_secret"`
	Name           string `db:"name" json:"name"`
	Owner          string `db:"owner" json:"owner"`
	CreatedAt      string `db:"created_at" json:"created_at"`
	Enabled        bool   `db:"enabled"  json:"enabled"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked"`
}

// maps db table data, not jwt string
type Scope struct {
	Uuid        string `db:"uuid" json:"scope_id"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
}

type MariaS2sLoginService struct {
	ServiceName string
	Dao         data.SqlRepository
	Mint        jwt.JwtSigner
}

func NewS2SLoginService(serviceName string, sql data.SqlRepository, mint jwt.JwtSigner) *MariaS2sLoginService {
	return &MariaS2sLoginService{
		ServiceName: serviceName,
		Dao:         sql,
		Mint:        mint,
	}
}

func (s *MariaS2sLoginService) ValidateCredentials(clientId, clientSecret string) error {

	var s2sClient S2sClientData
	qry := "SELECT uuid, password, name, owner, created_at, enabled, account_expired, account_locked FROM client WHERE uuid = ?"

	if err := s.Dao.SelectRecord(qry, &s2sClient, clientId); err != nil {
		log.Panicf("unable to retrieve s2s client record: %v", err)
		return err
	}

	// password checked first to prevent account enumeration
	secret := []byte(clientSecret)
	hash := []byte(s2sClient.Password)
	if err := bcrypt.CompareHashAndPassword(hash, secret); err != nil {
		return fmt.Errorf("unable to validate password: %v", err)
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

func (s *MariaS2sLoginService) GetUserScopes(uuid string) ([]Scope, error) {

	var scopes []Scope
	qry := `
		SELECT 
			s.uuid,
			s.scope,
			s.name,
			s.description,
			s.created_at,
			s.active
		FROM scope s 
			LEFT JOIN client_scope cs ON s.uuid = cs.scope_uuid
		WHERE cs.client_uuid = ?`
	if err := s.Dao.SelectRecords(qry, &scopes, uuid); err != nil {
		return scopes, fmt.Errorf("unable to retrieve scopes for client %s: %v", uuid, err)
	}

	return scopes, nil
}

func (s *MariaS2sLoginService) PersistRefresh(r Refresh) error {

	qry := "INSERT INTO refresh (uuid, refresh_token, client_uuid, created_at, revoked) VALUES (?, ?, ?, ?, ?)"
	if err := s.Dao.InsertRecord(qry, r); err != nil {
		return fmt.Errorf("unable to save refresh token: %v", err)
	}
	return nil
}

// assumes credentials already validated
func (s *MariaS2sLoginService) MintToken(subject string) (*jwt.JwtToken, error) {

	// jwt header
	header := jwt.JwtHeader{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create jti uuid")
	}

	currentTime := time.Now().UTC()

	scopes, err := s.GetUserScopes(subject)
	if err != nil {
		return nil, err
	}

	// create scopes string: scope values, space delimited
	var builder strings.Builder
	for _, v := range scopes {
		builder.WriteString(v.Scope)
		builder.WriteString(" ")
	}

	claims := jwt.JwtClaims{
		Jti:       jti.String(),
		Issuer:    s.ServiceName,
		Subject:   subject,
		Audience:  BuildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(10 * time.Minute).Unix(),
		Scopes:    builder.String(),
	}

	jot := jwt.JwtToken{Header: header, Claims: claims}

	err = s.Mint.MintJwt(&jot)
	if err != nil {
		return nil, err
	}

	return &jot, err
}

// helper func to build audience []string
func BuildAudiences(scopes []Scope) (unique []string) {

	var services []string
	for _, v := range scopes {
		s := strings.Split(v.Scope, ":") // splits scope by : -> w:service:*
		services = append(services, s[1])
	}

	set := make(map[string]struct{}, 0) // ie, one of each value
	for _, service := range services {
		if _, ok := set[service]; !ok {
			set[service] = struct{}{}
			unique = append(unique, service)
		}
	}

	return unique
}

func (s *MariaS2sLoginService) GetRefreshToken(refreshToken string) (*Refresh, error) {

	// look up refresh
	var refresh Refresh
	qry := `
		SELECT 
			uuid, 
			refresh_token, 
			client_uuid, 
			created_at, 
			revoked 
		FROM refresh
		WHERE refresh_token = ?`
	if err := s.Dao.SelectRecord(qry, &refresh, refreshToken); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token does not exist")
		}
		return nil, fmt.Errorf("refresh token lookup failed: %v", err)
	}

	// check revoke status
	if refresh.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	// validate refresh token not expired server-side
	if refresh.CreatedAt.Time.Add(30 * time.Minute).Before(time.Now().UTC()) {

		// opportunistically delete expired refresh tokens
		go func(id string) {
			qry := "DELETE FROM refresh WHERE uuid = ?"
			if err := s.Dao.DeleteRecord(qry, id); err != nil {
				log.Printf("unable to delete expired refresh token %s", id)
			}

			log.Printf("deleted expired refresh token id: %s", id)
		}(refresh.Uuid)

		return nil, fmt.Errorf("refresh token is expired")
	}

	return &refresh, nil
}

// s2s login handler -> handles incoming login
type S2sLoginHandler struct {
	LoginService LoginService
}

func NewS2sLoginHandler(service LoginService) *S2sLoginHandler {
	return &S2sLoginHandler{
		LoginService: service,
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

	// field input restrictions
	if !validate.IsValidUuid(cmd.ClientId) {
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
	}

	if err := validate.IsValidPassword(cmd.ClientSecret); err != nil {
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
	}

	// validate creds
	if err := h.LoginService.ValidateCredentials(cmd.ClientId, cmd.ClientSecret); err != nil {
		http.Error(w, fmt.Sprintf("invalid client credentials: %s", err), http.StatusUnauthorized)
		return
	}

	// create token
	token, err := h.LoginService.MintToken(cmd.ClientId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// create refresh
	refreshId, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	refresh := Refresh{
		Uuid:         refreshId.String(),
		RefreshToken: refreshToken.String(),
		ClientId:     cmd.ClientId,
		CreatedAt:    data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0)},
		Revoked:      false,
	}

	// don't wait to return jwt
	go func(r Refresh) {
		err := h.LoginService.PersistRefresh(r)
		if err != nil {
			// only logging since refresh is a convenience
			log.Print(err)
		}
	}(refresh)

	// respond with authorization data
	authz := S2sAuthorization{
		Jti:            token.Claims.Jti,
		ServiceToken:   token.Token,
		TokenExpires:   data.CustomTime{Time: time.Unix(token.Claims.Expires, 0)},
		RefreshToken:   refresh.RefreshToken,
		RefreshExpires: data.CustomTime{Time: time.Unix(token.Claims.IssuedAt, 0).Add(30 * time.Minute)},
	}
	authzJson, err := json.Marshal(authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(authzJson)
}
