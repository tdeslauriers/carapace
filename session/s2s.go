package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/jwt"
	"golang.org/x/crypto/bcrypt"
)

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
type S2sScope struct {
	Uuid        string `db:"uuid" json:"scope_id"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
}

// s2s login service -> validates incoming login
type S2sLoginService interface {
	ValidateCredentials(creds S2sLoginCmd) error
	GetScopes(clientId string) ([]S2sScope, error)
	PersistRefresh(Refresh) error
	MintToken(clientId string) (*jwt.JwtToken, error) // assumes valid creds
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

func (s *MariaS2sLoginService) ValidateCredentials(creds S2sLoginCmd) error {

	var s2sClient S2sClientData
	qry := "SELECT uuid, password, name, owner, created_at, enabled, account_expired, account_locked FROM client WHERE uuid = ?"

	if err := s.Dao.SelectRecord(qry, &s2sClient, creds.ClientId); err != nil {
		log.Panicf("unable to retrieve s2s client record: %v", err)
		return err
	}

	// password checked first to prevent account enumeration
	secret := []byte(creds.ClientSecret)
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

func (s *MariaS2sLoginService) GetScopes(uuid string) ([]S2sScope, error) {

	var scopes []S2sScope
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
func (s *MariaS2sLoginService) MintToken(clientId string) (*jwt.JwtToken, error) {

	// jwt header
	header := jwt.JwtHeader{Alg: jwt.ES512, Typ: jwt.TokenType}

	// set up jwt claims fields
	jti, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create jti uuid")
	}

	currentTime := time.Now()

	scopes, err := s.GetScopes(clientId)
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
		Subject:   clientId,
		Audience:  buildAudiences(scopes),
		IssuedAt:  currentTime.Unix(),
		NotBefore: currentTime.Unix(),
		Expires:   currentTime.Add(15 * time.Minute).Unix(),
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
func buildAudiences(scopes []S2sScope) (unique []string) {

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

// s2s login handler -> handles incoming login
type S2sLoginHandler struct {
	LoginService S2sLoginService
}

func NewS2sLoginHandler(service S2sLoginService) *S2sLoginHandler {
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

	// validate creds
	if err := h.LoginService.ValidateCredentials(cmd); err != nil {
		http.Error(w, fmt.Sprintf("invalid credentials: %s", err), http.StatusUnauthorized)
		return
	}

	// create token
	token, err := h.LoginService.MintToken(cmd.ClientId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// create refresh
	id, err := uuid.NewRandom()
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
		Uuid:         id.String(),
		RefreshToken: refreshToken.String(),
		ClientId:     cmd.ClientId,
		CreatedAt:    time.Unix(token.Claims.IssuedAt, 0),
		Revoked:      false,
	}

	// don't wait
	go func() {
		err := h.LoginService.PersistRefresh(refresh)
		if err != nil {
			// only logging since refresh is a convenience
			log.Print(err)
		}
	}()

	// respond with authorization data
	auth := Authorization{
		Jti:            token.Claims.Jti,
		ServiceToken:   token.Token,
		TokenExpires:   token.Claims.Expires,
		RefreshToken:   refresh.RefreshToken,
		RefreshExpires: time.Unix(token.Claims.IssuedAt, 0).Add(1 * time.Hour).Unix(),
	}
	authJson, err := json.Marshal(auth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(authJson)
}

// client side
// response
type Authorization struct {
	Jti            string `json:"jti" db:"uuid"` // gen'd by s2s service at token creation
	ServiceToken   string `json:"service_token" db:"service_token"`
	TokenExpires   int64  `json:"token_expires" db:"service_expires"`
	RefreshToken   string `json:"refresh_token" db:"refresh_token"`
	RefreshExpires int64  `json:"refresh_expires" db:"refresh_expires"`
}

// s2s token provider -> calls s2s service for tokens, stores and retrieves tokens from local db
type S2STokenProvider interface {
	GetServiceToken() (string, error)
	S2sLogin() (*Authorization, error)                               // login client call
	RefreshServiceToken(refreshToken string) (*Authorization, error) // refresh client call
	PersistServiceToken(*Authorization) error                        // save to db
	RetrieveServiceToken() (string, error)
}

type S2sTokenProvider struct {
	S2sServiceUrl string
	Credentials   S2sLoginCmd
	S2sClient     connect.TLSClient
	Dao           data.SqlRepository
}

func (p *S2sTokenProvider) GetServiceToken() (token string, e error) {

	// check db for active token

	// check db for active refresh token
	// persist new access token

	// login to s2s authn endpoint
	auth, err := p.S2sLogin()
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new access token, etc.
	go p.PersistServiceToken(auth)

	return auth.ServiceToken, nil
}

func (p *S2sTokenProvider) S2sLogin() (*Authorization, error) {

	jsonData, _ := json.Marshal(p.Credentials)
	req, _ := http.NewRequest("POST", "https://localhost:8443/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := p.S2sClient.Do(req)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	// unmarshal to json
	var auth Authorization
	if err = json.Unmarshal(body, &auth); err != nil {
		return nil, fmt.Errorf("unable to unmarshall s2s response body to json: %v", err)
	}

	return &auth, nil
}

func (p *S2sTokenProvider) PersistServiceToken(auth *Authorization) error {

	qry := "INSERT INTO servicetoken (uuid, service_token, service_expires, refresh_token, refresh_expires) VALUES (?, ?, ?, ?, ?)"
	if err := p.Dao.InsertRecord(qry, auth); err != nil {
		return fmt.Errorf("unable to persist service token: %v", err)
	}

	return nil
}
