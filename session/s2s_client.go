package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
)

// client side
// response
type Authorization struct {
	Jti            string    `json:"jti" db:"uuid"` // gen'd by s2s service at token creation
	ServiceToken   string    `json:"service_token" db:"service_token"`
	TokenExpires   time.Time `json:"token_expires" db:"service_expires"`
	RefreshToken   string    `json:"refresh_token" db:"refresh_token"`
	RefreshExpires time.Time `json:"refresh_expires" db:"refresh_expires"`
}

// s2s token provider -> calls s2s service for tokens, stores and retrieves tokens from local db
type S2STokenProvider interface {
	GetServiceToken() (string, error)
	S2sLogin() (*Authorization, error)                               // login client call
	RefreshServiceToken(refreshToken string) (*Authorization, error) // refresh client call
	PersistServiceToken(*Authorization) error                        // save to db
	RetrieveServiceToken() (string, error)                           // active token from local store
}

type S2sTokenProvider struct {
	S2sServiceUrl string
	Credentials   S2sLoginCmd
	S2sClient     connect.TLSClient
	Dao           data.SqlRepository
}

func (p *S2sTokenProvider) GetServiceToken() (token string, e error) {

	// pull tokens with un-expired refresh
	tokens, err := p.RetrieveServiceTokens()
	if err != nil {
		return "", err
	}

	// if active refresh tokens exist
	if len(tokens) > 0 {
		// check for active service token
		token, isActive := getActiveToken(tokens)
		if isActive {
			return token.ServiceToken, nil
		} else {
			// get new service token via refresh
			auth, err := p.RefreshServiceToken(token.RefreshToken)
		}
	}

	// login to s2s authn endpoint
	auth, err := p.S2sLogin()
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new access token, etc.
	go func() {
		if err := p.PersistServiceToken(auth); err != nil {
			log.Printf("Error persisting access token: %v", err)
		}
	}()

	return auth.ServiceToken, nil
}

// helper func: return first active token
func getActiveToken(tokens []Authorization) (*Authorization, bool) {
	for _, token := range tokens {
		if token.TokenExpires.After(time.Now()) {
			return &token, true
		}
	}
	return nil, false
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
	if err := p.Dao.InsertRecord(qry, *auth); err != nil {
		return fmt.Errorf("unable to persist service token: %v", err)
	}

	return nil
}

func (p *S2sTokenProvider) RetrieveServiceTokens() ([]Authorization, error) {

	var tokens []Authorization
	qry := `
			SELECT 
				uuid, 
				service_token, 
				serivce_expires, 
				refresh_token, 
				refresh_expires 
			FROM servicetoken
			WHERE refresh_expires > NOW()`
	if err := p.Dao.SelectRecords(qry, &tokens); err != nil {
		return tokens, fmt.Errorf("unable to select service token records: %v", err)
	}

	return tokens, nil
}

func (p *S2sTokenProvider)RefreshServiceToken(refreshToken string) (*Authorization, error){

	
}
