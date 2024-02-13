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
type S2sAuthorization struct {
	Jti            string          `json:"jti" db:"uuid"` // gen'd by s2s service at token creation
	ServiceToken   string          `json:"service_token" db:"service_token"`
	TokenExpires   data.CustomTime `json:"token_expires" db:"service_expires"`
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
}

// s2s token provider -> calls s2s service for tokens, stores and retrieves tokens from local db
type S2STokenProvider interface {
	GetServiceToken() (string, error)
}

type S2sTokenProvider struct {
	S2sServiceUrl string
	Credentials   S2sLoginCmd
	S2sClient     connect.TLSClient
	Dao           data.SqlRepository
}

func NewS2sTokenProvider(url string, creds S2sLoginCmd, client connect.TLSClient, dao data.SqlRepository) *S2sTokenProvider {
	return &S2sTokenProvider{
		S2sServiceUrl: url,
		Credentials:   creds,
		S2sClient:     client,
		Dao:           dao,
	}
}

func (p *S2sTokenProvider) GetServiceToken() (jwt string, e error) {

	// pull tokens with un-expired refresh
	tokens, err := p.RetrieveServiceToken()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve service tokens: %v", err)
	}
	// if active refresh tokens exist
	if len(tokens) > 0 {

		// check for active service access token
		for _, token := range tokens {

			if token.TokenExpires.Time.After(time.Now().UTC()) {
				log.Printf("active s2s access token present, jti: %s", token.Jti)
				return token.ServiceToken, err
			} else {
				// opportunistically delete expired access token
				go func(id string) {
					qry := "DELETE FROM servicetoken WHERE uuid = ?"
					if err := p.Dao.DeleteRecord(qry, id); err != nil {
						log.Printf("failed to delete expired access token, jti %s: %v", id, err)
					} else {
						log.Printf("deleted expired access token, jti %s", id)
					}
				}(token.Jti)
			}

		}

		log.Printf("refreshing s2s access token")
		// get new service access token via refresh
		authz, err := p.RefreshServiceToken(tokens[0].RefreshToken)
		if err != nil {
			log.Printf("unable to refresh access token (jti %s): %v", tokens[0].Jti, err)
		}

		// only return and persist if successful
		if authz != nil {
			// persist new access token, etc.
			go func(a *S2sAuthorization) {
				if err := p.PersistServiceToken(a); err != nil {
					log.Printf("Error persisting refreshed access token, jit %s: %v", a.Jti, err)
				}
			}(authz)

			return authz.ServiceToken, nil
		}
	}

	log.Printf("s2s login with credentials")
	// login to s2s authn endpoint
	authz, err := p.S2sLogin()
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new access token, etc.
	go func(a *S2sAuthorization) {
		if err := p.PersistServiceToken(a); err != nil {
			log.Printf("Error persisting access token: %v", err)
		}
	}(authz)

	return authz.ServiceToken, nil
}

// login client call
func (p *S2sTokenProvider) S2sLogin() (*S2sAuthorization, error) {

	jsonData, err := json.Marshal(p.Credentials)
	if err != nil {
		return nil, fmt.Errorf("unable to marshall login cmd to json: %v", err)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/login", p.S2sServiceUrl), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := p.S2sClient.Do(req)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	// unmarshal json
	var s2sAuthz S2sAuthorization
	if err = json.Unmarshal(body, &s2sAuthz); err != nil {
		return nil, fmt.Errorf("unable to unmarshall s2s response body to json: %v", err)
	}

	return &s2sAuthz, nil
}

// save to maria db
func (p *S2sTokenProvider) PersistServiceToken(authz *S2sAuthorization) error {

	qry := "INSERT INTO servicetoken (uuid, service_token, service_expires, refresh_token, refresh_expires) VALUES (?, ?, ?, ?, ?)"
	if err := p.Dao.InsertRecord(qry, *authz); err != nil {
		return fmt.Errorf("unable to persist service token: %v", err)
	}

	return nil
}

// active token from local store
func (p *S2sTokenProvider) RetrieveServiceToken() ([]S2sAuthorization, error) {

	var tokens []S2sAuthorization
	qry := `
			SELECT 
				uuid, 
				service_token, 
				service_expires, 
				refresh_token, 
				refresh_expires 
			FROM servicetoken
			WHERE refresh_expires > NOW()`
	if err := p.Dao.SelectRecords(qry, &tokens); err != nil {
		return tokens, fmt.Errorf("unable to select service token records: %v", err)
	}

	return tokens, nil
}

// refresh client call
func (p *S2sTokenProvider) RefreshServiceToken(refreshToken string) (*S2sAuthorization, error) {
	// create cmd
	data, err := json.Marshal(RefreshCmd{RefreshToken: refreshToken})
	if err != nil {
		return nil, fmt.Errorf("unable to marshall refresh cmd to json: %v", err)
	}

	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/refresh", p.S2sServiceUrl), bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := p.S2sClient.Do(req)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode == http.StatusOK {
		// unmarshal json
		var s2sAuthz S2sAuthorization
		if err = json.Unmarshal(body, &s2sAuthz); err != nil {
			return nil, fmt.Errorf("unable to unmarshall s2s response body to json: %v", err)
		}

		return &s2sAuthz, nil
	}

	// handle err
	return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(body))
}
