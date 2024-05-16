package session

import (
	"fmt"
	"log"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// client side
// response
type S2sAuthorization struct {
	Jti            string          `json:"jti" db:"uuid"` // gen'd by s2s service at token creation
	ServiceName    string          `json:"service_name" db:"service_name"`
	ServiceToken   string          `json:"service_token" db:"service_token"`
	TokenExpires   data.CustomTime `json:"token_expires" db:"service_expires"`
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
}

// s2s token provider -> calls s2s service for tokens, stores and retrieves tokens from local db
type S2sTokenProvider interface {
	GetServiceToken(serviceName string) (string, error)
}

func NewS2sTokenProvider(caller connect.S2sCaller, creds S2sCredentials, dao data.SqlRepository, ciph data.Cryptor) S2sTokenProvider {
	return &s2sTokenProvider{
		S2sCaller:   caller,
		Credentials: creds,
		Dao:         dao,
		Cryptor:     ciph,
	}
}

var _ S2sTokenProvider = (*s2sTokenProvider)(nil)

type s2sTokenProvider struct {
	S2sCaller   connect.S2sCaller
	Credentials S2sCredentials
	Dao         data.SqlRepository
	Cryptor     data.Cryptor
}

func (p *s2sTokenProvider) GetServiceToken(serviceName string) (jwt string, e error) {

	// pull tokens with un-expired refresh
	tokens, err := p.RetrieveServiceTokens(serviceName)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve service tokens for %s: %v", serviceName, err)
	}
	// if active refresh tokens exist
	if len(tokens) > 0 {

		// check for active service service token
		for _, token := range tokens {

			if token.TokenExpires.Time.After(time.Now().UTC()) {
				log.Printf("active s2s service token present for %s, jti: %s", serviceName, token.Jti)

				// decrypt service token
				decrypted, err := p.Cryptor.DecyptServiceData(token.ServiceToken)
				if err != nil {
					return "", fmt.Errorf("unable to decrypt %s service token (jti %s): %v", serviceName, token.Jti, err)
				}

				return decrypted, err
			} else {
				// opportunistically delete expired service token
				go func(id string) {
					qry := "DELETE FROM servicetoken WHERE uuid = ?"
					if err := p.Dao.DeleteRecord(qry, id); err != nil {
						log.Printf("failed to delete expired service token for %s, jti %s: %v", serviceName, id, err)
					} else {
						log.Printf("deleted expired service token for %s, jti %s", serviceName, id)
					}
				}(token.Jti)
			}

		}

		log.Printf("no active service token present, refreshing %s service token", serviceName)

		// get new service token via refresh
		authz, err := p.RefreshServiceToken(tokens[0].RefreshToken, serviceName) // decrypts
		if err != nil {
			log.Printf("unable to refresh service token (jti %s) for %s: %v", tokens[0].Jti, tokens[0].ServiceName, err)
		}

		// only return and persist if successful
		if authz != nil {
			// persist new service token, etc.
			go func(a *S2sAuthorization) {

				// encrypts before db insertion
				if err := p.PersistServiceToken(a); err != nil {
					log.Printf("Error persisting refreshed service token for %s, jit %s: %v", serviceName, a.Jti, err)
				}
			}(authz)

			return authz.ServiceToken, nil
		}
	}

	log.Printf("no active service token/refresh token for %s service: retrieving new service token via s2s login", serviceName)
	// login to s2s authn endpoint
	authz, err := p.S2sLogin(serviceName)
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new service token, etc.
	go func(a *S2sAuthorization) {
		if err := p.PersistServiceToken(a); err != nil {
			log.Printf("Error persisting service token: %v", err)
		}
	}(authz)

	return authz.ServiceToken, nil
}

// login client call
func (p *s2sTokenProvider) S2sLogin(service string) (*S2sAuthorization, error) {

	login := S2sLoginCmd{
		ClientId:     p.Credentials.ClientId,
		ClientSecret: p.Credentials.ClientSecret,
		ServiceName:  service,
	}

	var s2sAuthz S2sAuthorization
	if err := p.S2sCaller.PostToService("/login", "", "", login, &s2sAuthz); err != nil {
		return nil, fmt.Errorf("unable to login to s2s /login endpoint for %s: %v", service, err)
	}

	return &s2sAuthz, nil
}

// encrypt and save service tokens to local maria db
func (p *s2sTokenProvider) PersistServiceToken(authz *S2sAuthorization) error {

	// encrypt service token and refresh token
	encServiceToken, err := p.Cryptor.EncyptServiceData(authz.ServiceToken)
	if err != nil {
		return fmt.Errorf("unable to encrypt service token: %v", err)
	}
	authz.ServiceToken = encServiceToken

	encRefreshToken, err := p.Cryptor.EncyptServiceData(authz.RefreshToken)
	if err != nil {
		return fmt.Errorf("unable to encrypt refresh token: %v", err)
	}
	authz.RefreshToken = encRefreshToken

	qry := `
			INSERT INTO servicetoken (
				uuid, 
				service_name, 
				service_token, 
				service_expires, 
				refresh_token, 
				refresh_expires) 
			VALUES (?, ?, ?, ?, ?, ?)`
	if err := p.Dao.InsertRecord(qry, *authz); err != nil {
		return fmt.Errorf("unable to persist service token (jti %s) for %s: %v", authz.Jti, authz.ServiceName, err)
	}

	return nil
}

// gets active service tokens from local store
func (p *s2sTokenProvider) RetrieveServiceTokens(service string) ([]S2sAuthorization, error) {

	var tokens []S2sAuthorization
	qry := `
			SELECT 
				uuid, 
				service_name,
				service_token, 
				service_expires, 
				refresh_token, 
				refresh_expires 
			FROM servicetoken
			WHERE refresh_expires > NOW()
				AND service_name = ?`
	if err := p.Dao.SelectRecords(qry, &tokens, service); err != nil {
		return tokens, fmt.Errorf("unable to select service token records for %s: %v", service, err)
	}

	return tokens, nil
}

// decrypts refresh token and makes refresh client call
func (p *s2sTokenProvider) RefreshServiceToken(refreshToken, serviceName string) (*S2sAuthorization, error) {

	// decrypt refresh token
	decrypted, err := p.Cryptor.DecyptServiceData(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt refresh token: %v", err)
	}

	// create cmd
	cmd := RefreshCmd{
		RefreshToken: decrypted,
		ServiceName:  serviceName,
	}
	var s2sAuthz S2sAuthorization
	if err := p.S2sCaller.PostToService("/refresh", "", "", cmd, &s2sAuthz); err != nil {
		return nil, fmt.Errorf("call to s2s auth /refresh failed: %v", err)
	}

	return &s2sAuthz, nil
}
