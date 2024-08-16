package provider

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
)

// S2sTokenProvider is an interface for providing service-to-service tokens for service-to-service calls
type S2sTokenProvider interface {
	// GetServiceToken gets a service token for a given service name
	// intended for service-to-service calls
	GetServiceToken(serviceName string) (string, error)
}

func NewS2sTokenProvider(caller connect.S2sCaller, creds S2sCredentials, db data.SqlRepository, ciph data.Cryptor) S2sTokenProvider {
	return &s2sTokenProvider{
		s2s:     caller,
		creds:   creds,
		db:      db,
		cryptor: ciph,

		logger: slog.Default().With(slog.String(config.PackageKey, config.PackageSession), slog.String(config.ServiceKey, config.ServiceCarapace)),
	}
}

var _ S2sTokenProvider = (*s2sTokenProvider)(nil)

// s2sTokenProvider implements the S2sTokenProvider interface
type s2sTokenProvider struct {
	s2s     connect.S2sCaller
	creds   S2sCredentials
	db      data.SqlRepository
	cryptor data.Cryptor

	logger *slog.Logger
}

// GetServiceToken implements the S2sTokenProvider interface for service-to-service token retrieval.
// It looks fro active service tokens in the local db, and if none are found, it will attempt to refresh
// the token using the refresh token. If no active refresh tokens are found, it will attempt to login and get a new token.
func (p *s2sTokenProvider) GetServiceToken(serviceName string) (jwt string, e error) {

	// pull tokens with un-expired refresh
	tokens, err := p.retrieveS2sTokens(serviceName)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve service tokens for %s: %v", serviceName, err)
	}

	// if active refresh tokens exist
	if len(tokens) > 0 {
		for _, token := range tokens {

			// check for active s2s token
			if token.TokenExpires.Time.After(time.Now().UTC()) {
				p.logger.Info(fmt.Sprintf("active %s s2s token present, jti: %s", serviceName, token.Jti))

				// decrypt service token
				decrypted, err := p.cryptor.DecryptServiceData(token.ServiceToken)
				if err != nil {
					p.logger.Error(fmt.Sprintf("failed to decrypt %s s2s token, jti: %s", serviceName, token.Jti), "err", err.Error())
				} else {
					return decrypted, nil
				}
			} else {
				// opportunistically delete expired service token
				go func(id string) {
					qry := "DELETE FROM servicetoken WHERE uuid = ?"
					if err := p.db.DeleteRecord(qry, id); err != nil {
						p.logger.Error(fmt.Sprintf("failed to delete expired service token for %s, jti: %s", serviceName, id), "err", err.Error())
					} else {
						p.logger.Info(fmt.Sprintf("deleted expired %s s2s token, jti %s", serviceName, id))
					}
				}(token.Jti)
			}
		}

		// if no active s2s tokens exist
		// get new service token via refresh
		p.logger.Info(fmt.Sprintf("refreshing %s s2s token", serviceName))
		authz, err := p.refreshS2sToken(tokens[0].RefreshToken, serviceName) // decrypts
		if err != nil {
			p.logger.Error(fmt.Sprintf("failed to refresh %s s2s token, jti: %s", tokens[0].ServiceName, tokens[0].Jti), "err", err.Error())
		}

		// only return and persist if successful
		if authz != nil {
			// persist new service token, etc.
			go func(a *S2sAuthorization) {

				// encrypts before db insertion
				if err := p.persistS2sToken(a); err != nil {
					p.logger.Warn(fmt.Sprintf("failed to persist refreshed %s s2s token, jit: %s", serviceName, a.Jti), "err", err.Error())
				}
			}(authz)

			return authz.ServiceToken, nil
		}
	}

	p.logger.Info(fmt.Sprintf("no active %s s2s token found, authenticating", serviceName))

	// no active s2s tokens, no active refresh tokens, get new service token
	// login to s2s authn endpoint
	authz, err := p.s2sLogin(serviceName)
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new service token, etc.
	go func(a *S2sAuthorization) {
		if err := p.persistS2sToken(a); err != nil {
			p.logger.Warn(fmt.Sprintf("failed to persist %s s2s token", serviceName), "err", err.Error())
		}
	}(authz)

	return authz.ServiceToken, nil
}

// s2sLogin makes a call to the s2s authentication endpoint to get a new service token
func (p *s2sTokenProvider) s2sLogin(service string) (*S2sAuthorization, error) {

	login := types.S2sLoginCmd{
		ClientId:     p.creds.ClientId,
		ClientSecret: p.creds.ClientSecret,
		ServiceName:  service,
	}

	var s2sAuthz S2sAuthorization
	if err := p.s2s.PostToService("/login", "", "", login, &s2sAuthz); err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("failed to login to s2s /login endpoint for %s", service), "err", err.Error())
	}

	return &s2sAuthz, nil
}

// persistS2sToken encrypts and saves service tokens to local maria db
func (p *s2sTokenProvider) persistS2sToken(authz *S2sAuthorization) error {

	// encrypt service token and refresh token
	encServiceToken, err := p.cryptor.EncryptServiceData(authz.ServiceToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt s2s token: %v", err)
	}
	authz.ServiceToken = encServiceToken

	encRefreshToken, err := p.cryptor.EncryptServiceData(authz.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %v", err)
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
	if err := p.db.InsertRecord(qry, *authz); err != nil {
		return fmt.Errorf("failed to persist service token (jti %s) for %s: %v", authz.Jti, authz.ServiceName, err)
	}

	return nil
}

// retrieveS2sTokens gets active service tokens from local store
func (p *s2sTokenProvider) retrieveS2sTokens(service string) ([]S2sAuthorization, error) {

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
			WHERE refresh_expires > UTC_TIMESTAMP()
				AND service_name = ?`
	if err := p.db.SelectRecords(qry, &tokens, service); err != nil {
		return tokens, fmt.Errorf("failed to select service token records for %s: %v", service, err)
	}

	return tokens, nil
}

// refreshS2sToken decrypts refresh token and makes refresh client call
func (p *s2sTokenProvider) refreshS2sToken(refreshToken, serviceName string) (*S2sAuthorization, error) {

	// decrypt refresh token
	decrypted, err := p.cryptor.DecryptServiceData(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %v", err)
	}

	// create cmd
	cmd := types.S2sRefreshCmd{
		RefreshToken: decrypted,
		ServiceName:  serviceName,
	}
	var s2sAuthz S2sAuthorization
	if err := p.s2s.PostToService("/refresh", "", "", cmd, &s2sAuthz); err != nil {
		return nil, fmt.Errorf("call to s2s auth /refresh failed: %v", err)
	}

	return &s2sAuthz, nil
}
