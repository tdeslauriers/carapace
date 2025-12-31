package provider

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/session/types"
	"golang.org/x/net/context"
)

// S2sTokenProvider is an interface for providing service-to-service tokens for service-to-service calls
type S2sTokenProvider interface {
	// GetServiceToken gets a service token for a given service name
	// intended for service-to-service calls
	GetServiceToken(ctx context.Context, serviceName string) (string, error)
}

// NewS2sTokenProvider creates a new instance of S2sTokenProvider and provides a pointer to a concrete implementation.
func NewS2sTokenProvider(
	caller *connect.S2sCaller,
	creds S2sCredentials,
	db *sql.DB,
	ciph data.Cryptor,
) S2sTokenProvider {

	return &s2sTokenProvider{
		s2s:     caller,
		creds:   creds,
		db:      NewRepository(db),
		cryptor: ciph,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentTokenProvider)).
			With(slog.String(util.PackageKey, util.PackageSession)).
			With(slog.String(util.FrameworkKey, util.FrameworkCarapace)),
	}
}

var _ S2sTokenProvider = (*s2sTokenProvider)(nil)

// s2sTokenProvider implements the S2sTokenProvider interface
type s2sTokenProvider struct {
	s2s     *connect.S2sCaller
	creds   S2sCredentials
	db      Repository
	cryptor data.Cryptor

	logger *slog.Logger
}

// GetServiceToken implements the S2sTokenProvider interface for service-to-service token retrieval.
// It looks fro active service tokens in the local db, and if none are found, it will attempt to refresh
// the token using the refresh token. If no active refresh tokens are found, it will attempt to login and get a new token.
func (p *s2sTokenProvider) GetServiceToken(ctx context.Context, serviceName string) (jwt string, e error) {

	// local logger for the function to prevent field accumulation across calls
	logger := p.logger

	// get telemetry from context if exists
	telemetry, ok := connect.GetTelemetryFromContext(ctx)
	if ok && telemetry != nil {
		logger = logger.With(telemetry.TelemetryFields()...)
	} else {
		logger.Warn("failed to extract telemetry from context of s2s GetServiceToken call")
	}

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
				logger.Info(fmt.Sprintf("active %s s2s token present, jti: %s", serviceName, token.Jti))

				// decrypt service token
				decrypted, err := p.cryptor.DecryptServiceData(token.ServiceToken)
				if err != nil {
					logger.Error(fmt.Sprintf("failed to decrypt %s s2s token: jti %s", serviceName, token.Jti),
						slog.String("err", err.Error()),
					)
				} else {

					// return decrypted service token
					return string(decrypted), nil
				}
			} else {
				// opportunistically delete expired service token
				go func(id string) {

					if err := p.db.DeleteTokenById(id); err != nil {
						logger.Error(fmt.Sprintf("failed to delete expired service token for %s: jti %s", serviceName, id),
							slog.String("err", err.Error()),
						)
						return
					}
					logger.Info(fmt.Sprintf("deleted expired %s s2s token: jti %s", serviceName, id))
				}(token.Jti)
			}
		}

		// if no active s2s tokens exist: get new service token via refresh
		// loop until success, or all refresh tokens have failed: failure could happen if all refresh
		// tokens have been claimed/deleted, but there was an error persisting the replacement
		// token in s2s auth service.
		// return first successful refresh
		for _, token := range tokens {
			logger.Info(fmt.Sprintf("refreshing %s s2s token, jti %s", serviceName, token.Jti))

			// call s2s auth service to refresh token
			authz, err := p.refreshS2sToken(ctx, token.RefreshToken, serviceName) // decrypts
			if err != nil {
				logger.Error(fmt.Sprintf("failed to refresh %s s2s token: jti %s",
					token.ServiceName, token.Jti),
					slog.String("err", err.Error()),
				)
				continue
			}

			// persist new service token and replacement refresh token
			// keeps the same refresh expiry as the token it is replacing
			go func(a S2sAuthorization) {
				if err := p.persistS2sToken(a); err != nil {
					logger.Warn(fmt.Sprintf("failed to persist refreshed %s s2s token: jit %s", serviceName, a.Jti),
						slog.String("err", err.Error()),
					)
					return
				}
			}(*authz)

			// opportunistically delete claimed refresh token/expired service token record
			// since claimed refresh token will have been deleted by s2s auth service after use.
			go func(id string) {

				if err := p.db.DeleteTokenById(id); err != nil {
					logger.Error(fmt.Sprintf("failed to delete claimed refresh token for %s: jti %s", serviceName, id),
						slog.String("err", err.Error()),
					)
					return
				}

				logger.Info(fmt.Sprintf("deleted claimed refresh token for %s, jti %s", serviceName, id))
			}(token.Jti)

			logger.Info(fmt.Sprintf("successfully refreshed %s s2s token: jti %s", serviceName, authz.Jti))

			return authz.ServiceToken, nil
		}
	}

	// no active s2s tokens, no active refresh tokens, get new service token
	logger.Info(fmt.Sprintf("no active %s s2s access or refresh tokens found, authenticating", serviceName))

	// login to s2s authn endpoint
	authz, err := p.s2sLogin(ctx, serviceName)
	if err != nil {
		return "", fmt.Errorf("s2s login failed: %v", err)
	}

	// persist new service token, etc.
	go func(a S2sAuthorization) {
		if err := p.persistS2sToken(a); err != nil {
			logger.Warn(fmt.Sprintf("failed to persist %s s2s token", serviceName),
				slog.String("err", err.Error()),
			)
			return
		}

	}(authz)

	logger.Info(fmt.Sprintf("successfully authenticated to %s s2s authentication service: jti %s", serviceName, authz.Jti))
	return authz.ServiceToken, nil
}

// s2sLogin makes a call to the s2s authentication endpoint to get a new service token
func (p *s2sTokenProvider) s2sLogin(ctx context.Context, service string) (S2sAuthorization, error) {

	cmd := types.S2sLoginCmd{
		ClientId:     p.creds.ClientId,
		ClientSecret: p.creds.ClientSecret,
		ServiceName:  service,
	}

	var s2sAuthz S2sAuthorization
	s2sAuthz, err := connect.PostToService[types.S2sLoginCmd, S2sAuthorization](
		ctx,
		p.s2s,
		"/login",
		"",
		"",
		cmd,
	)
	if err != nil {
		return s2sAuthz, fmt.Errorf("failed to login to s2s /login endpoint for %s: %v", service, err)
	}

	return s2sAuthz, nil
}

// persistS2sToken encrypts and saves service tokens to local maria db
// note: this new record will have the same refresh-expiry as the one it it replacing, so that
// refresh cycles remain consistent, and cant go on forever.
func (p *s2sTokenProvider) persistS2sToken(authz S2sAuthorization) error {

	// encrypt service token and refresh token
	encServiceToken, err := p.cryptor.EncryptServiceData([]byte(authz.ServiceToken))
	if err != nil {
		return fmt.Errorf("failed to encrypt s2s token: %v", err)
	}
	authz.ServiceToken = encServiceToken

	encRefreshToken, err := p.cryptor.EncryptServiceData([]byte(authz.RefreshToken))
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %v", err)
	}
	authz.RefreshToken = encRefreshToken

	if err := p.db.InsertToken(authz); err != nil {
		return fmt.Errorf("failed to persist service token (jti %s) for %s: %v", authz.Jti, authz.ServiceName, err)
	}

	return nil
}

// retrieveS2sTokens gets active service tokens from local store
func (p *s2sTokenProvider) retrieveS2sTokens(service string) ([]S2sAuthorization, error) {

	tokens, err := p.db.FindActiveTokens(service)
	if err != nil {
		return tokens, fmt.Errorf("failed to select service token records for %s: %v", service, err)
	}

	return tokens, nil
}

// refreshS2sToken decrypts refresh token and makes refresh client call
func (p *s2sTokenProvider) refreshS2sToken(ctx context.Context, refreshToken, serviceName string) (*S2sAuthorization, error) {

	// decrypt refresh token
	decrypted, err := p.cryptor.DecryptServiceData(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %v", err)
	}

	// create cmd
	cmd := types.S2sRefreshCmd{
		RefreshToken: string(decrypted),
		ServiceName:  serviceName,
	}

	s2sAuthz, err := connect.PostToService[types.S2sRefreshCmd, *S2sAuthorization](
		ctx,
		p.s2s,
		"/refresh",
		"",
		"",
		cmd,
	)
	if err != nil {
		return nil, fmt.Errorf("call to s2s auth /refresh failed: %v", err)
	}

	return s2sAuthz, nil
}
