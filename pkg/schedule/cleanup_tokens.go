package schedule

import (
	"database/sql"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/internal/util"
)

// Cleanup is an interface for cleaning up expired tokens in a services local persistence/database.
type Cleanup interface {
	// ExpiredRefresh cleans up expired refresh tokens
	ExpiredRefresh(hours int)

	// ExpiredAccess cleans up expired access tokens if their attached refresh has expired
	ExpiredAccess()

	// ExpiredS2s cleans up expired service-to-service tokens if their attached refresh has expired
	ExpiredS2s()

	// ExpiredSession cleans up expired user sessions and the associated oauth2 values
	ExpiredSession(hours int)

	// ExpiredAuthcode cleans up expired authcodes out of the database and associated xrefs
	ExpiredAuthcode()
}

func NewCleanup(db *sql.DB) Cleanup {
	return &cleanup{
		db: NewRepository(db),

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentCleanup)).
			With(slog.String(util.PackageKey, util.PackageSchedule)).
			With(slog.String(util.FrameworkKey, util.FrameworkCarapace)),
	}
}

var _ Cleanup = (*cleanup)(nil)

type cleanup struct {
	db Repository

	logger *slog.Logger
}

// ExpiredRefresh cleans up expired refresh tokens
func (c *cleanup) ExpiredRefresh(hours int) {
	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {
			// using local time so this will be 2am no matter what timezone the service is in
			now := time.Now()

			// calc next 2am
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) {
				// if 2am has already passed today, set it for tomorrow
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			randInterval := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			c.logger.Info("scheduling expired refresh cleanup", "runAt", next)

			timer := time.NewTimer(duration)
			<-timer.C // Wait until it's time to run

			// execute deletion of expired refresh tokens
			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			if err := c.db.DeleteExpiredRefresh(hours); err != nil {
				c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
			} else {
				c.logger.Info("expired refresh tokens cleaned up")
			}
		}
	}()
}

// ExpiredAccess cleans up expired access tokens if their attached refresh has expired
func (c *cleanup) ExpiredAccess() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {

		for {
			// using local time so this will be 2am no matter what timezone the service is in
			now := time.Now()

			// calc next 2am
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			randInterval := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			c.logger.Info("scheduling expired access cleanup", "runAt", next)

			timer := time.NewTimer(duration)
			<-timer.C // Wait until it's time to run

			// need to delete xref records first to avoid constraint violation
			// Note: access tokens are short lived, so query aimed at the expired refresh tokens attached to them.
			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			xrefs, err := c.db.FindExpiredRefreshXrefs()
			if err != nil {
				c.logger.Error("failed to select expired uxsession_accesstoken xrefs", "error", err.Error())
				return
			}

			// check if there are any xrefs to delete
			if len(xrefs) > 0 {
				c.logger.Info("removing xrefs between expired access/refresh tokens and sessions")

				// delete xrefs
				var wg sync.WaitGroup
				for _, xref := range xrefs {

					wg.Add(1)
					go func(id int, wg *sync.WaitGroup) {
						defer wg.Done()

						if err := c.db.DeleteSessionAccessTknXref(id); err != nil {
							c.logger.Error(fmt.Sprintf("failed to delete uxsession_accesstoken xref id %d for expired accesstoken id/jti %s", id, xref.AccesstokenId), "err", err.Error())
						}
					}(xref.Id, &wg)
				}

				wg.Wait()
			}

			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			if err := c.db.DeleteExpiredAccessToken(); err != nil {
				c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
			}

			c.logger.Info(fmt.Sprintf("%d expired access tokens cleaned up", len(xrefs)))
		}
	}()
}

// ExpiredS2s cleans up expired service-to-service tokens if their attached refresh has expired
func (c *cleanup) ExpiredS2s() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {
			// using local time so this will be 2am no matter what timezone the service is in
			now := time.Now()

			// calc next 2am
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			randInterval := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			c.logger.Info("scheduling expired s2s cleanup", "runAt", next)

			timer := time.NewTimer(duration)
			<-timer.C // Wait until it's time to run

			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			if err := c.db.DeleteExpiredSvcTkns(); err != nil {
				c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
			}

			c.logger.Info("expired service-to-service tokens cleaned up")
		}
	}()
}

// ExpiredSession cleans up expired user sessions and the associated oauth2 values
func (c *cleanup) ExpiredSession(hours int) {
	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(hours int) {
		for {
			// using local time so this will be 2am no matter what timezone the service is in
			now := time.Now()

			// calc next 2am
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			randInterval := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			c.logger.Info("scheduling expired session token cleanup", "runAt", next)

			timer := time.NewTimer(duration)
			<-timer.C // Wait until it's time to run

			// need to delete xref records first to avoid constraint violation
			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			// Note: number of xrefs will be less than the number of sessions because oauth2 values SHOULD only be tied to unauth'ned sessions
			// Note: sessions and oauthflow records are created at different times, so using the session created_at time to determine expiry
			// because it doesnt matter if the oauthflow is expired since it cannot be used without a valid session.
			var wg sync.WaitGroup

			// oauth xrefs
			xrefsOauth, err := c.db.FindExpiredOauthXrefs(hours)
			if err != nil {
				c.logger.Error("failed to select expired uxsession_oauthflow xrefs", "error", err.Error())
				return
			}

			// check if there are any xrefs to delete
			if len(xrefsOauth) > 0 {
				c.logger.Info("removing xrefs between expired sessions and oauth2 values")

				// delete xrefs
				for _, xref := range xrefsOauth {

					wg.Add(1)
					go func(id int, wg *sync.WaitGroup) {
						defer wg.Done()

						if err := c.db.DeleteSessionOauthXref(id); err != nil {
							c.logger.Error(fmt.Sprintf("failed to delete uxsession_oauthflow xref id %d for expired oauthflow id %s", id, xref.OauthflowId), "err", err.Error())
						}
					}(xref.Id, &wg)
				}
			}

			// access token xrefs
			xrefsAuth, err := c.db.FindExpiredAccessTknXrefs(hours)
			if err != nil {
				c.logger.Error("failed to select expired uxsession_accesstoken xrefs", "error", err.Error())
				return
			}

			// check if there are any xrefs to delete
			if len(xrefsAuth) > 0 {
				c.logger.Info("removing xrefs between expired sessions and access tokens")

				// delete xrefs
				for _, xref := range xrefsAuth {

					wg.Add(1)
					go func(id int, wg *sync.WaitGroup) {
						defer wg.Done()

						if err := c.db.DeleteSessionAccessTknXref(id); err != nil {
							c.logger.Error(fmt.Sprintf("failed to delete uxsession_accesstoken xref id %d for expired accesstoken id %s", id, xref.AccesstokenId), "err", err.Error())
						}
					}(xref.Id, &wg)
				}
			}

			// wait for all xrefs to be deleted before deleting the sessions and oauthflow records
			wg.Wait()

			// wait group not needed here because the oauthflow records are no longer tied to any other records
			go func(hours int) {

				if err := c.db.DeleteOauthFlow(hours); err != nil {
					c.logger.Error("failed to delete expired oauthflow values", "error", err.Error())
				}
				c.logger.Info("expired and unattached oauthflow records cleaned up")
			}(hours)

			// remove expired sessions
			// EXPIRIES ARE IN UTC, SO USE UTC TIME
			// this will include both authenicated and unauthenticated sessions (so will be much larger than len(xrefs))
			// need to make sure xrefs to accesstokens table have been cleared also
			go func(hours int) {

				if err := c.db.DeleteExpiredSession(hours); err != nil {
					c.logger.Error("failed to delete expired user sessions", "error", err.Error())
				}
				c.logger.Info("expired user sessions cleaned up")
			}(hours)
		}
	}(hours)
}

// ExpiredAuthcode cleans up expired authcodes out of the database and associated xrefs
func (c *cleanup) ExpiredAuthcode() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {
			// using local time so this will be 2am no matter what timezone the service is in
			now := time.Now()

			// calc next 2am
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) {
				// if 2am has already passed today, set it for tomorrow
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +/- 30 minutes
			randInterval := time.Duration(rng.Intn(61)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			c.logger.Info("scheduling expired auth code cleanup", "runAt", next)

			timer := time.NewTimer(duration)
			<-timer.C // Wait until it's time to run

			if err := c.db.DeleteAuthCodeXrefs(); err != nil {
				c.logger.Error("failed to delete expired authcode account xref records", "error", err.Error())
				return
			}

			// EXPIRIES ARE IN UTC, SO USE UTC TIME

			if err := c.db.DeleteAuthCode(); err != nil {
				c.logger.Error("failed to delete expired authcodes", "error", err.Error())
				return
			}

			c.logger.Info("expired authcodes xrefs to account cleaned up")
		}
	}()
}
