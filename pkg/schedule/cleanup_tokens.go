package schedule

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/data"
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

func NewCleanup(db data.SqlRepository) Cleanup {
	return &cleanup{
		sb: db,

		logger: slog.Default().
			With(slog.String(config.ComponentKey, config.ComponentScedule)).
			With(slog.String(config.ServiceKey, config.ServiceCarapace)),
	}
}

var _ Cleanup = (*cleanup)(nil)

type cleanup struct {
	sb data.SqlRepository

	logger *slog.Logger
}

// ExpiredRefresh cleans up expired refresh tokens
func (c *cleanup) ExpiredRefresh(hours int) {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

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

		// sleep until next 2am
		time.Sleep(next.Sub(now))

		// execute deletion of expired refresh tokens
		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry := `DELETE FROM refresh WHERE created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()`
		if err := c.sb.DeleteRecord(qry, hours); err != nil {
			c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
		}

		c.logger.Info("expired refresh tokens cleaned up")
	}

}

// ExpiredAccess cleans up expired access tokens if their attached refresh has expired
func (c *cleanup) ExpiredAccess() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

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

		// sleep until next 2am
		time.Sleep(next.Sub(now))

		// need to delete xref records first to avoid constraint violation
		// Note: access tokens are short lived, so query aimed at the expired refresh tokens attached to them.
		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry := `SELECT 
					ua.id,
					ua.uxsession_uuid,
					ua.accesstoken_uuid
				FROM uxsession_accesstoken ua
					LEFT OUTER JOIN accesstoken a ON ua.accesstoken_uuid = a.uuid
				WHERE a.refresh_expires < UTC_TIMESTAMP()`
		var xrefs []SessionAccessXref
		if err := c.sb.SelectRecords(qry, &xrefs); err != nil {
			c.logger.Error("failed to select expired uxsession_accesstoken xrefs", "error", err.Error())
			return
		}

		// check if there are any xrefs to delete
		if len(xrefs) < 1 {
			c.logger.Info("no expired access tokens to clean up")
			return
		}
		// delete xrefs
		var wg sync.WaitGroup
		for _, xref := range xrefs {

			wg.Add(1)
			go func(id int, wg *sync.WaitGroup) {
				defer wg.Done()

				qry = `DELETE FROM uxsession_accesstoken WHERE id = ?`
				if err := c.sb.DeleteRecord(qry, id); err != nil {
					c.logger.Error(fmt.Sprintf("failed to delete uxsession_accesstoken xref id %d for expired accesstoken id/jti %s", id, xref.AccesstokenId), "err", err.Error())
				}
			}(xref.Id, &wg)
		}

		wg.Wait()

		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry = `DELETE FROM accesstoken WHERE refresh_expires < UTC_TIMESTAMP()`
		if err := c.sb.DeleteRecord(qry); err != nil {
			c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
		}

		c.logger.Info(fmt.Sprintf("%d expired access tokens cleaned up", len(xrefs)))
	}
}

// ExpiredS2s cleans up expired service-to-service tokens if their attached refresh has expired
func (c *cleanup) ExpiredS2s() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

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

		// sleep until next 2am
		time.Sleep(next.Sub(now))

		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry := `DELETE FROM servicetoken WHERE refresh_expires < UTC_TIMESTAMP()`
		if err := c.sb.DeleteRecord(qry); err != nil {
			c.logger.Error("failed to delete expired refresh tokens", "error", err.Error())
		}

		c.logger.Info("expired service-to-service tokens cleaned up")
	}
}

// ExpiredSession cleans up expired user sessions and the associated oauth2 values
func (c *cleanup) ExpiredSession(hours int) {
	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

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

		// sleep until next 2am
		time.Sleep(next.Sub(now))

		// need to delete xref records first to avoid constraint violation
		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		// Note: number of xrefs will be less than the number of sessions because oauth2 values SHOULD only be tied to unauth'ned sessions
		// Note: sessions and oauthflow records are created at different times, so using the session created_at time to determine expiry
		// because it doesnt matter if the oauthflow is expired since it cannot be used without a valid session.
		qry := `SELECT 
					uo.id,
					uo.uxsession_uuid,
					uo.oauthflow_uuid
				FROM uxsession_oauthflow uo
					LEFT OUTER JOIN uxsession u ON uo.oauthflow_uuid = u.uuid
				WHERE u.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()`
		var xrefs []SessionOauthXref
		if err := c.sb.SelectRecords(qry, &xrefs, hours); err != nil {
			c.logger.Error("failed to select expired uxsession_oauthflow xrefs", "error", err.Error())
			return
		}

		// check if there are any xrefs to delete
		if len(xrefs) < 1 {
			c.logger.Info("no expired user sessions to clean up")
			return
		}

		// delete xrefs
		var wg sync.WaitGroup
		for _, xref := range xrefs {

			wg.Add(1)
			go func(id int, wg *sync.WaitGroup) {
				defer wg.Done()

				qry = `DELETE FROM uxsession_oauthflow WHERE id = ?`
				if err := c.sb.DeleteRecord(qry, id); err != nil {
					c.logger.Error(fmt.Sprintf("failed to delete uxsession_oauthflow xref id %d for expired oauthflow id %s", id, xref.OauthflowId), "err", err.Error())
				}
			}(xref.Id, &wg)
		}

		wg.Wait()

		// wait group not needed here because the oauthflow records are no longer tied to any other records
		go func(hours int) {
			qry = `DELETE 
					FROM oauthflow o
						LEFT OUTER JOIN uxsession_oauthflow uo ON o.uuid = uo.oauthflow_uuid
					WHERE o.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()
						AND uo.oauthflow_uuid IS NULL`
			if err := c.sb.DeleteRecord(qry, hours); err != nil {
				c.logger.Error("failed to delete expired oauthflow values", "error", err.Error())
			}
			c.logger.Info("expired and unattached oauthflow records cleaned up")
		}(hours)

		// remove expired sessions
		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		// this will include both authenicated and unauthenticated sessions (so will be much larger than len(xrefs))
		// need to make sure xrefs to accesstokens table have been cleared also
		go func(hours int) {
			qry = `DELETE 
					FROM uxsession u
						LEFT OUTER JOIN uxsession_accesstoken ua ON u.uuid = ua.uxsession_uuid
					WHERE created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()
						AND ua.uxsession_uuid IS NULL`
			if err := c.sb.DeleteRecord(qry, hours); err != nil {
				c.logger.Error("failed to delete expired user sessions", "error", err.Error())
			}
			c.logger.Info("expired user sessions cleaned up")
		}(hours)
	}

}

// ExpiredAuthcode cleans up expired authcodes out of the database and associated xrefs
func (c *cleanup) ExpiredAuthcode() {

	// create local random generator
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

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

		// sleep until next 2am
		time.Sleep(next.Sub(now))

		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry := `DELETE 
					FROM authcode_account aa 
						LEFT OUTER JOIN authcode a ON aa.authcode_uuid = a.uuid
					WHERE a.created_at + INTERVAL 10 MINUTE < UTC_TIMESTAMP()`
		if err := c.sb.DeleteRecord(qry); err != nil {
			c.logger.Error("failed to delete expired authcode account xref records", "error", err.Error())
		}

		// EXPIRIES ARE IN UTC, SO USE UTC TIME
		qry = `DELETE FROM authcode WHERE created_at + INTERVAL 10 MINUTE < UTC_TIMESTAMP()`
		if err := c.sb.DeleteRecord(qry); err != nil {
			c.logger.Error("failed to delete expired authcodes", "error", err.Error())
		}

		c.logger.Info("expired authcodes xrefs to account cleaned up")

	}
}
