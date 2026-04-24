package schedule

import (
	"context"
	"database/sql"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tdeslauriers/carapace/internal/util"
)

// Cleanup is an interface for cleaning up expired tokens in a services local persistence/database.
type Cleanup interface {
	// ExpiredRefresh cleans up expired refresh tokens
	ExpiredRefresh(ctx context.Context, hours int)

	// ExpiredAccess cleans up expired access tokens if their attached refresh has expired
	ExpiredAccess(ctx context.Context)

	// ExpiredS2s cleans up expired service-to-service tokens if their attached refresh has expired
	ExpiredS2s(ctx context.Context)

	// ExpiredSession cleans up expired user sessions and the associated oauth2 values
	ExpiredSession(ctx context.Context, hours int)

	// ExpiredAuthcode cleans up expired authcodes out of the database and associated xrefs
	ExpiredAuthcode(ctx context.Context)
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
func (c *cleanup) ExpiredRefresh(ctx context.Context, hours int) {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(ctx context.Context) {
		for {
			next := nextRun(rng)
			c.logger.Info("scheduling expired refresh cleanup",
				slog.Time("run_at", next),
			)

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			c.runExpiredRefresh(hours)
		}
	}(ctx)
}

// ExpiredAccess cleans up expired access tokens if their attached refresh has expired
func (c *cleanup) ExpiredAccess(ctx context.Context) {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(ctx context.Context) {
		for {
			next := nextRun(rng)
			c.logger.Info("scheduling expired access cleanup",
				slog.Time("run_at", next),
			)

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := c.runExpiredAccess(); err != nil {
				continue
			}
		}
	}(ctx)
}

// ExpiredS2s cleans up expired service-to-service tokens if their attached refresh has expired
func (c *cleanup) ExpiredS2s(ctx context.Context) {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(ctx context.Context) {
		for {
			next := nextRun(rng)
			c.logger.Info("scheduling expired s2s cleanup",
				slog.Time("run_at", next),
			)

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			c.runExpiredS2s()
		}
	}(ctx)
}

// ExpiredSession cleans up expired user sessions and the associated oauth2 values
func (c *cleanup) ExpiredSession(ctx context.Context, hours int) {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(ctx context.Context, hours int) {
		for {
			next := nextRun(rng)
			c.logger.Info("scheduling expired session token cleanup",
				slog.Time("run_at", next),
			)

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := c.runExpiredSession(hours); err != nil {
				continue
			}
		}
	}(ctx, hours)
}

// ExpiredAuthcode cleans up expired authcodes out of the database and associated xrefs
func (c *cleanup) ExpiredAuthcode(ctx context.Context) {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func(ctx context.Context) {
		for {
			next := nextRun(rng)
			c.logger.Info("scheduling expired auth code cleanup",
				slog.Time("run_at", next),
			)

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := c.runExpiredAuthcode(); err != nil {
				continue
			}
		}
	}(ctx)
}

// nextRun calculates the next 2am wall-clock time with +/- 30 minute jitter.
// Using local time so the run is at 2am regardless of the service's timezone.
func nextRun(rng *rand.Rand) time.Time {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Add(time.Duration(rng.Intn(61)-30) * time.Minute)
}

// runExpiredRefresh executes the expired refresh token deletion for a single cycle.
func (c *cleanup) runExpiredRefresh(hours int) {
	if err := c.db.DeleteExpiredRefresh(hours); err != nil {
		c.logger.Error("failed to delete expired refresh tokens",
			slog.String("err", err.Error()),
		)
	} else {
		c.logger.Info("expired refresh tokens cleaned up")
	}
}

// runExpiredAccess executes the expired access token deletion for a single cycle.
// Returns an error only when the initial xref query fails, which signals the goroutine to skip
// the cycle via continue rather than permanently exit.
func (c *cleanup) runExpiredAccess() error {

	// need to delete xref records first to avoid constraint violation
	// Note: access tokens are short lived, so query is aimed at expired refresh tokens attached to them.
	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	xrefs, err := c.db.FindExpiredRefreshXrefs()
	if err != nil {
		c.logger.Error("failed to select expired uxsession_accesstoken xrefs",
			slog.String("err", err.Error()),
		)
		return err
	}

	var xrefFailed atomic.Bool
	if len(xrefs) > 0 {
		c.logger.Info("removing xrefs between expired access/refresh tokens and sessions")

		var wg sync.WaitGroup
		for _, xref := range xrefs {
			wg.Add(1)
			go func(id int, wg *sync.WaitGroup) {
				defer wg.Done()

				if err := c.db.DeleteSessionAccessTknXref(id); err != nil {
					c.logger.Error("failed to delete uxsession_accesstoken xref",
						slog.Int("xref_id", id),
						slog.String("access_token_id", xref.AccesstokenId),
						slog.String("err", err.Error()),
					)
					xrefFailed.Store(true)
				}
			}(xref.Id, &wg)
		}
		wg.Wait()
	}

	if xrefFailed.Load() {
		c.logger.Warn("skipping access token delete: one or more xref deletes failed",
			slog.Int("xref_count", len(xrefs)),
		)
		return nil
	}

	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	if err := c.db.DeleteExpiredAccessToken(); err != nil {
		c.logger.Error("failed to delete expired access tokens",
			slog.String("err", err.Error()),
		)
	}

	c.logger.Info("expired access tokens cleaned up",
		slog.Int("count", len(xrefs)),
	)

	return nil
}

// runExpiredS2s executes the expired s2s token deletion for a single cycle.
func (c *cleanup) runExpiredS2s() {
	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	if err := c.db.DeleteExpiredSvcTkns(); err != nil {
		c.logger.Error("failed to delete expired s2s tokens",
			slog.String("err", err.Error()),
		)
	} else {
		c.logger.Info("expired service-to-service tokens cleaned up")
	}
}

// runExpiredSession executes the expired session and associated record deletion for a single cycle.
// Returns an error when either xref query fails, which signals the goroutine to skip the cycle
// via continue rather than permanently exit.
func (c *cleanup) runExpiredSession(hours int) error {

	var wg sync.WaitGroup

	// oauth xrefs — must be deleted before the oauthflow records to avoid constraint violations
	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	// Note: sessions and oauthflow records are created at different times; session created_at is
	// used as the expiry anchor because an oauthflow cannot be used without a valid session.
	xrefsOauth, err := c.db.FindExpiredOauthXrefs(hours)
	if err != nil {
		c.logger.Error("failed to select expired uxsession_oauthflow xrefs",
			slog.String("err", err.Error()),
		)
		return err
	}

	if len(xrefsOauth) > 0 {
		c.logger.Info("removing xrefs between expired sessions and oauth2 values")

		for _, xref := range xrefsOauth {
			wg.Add(1)
			go func(id int, wg *sync.WaitGroup) {
				defer wg.Done()

				if err := c.db.DeleteSessionOauthXref(id); err != nil {
					c.logger.Error("failed to delete uxsession_oauthflow xref",
						slog.Int("xref_id", id),
						slog.String("oauthflow_id", xref.OauthflowId),
						slog.String("err", err.Error()),
					)
				}
			}(xref.Id, &wg)
		}
	}

	// access token xrefs — must be deleted before the session records to avoid constraint violations
	xrefsAuth, err := c.db.FindExpiredAccessTknXrefs(hours)
	if err != nil {
		c.logger.Error("failed to select expired uxsession_accesstoken xrefs",
			slog.String("err", err.Error()),
		)
		// drain any oauth xref goroutines already launched before skipping this cycle
		wg.Wait()
		return err
	}

	if len(xrefsAuth) > 0 {
		c.logger.Info("removing xrefs between expired sessions and access tokens")

		for _, xref := range xrefsAuth {
			wg.Add(1)
			go func(id int, wg *sync.WaitGroup) {
				defer wg.Done()

				if err := c.db.DeleteSessionAccessTknXref(id); err != nil {
					c.logger.Error("failed to delete uxsession_accesstoken xref",
						slog.Int("xref_id", id),
						slog.String("access_token_id", xref.AccesstokenId),
						slog.String("err", err.Error()),
					)
				}
			}(xref.Id, &wg)
		}
	}

	// wait for all xrefs to be deleted before deleting the parent records
	wg.Wait()

	// oauthflow records are no longer referenced by any xrefs at this point
	go func(hours int) {
		if err := c.db.DeleteOauthFlow(hours); err != nil {
			c.logger.Error("failed to delete expired oauthflow values",
				slog.String("err", err.Error()),
			)
		}
		c.logger.Info("expired and unattached oauthflow records cleaned up")
	}(hours)

	// sessions include both authenticated and unauthenticated records
	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	go func(hours int) {
		if err := c.db.DeleteExpiredSession(hours); err != nil {
			c.logger.Error("failed to delete expired user sessions",
				slog.String("err", err.Error()),
			)
		}
		c.logger.Info("expired user sessions cleaned up")
	}(hours)

	return nil
}

// runExpiredAuthcode executes the expired authcode deletion for a single cycle.
// Returns an error when either delete fails, which signals the goroutine to skip the cycle
// via continue rather than permanently exit.
func (c *cleanup) runExpiredAuthcode() error {
	if err := c.db.DeleteAuthCodeXrefs(); err != nil {
		c.logger.Error("failed to delete expired authcode account xref records",
			slog.String("err", err.Error()),
		)
		return err
	}

	// EXPIRIES ARE IN UTC, SO USE UTC TIME
	if err := c.db.DeleteAuthCode(); err != nil {
		c.logger.Error("failed to delete expired authcodes",
			slog.String("err", err.Error()),
		)
		return err
	}

	c.logger.Info("expired authcodes and account xrefs cleaned up")
	return nil
}
