package connect

import (
	"log/slog"
	"math/rand"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/internal/util"
)

var rng *rand.Rand

// retries and jitter
func init() {
	// initialize global random num gen -> jitter
	seed := time.Now().UnixNano()
	rng = rand.New(rand.NewSource(seed))
}

// add jitter to backoff so that retying services do not all retry at the same time
func addJitter(attempt int, baseBackoff, maxBackoff time.Duration) time.Duration {
	// Get the next exponential backoff interval
	backoff := baseBackoff * time.Duration(1<<attempt)

	// Use the custom Rand instance for jitter calculation
	jitter := backoff/2 + time.Duration(rng.Int63n(int64(backoff/2)))

	// Check that the backoff is not too big
	if jitter > maxBackoff {
		jitter = maxBackoff
	}

	return jitter
}

// willRetry checks if we should retry based on the error and attempt number
func willRetry(statusCode, attempt, maxRetries int) bool {
	if attempt < maxRetries {
		return true
	}

	// 500 is used by upstream services to indicate an internal server error, so we do not retry on that
	// since whatever the issue is, retrying will not help.
	if statusCode == http.StatusTooManyRequests ||
		(statusCode > 500 && statusCode <= 599) {
		return true
	}

	return false
}

// RetryConfiguration is a struct that holds the configuration for retrying service calls.
type RetryConfiguration struct {
	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// S2sCaller is used to call downstream services with s2s authentication and retry logic.
type S2sCaller struct {
	ServiceUrl  string
	ServiceName string
	TlsClient   TlsClient
	RetryConfig RetryConfiguration

	logger *slog.Logger
}

// NewS2sCaller creates a new S2sCaller interface with underlying implementation.
func NewS2sCaller(url, name string, client TlsClient, retry RetryConfiguration) *S2sCaller {
	return &S2sCaller{
		ServiceUrl:  url,
		ServiceName: name,
		TlsClient:   client,
		RetryConfig: retry,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageConnect)).
			With(slog.String(util.ComponentKey, util.ComponentS2sCaller)).
			With(slog.String(util.ServiceKey, util.FrameworkCarapace)),
	}
}
