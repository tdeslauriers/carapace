package connect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
)

var rng *rand.Rand

// retries and jitter
func init() {
	// initialize global random num gen -> jitter
	seed := time.Now().UnixNano()
	rng = rand.New(rand.NewSource(seed))
}

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

type RetryConfiguration struct {
	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

type S2sCaller interface {
	GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error
	PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error
}

var _ S2sCaller = (*s2sCaller)(nil)

// http getting json formatted data
type s2sCaller struct {
	ServiceUrl  string
	ServiceName string
	TlsClient   TlsClient
	RetryConfig RetryConfiguration

	logger *slog.Logger
}

func NewS2sCaller(url, name string, client TlsClient, retry RetryConfiguration) S2sCaller {
	return &s2sCaller{
		ServiceUrl:  url,
		ServiceName: name,
		TlsClient:   client,
		RetryConfig: retry,

		logger: slog.Default().With(slog.String(config.PackageKey, config.PackageConnect), slog.String(config.ServiceKey, config.ServiceCarapace)),
	}
}

// get data (includes retry logic)
func (caller *s2sCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {

	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// retry loop
	for attempt := 0; attempt < caller.RetryConfig.MaxRetries; attempt++ {

		// set up request
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("unable to create get request for %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err)
		}
		request.Header.Set("Content-Type", "application/json")

		// service token
		if s2sToken != "" {
			request.Header.Set("Service-Authorization", fmt.Sprintf("Bearer %s", s2sToken))
		}

		// user access token
		if authToken != "" {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
		}

		response, err := caller.TlsClient.Do(request)
		if err != nil {
			if nErr, ok := err.(net.Error); ok {
				if nErr.Timeout() {

					// apply backout/jitter to timeout
					backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
					caller.logger.Error(fmt.Sprintf("attempt %d - %s service get-request to %s timed out (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), err)
					time.Sleep(backoff)
					continue // jump to next loop iteration
				} else {

					// jump out of retry loop and return error
					return fmt.Errorf("attempt %d - %s service get-request to %s yielded a non-timeout network error: %v", attempt+1, caller.ServiceName, endpoint, err)
				}
			}
			// jump out of retry loop for error that is not net.Error
			return fmt.Errorf("attempt %d - %s service get-request to %s yielded a non-network error: %v", attempt+1, caller.ServiceName, endpoint, err)
		}

		// validate Content-Type is application/json
		contentType := response.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			return fmt.Errorf("unexpected content type: got %v want application/json", contentType)
		}

		// read response body
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			// jump out of retry loop and return error
			return fmt.Errorf("unable to read response body from %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err)
		}

		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {

			if err := json.Unmarshal(body, data); err != nil {
				return fmt.Errorf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(data), caller.ServiceName, endpoint, err)
			}
			return nil // success -> jump out of retry and return

		} else if response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode >= 500 && response.StatusCode <= 599) {

			// handle retry: 5xx Errors w/ backoff
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return fmt.Errorf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err)
			}

			if attempt < caller.RetryConfig.MaxRetries-1 {

				// apply backout/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				caller.logger.Error(fmt.Sprintf("attempt %d - received '%d: %s' from GET request to %s service's endpoint %s: (retrying in %v...)", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint, backoff))
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			} else {
				return fmt.Errorf("attempt %d - received '%d: %s' from get request to %s service's endpoint %s: retries exhausted", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint)
			}
		} else {

			// 4xx Errors
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				return fmt.Errorf("unable to unmarshal response body json to %v from  %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err)
			}
			// jump out of retry loop and return error
			return fmt.Errorf("received '%d: %s' from get-service-data call to %s service's endpoint %s", e.StatusCode, e.Message, caller.ServiceName, endpoint)
		}
	}
	return nil
}

// post to service (includes retry logic)
func (caller *s2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// retry loop
	for attempt := 0; attempt < caller.RetryConfig.MaxRetries; attempt++ {

		// set up request
		// marshal data
		jsonData, err := json.Marshal(cmd)
		if err != nil {
			return fmt.Errorf("unable to marshall cmd %v to json: %v", reflect.TypeOf(cmd), err)
		}

		request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("unable to create post request for endpoint '%s': %v", url, err)
		}
		request.Header.Set("Content-Type", "application/json")

		// service token
		if s2sToken != "" {
			request.Header.Set("Service-Authorization", fmt.Sprintf("Bearer %s", s2sToken))
		}

		// user access token
		if authToken != "" {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
		}

		response, err := caller.TlsClient.Do(request)
		if err != nil {
			if nErr, ok := err.(net.Error); ok {
				if nErr.Timeout() {

					// apply backout/jitter to timeout
					backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
					caller.logger.Error(fmt.Sprintf("attempt %d - %s service POST request to %s timed out (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), err)
					time.Sleep(backoff)
					continue // jump to next loop iteration
				} else {

					// jump out of retry loop and return error
					return fmt.Errorf("attempt %d - %s service post-request to %s yielded a non-timeout network error: %v", attempt+1, caller.ServiceName, endpoint, err)
				}
			}
			// jump out of retry loop for error that is not net.Error
			return fmt.Errorf("attempt %d - %s service post-request to %s yielded a non-network error: %v", attempt+1, caller.ServiceName, endpoint, err)
		}

		// validate Content-Type is application/json
		contentType := response.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			return fmt.Errorf("unexpected content type: got %v want application/json", contentType)
		}

		// read response body
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			// jump out of retry loop and return error
			return fmt.Errorf("unable to read response body from %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err)
		}

		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {

			if err := json.Unmarshal(body, data); err != nil {
				return fmt.Errorf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(data), caller.ServiceName, endpoint, err)
			}
			return nil // success -> jump out of retry and return

		} else if response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode >= 500 && response.StatusCode <= 599) {

			// handle retry: 5xx Errors w/ backoff
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return fmt.Errorf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err)
			}

			if attempt < caller.RetryConfig.MaxRetries-1 {

				// apply backout/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				caller.logger.Error(fmt.Sprintf("attempt %d - received '%d: %s' from post request to %s service's endpoint %s: (retrying in %v...)", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint, backoff))
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			} else {
				return fmt.Errorf("attempt %d - received '%d: %s' from post request to %s service's endpoint %s: retries exhausted", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint)
			}
		} else {

			// 4xx Errors
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				return fmt.Errorf("unable to unmarshal response body json to %v from  %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err)
			}
			// jump out of retry loop and return error
			return fmt.Errorf("received '%d: %s' from post-service-data call to %s service's endpoint %s", e.StatusCode, e.Message, caller.ServiceName, endpoint)
		}
	}
	return nil
}
