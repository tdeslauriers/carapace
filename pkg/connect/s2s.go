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
	"github.com/tdeslauriers/carapace/pkg/jwt"
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
	// Make a GET request to a service endpoint, providing the service-to-service token and user access token (if available).
	// The response body is unmarshaled into the provided data interface.
	GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error

	// Make a POST request to a service endpoint, providing the service-to-service token and user access token (if available).
	// The request body is marshaled from the provided cmd interface, and the response body is unmarshaled into the provided data interface.
	PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error

	// RespondUpstreamError is a function to handle errors from upstream services.
	// It takes in an error and http.ResponseWriter in order to handle writing the error to the http.ResponseWriter.
	RespondUpstreamError(err error, w http.ResponseWriter)
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
			return &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("unable to create get request for %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err),
			}
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

		// TlsClient makes http request
		response, err := caller.TlsClient.Do(request)
		if err != nil {
			// check if network error such as timeout, etc.
			if nErr, ok := err.(net.Error); ok {
				if nErr.Timeout() {
					// apply backout/jitter to timeout
					backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
					caller.logger.Error(fmt.Sprintf("attempt %d - %s service get-request to %s timed out (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), "err", err.Error())
					time.Sleep(backoff)
					continue // jump to next loop iteration
				} else {
					// jump out of retry loop and return 503: Service Unavailable error
					return &ErrorHttp{
						StatusCode: http.StatusServiceUnavailable,
						Message:    fmt.Sprintf("service unavailable: attempt %d - %s service get-request to %s yielded a non-timeout network error: %v", attempt+1, caller.ServiceName, endpoint, err),
					}
				}
			}
			// jump out of retry loop for error that is not net.Error: return 503: Service Unavailable error
			return &ErrorHttp{
				StatusCode: http.StatusServiceUnavailable,
				Message:    fmt.Sprintf("service unavailable: attempt %d - %s service get-request to %s yielded a non-network error: %v", attempt+1, caller.ServiceName, endpoint, err),
			}
		}

		// validate response Content-Type is application/json
		contentType := response.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			return &ErrorHttp{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    fmt.Sprintf("unexpected content type returned from %s service get-request to %s: got %v want application/json", caller.ServiceName, endpoint, contentType),
			}
		}

		// read response body
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			// jump out of retry loop and return error
			return &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("unable to read response body from %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err),
			}
		}

		// handle response status codes 2xx, 4xx, 5xx
		// 2xx -> success
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {

			if err := json.Unmarshal(body, data); err != nil {
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(data), caller.ServiceName, endpoint, err),
				}
			}
			return nil // success -> jump out of retry and return

			// 5xx -> retry w/ backoff
		} else if response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode >= 500 && response.StatusCode <= 599) {

			// 5xx ErrorsHttps generated upstream by local services:  handle retry: w/ backoff
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err),
				}
			}

			if attempt < caller.RetryConfig.MaxRetries-1 {

				// apply backout/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				caller.logger.Error(fmt.Sprintf("attempt %d - GET request to %s service's endpoint %s failed: (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), "err", fmt.Sprintf("%d: %s", e.StatusCode, e.Message))
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			} else {
				return &ErrorHttp{
					StatusCode: response.StatusCode,
					Message:    fmt.Sprintf("attempt %d - received '%d: %s' from get request to %s service's endpoint %s: retries exhausted", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint),
				}
			}

			// 4xx Errors
		} else {

			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("unable to unmarshal response body json to %v from  %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err),
				}
			}
			// jump out of retry loop and return error
			return &ErrorHttp{
				StatusCode: e.StatusCode,
				Message:    fmt.Sprintf("received '%d: %s' from get-service-data call to %s service's endpoint %s", e.StatusCode, e.Message, caller.ServiceName, endpoint),
			}
		}
	}
	return nil
}

// post to service (includes retry logic)
func (caller *s2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// retry loop
	for attempt := 0; attempt < caller.RetryConfig.MaxRetries; attempt++ {

		// marshal data
		jsonData, err := json.Marshal(cmd)
		if err != nil {
			return &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to marshal data to json for %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err),
			}
		}

		// set up request
		request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to create POST request for %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err),
			}
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
					caller.logger.Error(fmt.Sprintf("attempt %d - POST request to %s service's endpoint %s timed out (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), "err", err.Error())
					time.Sleep(backoff)
					continue // jump to next loop iteration
				} else {

					// jump out of retry loop and return error
					return &ErrorHttp{
						StatusCode: http.StatusServiceUnavailable,
						Message:    fmt.Sprintf("attempt %d - POST request to %s service's %s endpoint yielded a non-timeout network error: %v", attempt+1, caller.ServiceName, endpoint, err),
					}
				}
			}
			// jump out of retry loop for error that is not net.Error
			return &ErrorHttp{
				StatusCode: http.StatusServiceUnavailable,
				Message:    fmt.Sprintf("attempt %d - POST request to %s service's %s endpoint yielded a non-network error: %v", attempt+1, caller.ServiceName, endpoint, err),
			}
		}

		// validate Content-Type is application/json
		contentType := response.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			return &ErrorHttp{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    fmt.Sprintf("POST request to %s service's %s endpoint returned unexpected content type: got %v want application/json", caller.ServiceName, endpoint, contentType),
			}
		}

		// read response body
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			// jump out of retry loop and return error
			return &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to read response body from %s service's endpoint '%s': %v", caller.ServiceName, endpoint, err),
			}
		}

		// handle response status codes 2xx, 4xx, 5xx
		// 2xx -> success
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {

			if err := json.Unmarshal(body, data); err != nil {
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(data), caller.ServiceName, endpoint, err),
				}
			}
			return nil // success -> jump out of retry and return

			// 5xx -> retry w/ backoff
		} else if response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode >= 500 && response.StatusCode <= 599) {

			// handle retry: 5xx Errors w/ backoff
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err),
				}
			}

			if attempt < caller.RetryConfig.MaxRetries-1 {

				// apply backout/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				caller.logger.Error(fmt.Sprintf("attempt %d - POST request to %s service's endpoint %s failed: (retrying in %v...)", attempt+1, caller.ServiceName, endpoint, backoff), "err", fmt.Sprintf("%d: %s", e.StatusCode, e.Message))
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			} else {
				return &ErrorHttp{
					StatusCode: response.StatusCode,
					Message:    fmt.Sprintf("attempt %d - received '%d: %s' from POST request to %s service's endpoint %s: retries exhausted", attempt+1, e.StatusCode, e.Message, caller.ServiceName, endpoint),
				}
			}

			// 4xx Errors
		} else {

			// 4xx Errors
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				return &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("unable to unmarshal response body json to %v from %s service's endpoint '%s': %v", reflect.TypeOf(&e), caller.ServiceName, endpoint, err),
				}
			}
			// jump out of retry loop and return error
			return &ErrorHttp{
				StatusCode: e.StatusCode,
				Message:    fmt.Sprintf("received '%d: %s' from POST call to %s service's endpoint %s", e.StatusCode, e.Message, caller.ServiceName, endpoint),
			}
		}
	}
	return nil
}

// handle upstream errors returned by the other two above funtions.
// Adds in meta data to the logging from the caller struct.
func (caller *s2sCaller) RespondUpstreamError(err error, w http.ResponseWriter) {

	// checks for expected ErrorHttp type and handles logging and writing to response if different type
	errMsg, ok := err.(*ErrorHttp)
	if !ok {
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// handle ErrorHttp type errors
	switch errMsg.StatusCode {
	case http.StatusBadRequest:
		e := ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusUnauthorized:
		// s2s token unauthorized
		if errMsg.Message == jwt.S2sUnauthorizedErrMsg {
			e := ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error",
			}
			e.SendJsonErr(w)
			break
		}

		// user token unauthorized
		if errMsg.Message == jwt.UserUnauthorizedErrMsg {
			e := ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    "unauthorized",
			}
			e.SendJsonErr(w)
			break
		}
	case http.StatusForbidden:
		// call returned forbidden for s2s token
		if errMsg.Message == jwt.S2sForbiddenErrMsg {
			e := ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error", // this should never happen --> means I didnt provision the service correctly
			}
			e.SendJsonErr(w)
			break
		}

		// call returned forbidden for user token
		if errMsg.Message == jwt.UserForbdiddenErrMsg {
			e := ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    "forbidden",
			}
			e.SendJsonErr(w)
			break
		}

	case http.StatusMethodNotAllowed:
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error", // this should never happen -> means calling service was written using wrong method
		}
		e.SendJsonErr(w)

		// returns conflict error from the upstream service, eg. "username unavailable"
	case http.StatusConflict:
		e := ErrorHttp{
			StatusCode: http.StatusConflict,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

		// this returns validation errors from the upstream service
	case http.StatusUnprocessableEntity:
		e := ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

		// this returns data processing errors from the upstream service like "unexpected content type"
	case http.StatusUnsupportedMediaType:
		e := ErrorHttp{
			StatusCode: http.StatusUnsupportedMediaType,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusServiceUnavailable:
		e := ErrorHttp{
			StatusCode: http.StatusServiceUnavailable,
			Message:    "required service unavailable",
		}
		e.SendJsonErr(w)

	default:
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
	}
}
