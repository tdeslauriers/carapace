package connect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetServiceData makes a GET (data) request to a downstream service's endpoint with
// s2s authentication and retry logic including exponetial backoff + jitter.
func GetServiceData[T any](
	ctx context.Context,
	caller *S2sCaller,
	endpoint string,
	s2sToken string,
	authToken string,
) (T, error) {

	// initialize zero value of generic type T
	var data T

	// build url
	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// extract telemetry from context if exists
	telemetry, ok := GetTelemetryFromContext(ctx)
	if !ok {
		caller.logger.Warn("failed to extract telemetry from context of s2s GetServiceData call")
	}

	// add universal fields to baseLogger
	baseLogger := caller.logger.With(
		slog.String("target_service", caller.ServiceName),
		slog.String("target_url", url),
		slog.Int("retry.max_retries", caller.RetryConfig.MaxRetries),
	)

	// add telemetry fields to baseLogger if exists
	if telemetry != nil {
		baseLogger = baseLogger.With(telemetry.TelemetryFields()...)
	}

	// last error for final return if needed -> should not be needed but just in case
	var lastErr error

	// retry loop
	for attempt := 0; attempt <= caller.RetryConfig.MaxRetries; attempt++ {

		// add attempt counter to logger
		attemptLogger := baseLogger.With(slog.Int("retry.attempt", attempt))

		// set up request
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return data, &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to create get request: %v", err),
			}
		}

		// set content type header to application/json
		request.Header.Set("Content-Type", "application/json")

		// set traceparent header from context if exists
		if telemetry != nil {
			request.Header.Set("traceparent", telemetry.Traceparent.BuildTraceparent())
		}

		// set service token service-authorization header
		if s2sToken != "" {
			request.Header.Set("Service-Authorization", fmt.Sprintf("Bearer %s", s2sToken))
		}

		// set user access token authorization header
		if authToken != "" {
			request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
		}

		// TlsClient makes http request
		response, err := caller.TlsClient.Do(request)
		if err != nil {
			lastErr = err // set last error for final return if needed
			// check if network error such as timeout, etc.
			if nErr, ok := err.(net.Error); ok {
				if nErr.Timeout() {
					if attempt < caller.RetryConfig.MaxRetries {
						// apply backoff/jitter to timeout
						backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
						attemptLogger.Error("request timed out",
							slog.Int("status_code", response.StatusCode),
							slog.String("err", err.Error()),
							slog.Duration("retry.backoff", backoff),
							slog.Bool("retry.will_retry", willRetry(response.StatusCode, attempt, caller.RetryConfig.MaxRetries)),
						)
						time.Sleep(backoff)
						continue // jump to next loop iteration
					}

					return data, &ErrorHttp{
						StatusCode: http.StatusServiceUnavailable,
						Message:    "retries exhausted: timeout",
					}
				}

				// log non-timeout network error
				attemptLogger.Error("request yielded a non-timeout network error",
					slog.String("err", err.Error()))

				// jump out of retry loop and return error
				return data, &ErrorHttp{
					StatusCode: http.StatusServiceUnavailable,
					Message:    fmt.Sprintf("service unavailable: %v", err),
				}
			}

			// log non-network error
			attemptLogger.Error("request yielded a non-network error",
				slog.String("err", err.Error()))

			// jump out of retry loop for error that is not net.Error: return 503: Service Unavailable error
			return data, &ErrorHttp{
				StatusCode: http.StatusServiceUnavailable,
				Message:    fmt.Sprintf("service unavailable: %v", err),
			}
		}

		// validate response Content-Type is application/json
		contentType := response.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {

			response.Body.Close() // close response body before returning
			return data, &ErrorHttp{
				StatusCode: http.StatusUnsupportedMediaType,
				Message:    fmt.Sprintf("unexpected content type returned: got %v want application/json", contentType),
			}
		}

		// read response body
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {

			// jump out of retry loop and return error
			return data, &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to read response body: %v", err),
			}
		}

		// handle response status codes
		switch {
		case response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices:
			// 2xx -> success
			if err := json.Unmarshal(body, &data); err != nil {
				return data, &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
				}
			}
			// success -> jump out of retry and return
			return data, nil

		case response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode > 500 && response.StatusCode <= 599):
			// 5xx -> retry w/ backoff
			// Note: 500 itself is not retried because likely an upstream error with the server where a
			// retry will not help, but 502, 503, 504, etc., are retried
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return data, &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
				}
			}
			lastErr = &e // set last error for final return if needed

			if attempt < caller.RetryConfig.MaxRetries {

				// apply backoff/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				attemptLogger.Error("request failed",
					slog.Int("status_code", e.StatusCode),
					slog.String("err", e.Message),
					slog.Duration("retry.backoff", backoff),
					slog.Bool("retry.will_retry", willRetry(e.StatusCode, attempt, caller.RetryConfig.MaxRetries)),
				)
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			}

			attemptLogger.Error(" retries exhausted",
				slog.Int("status_code", e.StatusCode),
				slog.String("err", e.Message))

			return data, &ErrorHttp{
				StatusCode: response.StatusCode,
				Message:    fmt.Sprintf("retries exhausted: %s", e.Message),
			}
		default:
			// 4xx (and 500) errors -> non-retryable
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				return data, &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
				}
			}
			return data, &e
		}
	}

	// should never reach here, but just in case
	return data, &ErrorHttp{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("retries exhausted: %v", lastErr),
	}
}
