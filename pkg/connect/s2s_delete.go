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

// DeleteFromService makes a DELETE request to a downstream service's endpoint with
// s2s authentication and retry logic including exponential backoff + jitter.
// DELETE is typically used to remove an existing resource (idempotent operation).
// Following REST conventions, the resource to delete is identified by the URL path,
// not a request body. Most DELETE requests return no response body (204 No Content).
func DeleteFromService[TResp any](
	caller S2sCaller,
	ctx context.Context,
	endpoint,
	s2sToken,
	authToken string,
) (TResp, error) {

	// initialize zero value of generic type TResp
	var data TResp

	// build url
	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// extract telemetry from context if exists
	telemetry, ok := GetTelemetryFromContext(ctx)
	if !ok {
		caller.logger.Warn("failed to extract telemetry from context of s2s DeleteFromService call")
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
	for attempt := 0; attempt < caller.RetryConfig.MaxRetries; attempt++ {

		// add attempt counter to logger
		attemptLogger := baseLogger.With(slog.Int("retry.attempt", attempt))

		// set up request (no body for DELETE)
		request, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			return data, &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to create DELETE request: %v", err),
			}
		}

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

		attemptLogger.Info("attempting DELETE request")

		// TlsClient makes http request
		response, err := caller.TlsClient.Do(request)
		if err != nil {
			lastErr = err // set last error for final return if needed
			// check if error is a net.Error and if it is a timeout, etc.
			if nErr, ok := err.(net.Error); ok {
				if nErr.Timeout() {
					if attempt < caller.RetryConfig.MaxRetries-1 {
						// apply backoff/jitter to timeout
						backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
						attemptLogger.Error("request timed out",
							slog.String("err", err.Error()),
							slog.Duration("retry.backoff", backoff),
							slog.Bool("will_retry", willRetry(0, attempt, caller.RetryConfig.MaxRetries)),
						)
						time.Sleep(backoff)
						continue // jump out of the loop to next iteration
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

			return data, &ErrorHttp{
				StatusCode: http.StatusServiceUnavailable,
				Message:    fmt.Sprintf("service unavailable: %v", err),
			}
		}

		// validate Content-Type is application/json (if response body exists)
		// 200, 202, and 204 may not have a response body
		if response.StatusCode != http.StatusOK &&
			response.StatusCode != http.StatusAccepted &&
			response.StatusCode != http.StatusNoContent {
			contentType := response.Header.Get("Content-Type")
			if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
				response.Body.Close() // close response body before returning
				return data, &ErrorHttp{
					StatusCode: http.StatusUnsupportedMediaType,
					Message:    fmt.Sprintf("DELETE request returned unexpected content type: got %v want application/json", contentType),
				}
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
			// 200 OK (with optional response body)
			// 202 Accepted (deletion queued)
			// 204 No Content (most common - no response body)
			if len(body) > 0 {
				if err := json.Unmarshal(body, &data); err != nil {
					return data, &ErrorHttp{
						StatusCode: http.StatusInternalServerError,
						Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
					}
				}
			}

			attemptLogger.Info("DELETE request succeeded",
				slog.Int("status_code", response.StatusCode),
			)

			// success -> jump out of retry and return
			return data, nil

		case response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode > 500 && response.StatusCode <= 599):
			// 5xx -> retry w/ backoff
			// Note: 500 itself is not retried because likely an upstream error with the server where a
			// retry will not help
			var e ErrorHttp
			if len(body) > 0 {
				if err := json.Unmarshal(body, &e); err != nil {
					// jump out of retry loop and return error
					return data, &ErrorHttp{
						StatusCode: http.StatusInternalServerError,
						Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
					}
				}
			} else {
				e = ErrorHttp{
					StatusCode: response.StatusCode,
					Message:    fmt.Sprintf("HTTP %d", response.StatusCode),
				}
			}
			lastErr = &e // set last error for final return if needed

			if attempt < caller.RetryConfig.MaxRetries-1 {
				// apply backoff/jitter to 5xx
				backoff := addJitter(attempt, caller.RetryConfig.BaseBackoff, caller.RetryConfig.MaxBackoff)
				attemptLogger.Error("retryable error, will retry",
					slog.Int("status_code", e.StatusCode),
					slog.String("err", e.Message),
					slog.Duration("retry.backoff", backoff),
					slog.Bool("will_retry", willRetry(e.StatusCode, attempt, caller.RetryConfig.MaxRetries)),
				)
				time.Sleep(backoff)
				continue // jump out of the loop to next iteration
			}

			attemptLogger.Error("retries exhausted",
				slog.Int("status_code", e.StatusCode),
				slog.String("err", e.Message),
			)

			return data, &ErrorHttp{
				StatusCode: response.StatusCode,
				Message:    fmt.Sprintf("retries exhausted: %s", e.Message),
			}

		default:
			// 4xx Errors (and 500) errors -> non-retryable
			var e ErrorHttp
			if len(body) > 0 {
				if err := json.Unmarshal(body, &e); err != nil {
					return data, &ErrorHttp{
						StatusCode: http.StatusInternalServerError,
						Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
					}
				}
			} else {
				e = ErrorHttp{
					StatusCode: response.StatusCode,
					Message:    fmt.Sprintf("HTTP %d", response.StatusCode),
				}
			}

			attemptLogger.Error("non-retryable error",
				slog.Int("status_code", e.StatusCode),
				slog.String("err", e.Message),
			)

			// jump out of retry loop and return error
			return data, &e
		}
	}

	// should never reach here, but just in case
	return data, &ErrorHttp{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("retries exhausted: %v", lastErr),
	}
}
