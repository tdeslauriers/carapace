package connect

import (
	"bytes"
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

// PatchToService makes a PATCH request to a downstream service's endpoint with
// s2s authentication and retry logic including exponential backoff + jitter.
// PATCH is typically used for partial updates to existing resources (idempotent operation).
// Unlike PUT which replaces the entire resource, PATCH only updates specified fields.
func PatchToService[TCmd any, TResp any](
	ctx context.Context,
	caller *S2sCaller,
	endpoint,
	s2sToken,
	authToken string,
	cmd TCmd,
) (TResp, error) {

	// initialize zero value of generic type TResp
	var data TResp

	// build url
	url := fmt.Sprintf("%s%s", caller.ServiceUrl, endpoint)

	// extract telemetry from context if exists
	telemetry, ok := GetTelemetryFromContext(ctx)
	if !ok {
		caller.logger.Warn("failed to extract telemetry from context of s2s PatchToService call")
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

		// marshal command data
		jsonData, err := json.Marshal(cmd)
		if err != nil {

			return data, &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to marshal data to json: %v", err),
			}
		}

		// set up request
		request, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return data, &ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to create PATCH request: %v", err),
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

		// validate Content-Type is application/json
		// 200 and 204 may not have a response body -> check status code 200 and 204
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
			contentType := response.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {

				response.Body.Close() // close response body before returning
				return data, &ErrorHttp{
					StatusCode: http.StatusUnsupportedMediaType,
					Message:    fmt.Sprintf("PATCH request returned unexpected content type: got %v want application/json", contentType),
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
			// 200 and 204 -> may not have a response body
			if len(body) > 0 {
				if err := json.Unmarshal(body, &data); err != nil {
					return data, &ErrorHttp{
						StatusCode: http.StatusInternalServerError,
						Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
					}
				}
			}
			// success -> jump out of retry and return
			return data, nil

		case response.StatusCode == http.StatusTooManyRequests ||
			(response.StatusCode > 500 && response.StatusCode <= 599):
			// 5xx -> retry w/ backoff
			// Note: 500 itself is not retried because likely an upstream error with the server where a
			// retry will not help
			var e ErrorHttp
			if err := json.Unmarshal(body, &e); err != nil {
				// jump out of retry loop and return error
				return data, &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
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
			if err := json.Unmarshal(body, &e); err != nil {
				return data, &ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to unmarshal response body json: %v", err),
				}
			}

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
