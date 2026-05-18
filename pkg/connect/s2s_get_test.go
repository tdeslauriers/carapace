package connect

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetServiceData(t *testing.T) {
	payload := testPayload{ID: "abc", Name: "test"}

	// NOTE: The GET timeout path cannot be safely tested:
	// - The loop bound and the inner retry guard are both "attempt < MaxRetries",
	//   so the in-switch "retries exhausted: timeout" branch is dead code.
	// - Any timeout that occurs inside the loop will try to retry and will
	//   dereference response.StatusCode (nil) → panic.
	// These are known bugs identified in the review; fix them before adding
	// a GET timeout test.

	tests := []struct {
		name            string
		ctx             func() context.Context
		s2sToken        string
		authToken       string
		maxRetries      int
		responses       []*http.Response
		errs            []error
		wantErr         bool
		wantStatusCode  int
		wantMsgContains string
		wantData        *testPayload
		wantCallCount   int
		checkReq        func(t *testing.T, req *http.Request)
	}{
		// ---- success paths --------------------------------------------------
		{
			name:       "200 ok returns unmarshalled data",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if req.Method != http.MethodGet {
					t.Errorf("method: want GET, got %s", req.Method)
				}
				if ct := req.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type: want application/json, got %s", ct)
				}
			},
			wantCallCount: 1,
		},
		{
			name:          "201 created returns unmarshalled data",
			ctx:           noTelemetryCtx,
			maxRetries:    1,
			responses:     []*http.Response{jsonResp(t, http.StatusCreated, payload)},
			errs:          []error{nil},
			wantData:      &payload,
			wantCallCount: 1,
		},
		// ---- outgoing header checks -----------------------------------------
		{
			name:       "s2s token sets Service-Authorization header",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			s2sToken:   "s2s-token-value",
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				want := "Bearer s2s-token-value"
				if got := req.Header.Get("Service-Authorization"); got != want {
					t.Errorf("Service-Authorization: want %q, got %q", want, got)
				}
			},
		},
		{
			name:       "empty s2s token omits Service-Authorization header",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			s2sToken:   "",
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got := req.Header.Get("Service-Authorization"); got != "" {
					t.Errorf("Service-Authorization should be absent, got %q", got)
				}
			},
		},
		{
			name:       "auth token sets Authorization header",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			authToken:  "user-access-token",
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				want := "Bearer user-access-token"
				if got := req.Header.Get("Authorization"); got != want {
					t.Errorf("Authorization: want %q, got %q", want, got)
				}
			},
		},
		{
			name:       "empty auth token omits Authorization header",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			authToken:  "",
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got := req.Header.Get("Authorization"); got != "" {
					t.Errorf("Authorization should be absent, got %q", got)
				}
			},
		},
		{
			name:       "telemetry context sets traceparent header",
			ctx:        telemetryCtx,
			maxRetries: 1,
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got := req.Header.Get("traceparent"); got == "" {
					t.Error("traceparent header should be set when telemetry context is present")
				}
			},
		},
		{
			name:       "no telemetry context omits traceparent header",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if got := req.Header.Get("traceparent"); got != "" {
					t.Errorf("traceparent should be absent without telemetry context, got %q", got)
				}
			},
		},
		// ---- content-type validation ----------------------------------------
		{
			name:           "non-json content type returns 415",
			ctx:            noTelemetryCtx,
			maxRetries:     1,
			responses:      []*http.Response{wrongContentTypeResp(t, http.StatusOK, payload)},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusUnsupportedMediaType,
			wantCallCount:  1,
		},
		// ---- non-retryable 4xx errors ---------------------------------------
		{
			name:           "400 bad request returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusBadRequest, "bad request")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusBadRequest,
			wantCallCount:  1,
		},
		{
			name:           "401 unauthorized returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusUnauthorized, "unauthorized")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusUnauthorized,
			wantCallCount:  1,
		},
		{
			name:           "403 forbidden returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusForbidden, "forbidden")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusForbidden,
			wantCallCount:  1,
		},
		{
			name:           "404 not found returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusNotFound, "not found")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusNotFound,
			wantCallCount:  1,
		},
		{
			name:           "409 conflict returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusConflict, "conflict")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusConflict,
			wantCallCount:  1,
		},
		{
			name:           "422 unprocessable entity returns immediately without retry",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusUnprocessableEntity, "validation failed")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusUnprocessableEntity,
			wantCallCount:  1,
		},
		// ---- 500 falls into the default (non-retryable) case ----------------
		{
			name:           "500 internal server error is not retried",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{errResp(t, http.StatusInternalServerError, "internal error")},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
			wantCallCount:  1,
		},
		// ---- retryable status codes -----------------------------------------
		// GET loop bound is <= MaxRetries, so MaxRetries=2 gives attempts 0,1,2.
		// Guard is attempt < MaxRetries, so attempts 0 and 1 trigger a retry.
		{
			name:          "429 too many requests retries and then succeeds",
			ctx:           noTelemetryCtx,
			maxRetries:    2,
			responses:     []*http.Response{errResp(t, http.StatusTooManyRequests, "rate limited"), jsonResp(t, http.StatusOK, payload)},
			errs:          []error{nil, nil},
			wantData:      &payload,
			wantCallCount: 2,
		},
		{
			name:          "502 bad gateway retries and then succeeds",
			ctx:           noTelemetryCtx,
			maxRetries:    2,
			responses:     []*http.Response{errResp(t, http.StatusBadGateway, "bad gateway"), jsonResp(t, http.StatusOK, payload)},
			errs:          []error{nil, nil},
			wantData:      &payload,
			wantCallCount: 2,
		},
		{
			name:          "503 service unavailable retries and then succeeds",
			ctx:           noTelemetryCtx,
			maxRetries:    2,
			responses:     []*http.Response{errResp(t, http.StatusServiceUnavailable, "down"), jsonResp(t, http.StatusOK, payload)},
			errs:          []error{nil, nil},
			wantData:      &payload,
			wantCallCount: 2,
		},
		// ---- retries exhausted ----------------------------------------------
		// MaxRetries=2: loop runs attempts 0 and 1 (both guard < MaxRetries → true →
		// retry via continue). The loop exits normally after attempt 1 and the
		// post-loop fallback returns "retries exhausted".
		{
			name:            "5xx retries exhausted returns wrapped error",
			ctx:             noTelemetryCtx,
			maxRetries:      2,
			responses:       []*http.Response{errResp(t, http.StatusServiceUnavailable, "down"), errResp(t, http.StatusServiceUnavailable, "down")},
			errs:            []error{nil, nil},
			wantErr:         true,
			wantMsgContains: "retries exhausted",
			wantCallCount:   2,
		},
		{
			name:           "non-timeout network error returns 503",
			ctx:            noTelemetryCtx,
			maxRetries:     1,
			responses:      []*http.Response{nil},
			errs:           []error{&mockNetError{isTimeout: false}},
			wantErr:        true,
			wantStatusCode: http.StatusServiceUnavailable,
			wantCallCount:  1,
		},
		{
			name:           "non-network transport error returns 503",
			ctx:            noTelemetryCtx,
			maxRetries:     1,
			responses:      []*http.Response{nil},
			errs:           []error{errors.New("connection refused")},
			wantErr:        true,
			wantStatusCode: http.StatusServiceUnavailable,
			wantCallCount:  1,
		},
		// ---- JSON decode errors ---------------------------------------------
		{
			name:           "garbled json on 2xx body returns 500",
			ctx:            noTelemetryCtx,
			maxRetries:     1,
			responses:      []*http.Response{garbledResp(http.StatusOK)},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
			wantCallCount:  1,
		},
		{
			name:           "garbled json on retryable 5xx body returns 500 immediately",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{garbledResp(http.StatusBadGateway)},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
			wantCallCount:  1,
		},
		{
			name:           "garbled json on 4xx body returns 500 immediately",
			ctx:            noTelemetryCtx,
			maxRetries:     2,
			responses:      []*http.Response{garbledResp(http.StatusBadRequest)},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusInternalServerError,
			wantCallCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockTlsClient{responses: tt.responses, errors: tt.errs}
			caller := callerWithRetries(mock, tt.maxRetries)

			got, err := GetServiceData[testPayload](tt.ctx(), caller, "/api/resource", tt.s2sToken, tt.authToken)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantStatusCode != 0 {
					httpErr, ok := err.(*ErrorHttp)
					if !ok {
						t.Fatalf("expected *ErrorHttp, got %T: %v", err, err)
					}
					if httpErr.StatusCode != tt.wantStatusCode {
						t.Errorf("StatusCode: want %d, got %d (msg: %s)", tt.wantStatusCode, httpErr.StatusCode, httpErr.Message)
					}
				}
				if tt.wantMsgContains != "" && !strings.Contains(err.Error(), tt.wantMsgContains) {
					t.Errorf("error message: want contains %q, got %q", tt.wantMsgContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.wantData != nil && got != *tt.wantData {
					t.Errorf("data: want %+v, got %+v", *tt.wantData, got)
				}
			}

			if tt.wantCallCount > 0 && mock.callCount != tt.wantCallCount {
				t.Errorf("HTTP calls: want %d, got %d", tt.wantCallCount, mock.callCount)
			}

			if tt.checkReq != nil && len(mock.capturedRequests) > 0 {
				tt.checkReq(t, mock.capturedRequests[0])
			}
		})
	}
}
