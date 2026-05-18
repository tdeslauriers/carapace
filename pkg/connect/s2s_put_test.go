package connect

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestPutToService(t *testing.T) {
	payload := testPayload{ID: "abc", Name: "test"}
	cmd := testCmd{Field: "value"}

	// PUT passes 0 (not response.StatusCode) to willRetry on timeout, so the
	// timeout-retry path is safe to exercise here, unlike GET and POST.

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
			name:       "200 ok with json body",
			ctx:        noTelemetryCtx,
			maxRetries: 1,
			responses:  []*http.Response{jsonResp(t, http.StatusOK, payload)},
			errs:       []error{nil},
			wantData:   &payload,
			checkReq: func(t *testing.T, req *http.Request) {
				t.Helper()
				if req.Method != http.MethodPut {
					t.Errorf("method: want PUT, got %s", req.Method)
				}
				if ct := req.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type: want application/json, got %s", ct)
				}
			},
			wantCallCount: 1,
		},
		{
			// 204 body is empty; the 2xx branch skips unmarshal when len(body)==0.
			name:          "204 no content returns zero value without error",
			ctx:           noTelemetryCtx,
			maxRetries:    1,
			responses:     []*http.Response{emptyResp(http.StatusNoContent)},
			errs:          []error{nil},
			wantCallCount: 1,
		},
		{
			name:          "201 created with json body",
			ctx:           noTelemetryCtx,
			maxRetries:    1,
			responses:     []*http.Response{jsonResp(t, http.StatusCreated, payload)},
			errs:          []error{nil},
			wantData:      &payload,
			wantCallCount: 1,
		},
		// ---- content-type enforcement ----------------------------------------
		{
			// 200 and 204 bypass the content-type check.
			// 200 with wrong content-type still succeeds because the check is skipped.
			name:          "200 with wrong content-type but valid json body succeeds",
			ctx:           noTelemetryCtx,
			maxRetries:    1,
			responses:     []*http.Response{wrongContentTypeResp(t, http.StatusOK, payload)},
			errs:          []error{nil},
			wantData:      &payload,
			wantCallCount: 1,
		},
		{
			// 201 is not in the bypass list; text/plain triggers 415.
			name:           "201 with non-json content type returns 415",
			ctx:            noTelemetryCtx,
			maxRetries:     1,
			responses:      []*http.Response{wrongContentTypeResp(t, http.StatusCreated, payload)},
			errs:           []error{nil},
			wantErr:        true,
			wantStatusCode: http.StatusUnsupportedMediaType,
			wantCallCount:  1,
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
		// ---- 500 falls through to the default (non-retryable) case ----------
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
		// PUT loop bound is < MaxRetries; MaxRetries=2 gives attempts 0 and 1.
		// Guard is attempt < MaxRetries-1, so only attempt 0 triggers a retry.
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
		// MaxRetries=2: attempt 0 retries (guard 0<1), attempt 1 exhausts (guard 1<1 false).
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
		// ---- network errors -------------------------------------------------
		// PUT passes 0 to willRetry on timeout, so the retry path is safe.
		// MaxRetries=2: attempt 0 times out (retry, guard 0<1), attempt 1 succeeds.
		{
			name:          "timeout retries and then succeeds",
			ctx:           noTelemetryCtx,
			maxRetries:    2,
			responses:     []*http.Response{nil, jsonResp(t, http.StatusOK, payload)},
			errs:          []error{&mockNetError{isTimeout: true}, nil},
			wantData:      &payload,
			wantCallCount: 2,
		},
		{
			// MaxRetries=2: attempt 0 times out (retry), attempt 1 times out (guard 1<1 false → exhausted).
			name:            "timeout retries exhausted returns 503",
			ctx:             noTelemetryCtx,
			maxRetries:      2,
			responses:       []*http.Response{nil, nil},
			errs:            []error{&mockNetError{isTimeout: true}, &mockNetError{isTimeout: true}},
			wantErr:         true,
			wantStatusCode:  http.StatusServiceUnavailable,
			wantMsgContains: "retries exhausted: timeout",
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

			got, err := PutToService[testCmd, testPayload](tt.ctx(), caller, "/api/resource", tt.s2sToken, tt.authToken, cmd)

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
