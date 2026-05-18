package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect/telemetry"
)

// testPayload is the generic response type used across s2s tests.
type testPayload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// testCmd is the generic request body type used for mutation (POST/PUT/PATCH) tests.
type testCmd struct {
	Field string `json:"field"`
}

// mockNetError implements net.Error so tests can simulate timeout and non-timeout
// network-level failures without a real socket.
type mockNetError struct {
	isTimeout bool
}

func (e *mockNetError) Error() string   { return "mock network error" }
func (e *mockNetError) Timeout() bool   { return e.isTimeout }
func (e *mockNetError) Temporary() bool { return false }

// mockTlsClient returns pre-configured HTTP responses in the order they were
// added and captures every *http.Request for header inspection.
// If callCount exceeds the number of configured responses the last entry is repeated.
type mockTlsClient struct {
	responses        []*http.Response
	errors           []error
	callCount        int
	capturedRequests []*http.Request
}

func (m *mockTlsClient) Do(req *http.Request) (*http.Response, error) {
	m.capturedRequests = append(m.capturedRequests, req)
	i := m.callCount
	m.callCount++
	if i >= len(m.responses) {
		i = len(m.responses) - 1
	}
	return m.responses[i], m.errors[i]
}

// callerWithRetries builds an S2sCaller backed by mock with near-zero backoff so
// retry tests finish in microseconds rather than seconds.
// BaseBackoff must be >= 2ns: addJitter divides by 2 and rand.Int63n panics on 0.
func callerWithRetries(mock *mockTlsClient, maxRetries int) *S2sCaller {
	return NewS2sCaller(
		"https://svc.example.internal",
		"test-service",
		mock,
		RetryConfiguration{
			MaxRetries:  maxRetries,
			BaseBackoff: 2 * time.Nanosecond,
			MaxBackoff:  2 * time.Nanosecond,
		},
	)
}

func noTelemetryCtx() context.Context { return context.Background() }

func telemetryCtx() context.Context {
	tel := &telemetry.Telemetry{
		Traceparent: telemetry.Traceparent{
			Version: "00",
			TraceId: strings.Repeat("4b", 16),
			SpanId:  strings.Repeat("a3", 8),
			Flags:   "01",
		},
		RemoteAddr: "10.0.0.1",
		UserAgent:  "test-agent/1.0",
	}
	return context.WithValue(context.Background(), telemetry.TelemetryKey, tel)
}

// jsonResp returns an *http.Response with Content-Type: application/json and a
// JSON-marshalled body.
func jsonResp(t *testing.T, statusCode int, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("jsonResp: marshal: %v", err)
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

// errResp returns a JSON response whose body is a serialised ErrorHttp.
func errResp(t *testing.T, statusCode int, msg string) *http.Response {
	t.Helper()
	return jsonResp(t, statusCode, ErrorHttp{StatusCode: statusCode, Message: msg})
}

// emptyResp returns a response with an empty body (e.g. 204 No Content).
func emptyResp(statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
}

// garbledResp returns a response whose Content-Type claims JSON but whose body
// cannot be unmarshalled.
func garbledResp(statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("{not valid json"))),
	}
}

// wrongContentTypeResp returns a response with Content-Type: text/plain but a
// valid JSON body, used to verify content-type enforcement.
func wrongContentTypeResp(t *testing.T, statusCode int, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("wrongContentTypeResp: marshal: %v", err)
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}
