package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// findAttr searches for an slog.Attr by key within the slice returned by TelemetryFields.
func findAttr(fields []any, key string) (slog.Attr, bool) {
	for _, f := range fields {
		if attr, ok := f.(slog.Attr); ok && attr.Key == key {
			return attr, true
		}
	}
	return slog.Attr{}, false
}

// ---- unexported helper tests -----------------------------------------------

func TestGetClientIp(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		want       string
	}{
		{
			name: "X-Forwarded-For single IP takes precedence over all others",
			xff:  "10.0.0.1",
			want: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For comma-separated returns leftmost valid IP",
			xff:  "10.0.0.1, 192.168.1.1",
			want: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For skips invalid entry and returns next valid IP",
			xff:  "not-an-ip, 10.0.0.2",
			want: "10.0.0.2",
		},
		{
			name: "X-Forwarded-For all invalid returns invalid marker",
			xff:  "bad, also-bad",
			want: "invalid",
		},
		{
			name:    "X-Real-IP used when X-Forwarded-For absent",
			xRealIP: "172.16.0.5",
			want:    "172.16.0.5",
		},
		{
			name:       "RemoteAddr used when no proxy headers present",
			remoteAddr: "203.0.113.5:45678",
			want:       "203.0.113.5",
		},
		{
			name:       "RemoteAddr without port is returned as-is when valid",
			remoteAddr: "203.0.113.5",
			want:       "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			got := getClientIp(req)
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGrpcTraceparentValue(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)
	validTp := fmt.Sprintf("00-%s-%s-01", validTrace, validSpan)

	tests := []struct {
		name string
		md   metadata.MD
		want string
	}{
		{
			name: "returns traceparent value when present",
			md:   metadata.MD{"traceparent": []string{validTp}},
			want: validTp,
		},
		{
			name: "returns first value when multiple entries exist",
			md:   metadata.MD{"traceparent": []string{validTp, "other"}},
			want: validTp,
		},
		{
			name: "returns empty string when key absent",
			md:   metadata.MD{},
			want: "",
		},
		{
			name: "returns empty string for nil MD",
			md:   nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcTraceparentValue(tt.md)
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGrpcUserAgent(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
		want string
	}{
		{
			name: "returns user-agent value",
			md:   metadata.MD{"user-agent": []string{"grpc-go/1.50.0"}},
			want: "grpc-go/1.50.0",
		},
		{
			name: "strips control characters from user-agent",
			md:   metadata.MD{"user-agent": []string{"agent\x00with\nnulls"}},
			want: "agentwithnulls",
		},
		{
			name: "returns empty string when key absent",
			md:   metadata.MD{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcUserAgent(tt.md)
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGrpcAuthority(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
		want string
	}{
		{
			name: "strips port from authority host",
			md:   metadata.MD{":authority": []string{"api.example.com:443"}},
			want: "api.example.com",
		},
		{
			name: "returns host unchanged when no port present",
			md:   metadata.MD{":authority": []string{"api.example.com"}},
			want: "api.example.com",
		},
		{
			name: "returns empty string when :authority absent",
			md:   metadata.MD{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcAuthority(tt.md)
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGrpcClientAddr(t *testing.T) {
	tests := []struct {
		name     string
		buildCtx func() context.Context
		want     string
	}{
		{
			name: "extracts and sanitizes IP from peer context",
			buildCtx: func() context.Context {
				p := &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051}}
				return peer.NewContext(context.Background(), p)
			},
			want: "10.0.0.1",
		},
		{
			name: "returns empty string when peer absent",
			buildCtx: func() context.Context {
				return context.Background()
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcClientAddr(tt.buildCtx())
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

// ---- ObtainHttpTelemetry ---------------------------------------------------

func TestObtainHttpTelemetry(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)

	tests := []struct {
		name           string
		buildReq       func() *http.Request
		logger         *slog.Logger
		wantTraceId    string // non-empty: exact match; empty: a fresh ID was generated
		wantParentId   string
		wantSpanId     string
		wantRemoteAddr string
		wantProtocol   string
		wantMethod     string
		wantHost       string
		wantPath       string
	}{
		{
			name: "valid traceparent header propagates trace ID and caller span as parent",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
				req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%s-01", validTrace, validSpan))
				req.Host = "api.example.com"
				return req
			},
			logger:       discardLogger(),
			wantTraceId:  validTrace,
			wantParentId: validSpan,
			wantSpanId:   "",
			wantProtocol: "HTTP/1.1",
			wantMethod:   "GET",
			wantPath:     "/api/resource",
			wantHost:     "api.example.com",
		},
		{
			name: "missing traceparent header generates a fresh traceparent",
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/resource", nil)
			},
			logger:     discardLogger(),
			wantMethod: "POST",
		},
		{
			name: "invalid traceparent header generates a fresh traceparent",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
				req.Header.Set("Traceparent", "not-a-valid-traceparent")
				return req
			},
			logger: discardLogger(),
		},
		{
			name: "X-Forwarded-For header sets remote addr",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "10.0.0.1")
				return req
			},
			logger:         discardLogger(),
			wantRemoteAddr: "10.0.0.1",
		},
		{
			name: "X-Real-IP header used when X-Forwarded-For absent",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Real-IP", "172.16.0.5")
				return req
			},
			logger:         discardLogger(),
			wantRemoteAddr: "172.16.0.5",
		},
		{
			name: "referrer is sanitized to host-only",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Referer", "https://origin.example.com/some/path?q=1")
				return req
			},
			logger: discardLogger(),
		},
		{
			name: "nil logger does not panic",
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			got := ObtainHttpTelemetry(tt.buildReq(), tt.logger)
			after := time.Now()

			if got == nil {
				t.Fatal("ObtainHttpTelemetry returned nil")
			}

			// Trace ID: exact match when provided, otherwise validate format.
			if tt.wantTraceId != "" {
				if got.Traceparent.TraceId != tt.wantTraceId {
					t.Errorf("trace ID: want %q, got %q", tt.wantTraceId, got.Traceparent.TraceId)
				}
			} else {
				if len(got.Traceparent.TraceId) != 32 || !isValidHexString(got.Traceparent.TraceId) {
					t.Errorf("generated trace ID invalid: %q", got.Traceparent.TraceId)
				}
			}

			if tt.wantParentId != "" && got.Traceparent.ParentSpanId != tt.wantParentId {
				t.Errorf("parent span ID: want %q, got %q", tt.wantParentId, got.Traceparent.ParentSpanId)
			}
			if tt.wantSpanId != "" && got.Traceparent.SpanId != tt.wantSpanId {
				t.Errorf("span ID: want %q, got %q", tt.wantSpanId, got.Traceparent.SpanId)
			}
			if tt.wantRemoteAddr != "" && got.RemoteAddr != tt.wantRemoteAddr {
				t.Errorf("remote addr: want %q, got %q", tt.wantRemoteAddr, got.RemoteAddr)
			}
			if tt.wantProtocol != "" && got.Protocol != tt.wantProtocol {
				t.Errorf("protocol: want %q, got %q", tt.wantProtocol, got.Protocol)
			}
			if tt.wantMethod != "" && got.HttpMethod != tt.wantMethod {
				t.Errorf("http method: want %q, got %q", tt.wantMethod, got.HttpMethod)
			}
			if tt.wantHost != "" && got.Host != tt.wantHost {
				t.Errorf("host: want %q, got %q", tt.wantHost, got.Host)
			}
			if tt.wantPath != "" && got.Path != tt.wantPath {
				t.Errorf("path: want %q, got %q", tt.wantPath, got.Path)
			}

			// StartTime should fall within the test window.
			if got.StartTime.Before(before) || got.StartTime.After(after) {
				t.Errorf("start time %v not within [%v, %v]", got.StartTime, before, after)
			}

			// gRPC-specific fields must be empty for HTTP requests.
			if got.GrpcMethod != "" {
				t.Errorf("grpc method should be empty, got %q", got.GrpcMethod)
			}
		})
	}
}

// ---- ObtainGrpcTelemetry ---------------------------------------------------

func TestObtainGrpcTelemetry(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)
	method := "/test.ExampleService/GetResource"

	tests := []struct {
		name           string
		buildCtx       func() context.Context
		method         string
		logger         *slog.Logger
		wantTraceId    string // non-empty: exact match; empty: fresh ID generated
		wantParentId   string
		wantSpanId     string
		wantRemoteAddr string
		wantUserAgent  string
		wantAuthority  string
		wantMethod     string
	}{
		{
			name: "valid traceparent in metadata propagates trace ID and caller span",
			buildCtx: func() context.Context {
				md := metadata.MD{
					"traceparent": []string{fmt.Sprintf("00-%s-%s-01", validTrace, validSpan)},
				}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			method:       method,
			logger:       discardLogger(),
			wantTraceId:  validTrace,
			wantParentId: validSpan,
			wantSpanId:   "",
			wantMethod:   method,
		},
		{
			name: "no metadata in context generates a fresh traceparent",
			buildCtx: func() context.Context {
				return context.Background()
			},
			method: method,
			logger: discardLogger(),
		},
		{
			name: "invalid traceparent in metadata generates a fresh traceparent",
			buildCtx: func() context.Context {
				md := metadata.MD{"traceparent": []string{"bad-value"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			method: method,
			logger: discardLogger(),
		},
		{
			name: "user-agent metadata is captured",
			buildCtx: func() context.Context {
				md := metadata.MD{"user-agent": []string{"grpc-go/1.50.0"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			method:        method,
			logger:        discardLogger(),
			wantUserAgent: "grpc-go/1.50.0",
		},
		{
			name: ":authority metadata is captured and port stripped",
			buildCtx: func() context.Context {
				md := metadata.MD{":authority": []string{"api.example.com:443"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			method:        method,
			logger:        discardLogger(),
			wantAuthority: "api.example.com",
		},
		{
			name: "peer context provides remote addr",
			buildCtx: func() context.Context {
				p := &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051}}
				ctx := peer.NewContext(context.Background(), p)
				return ctx
			},
			method:         method,
			logger:         discardLogger(),
			wantRemoteAddr: "10.0.0.1",
		},
		{
			name: "nil logger does not panic",
			buildCtx: func() context.Context {
				return context.Background()
			},
			method: method,
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			got := ObtainGrpcTelemetry(tt.buildCtx(), tt.method, tt.logger)
			after := time.Now()

			if got == nil {
				t.Fatal("ObtainGrpcTelemetry returned nil")
			}

			if tt.wantTraceId != "" {
				if got.Traceparent.TraceId != tt.wantTraceId {
					t.Errorf("trace ID: want %q, got %q", tt.wantTraceId, got.Traceparent.TraceId)
				}
			} else {
				if len(got.Traceparent.TraceId) != 32 || !isValidHexString(got.Traceparent.TraceId) {
					t.Errorf("generated trace ID invalid: %q", got.Traceparent.TraceId)
				}
			}

			if tt.wantParentId != "" && got.Traceparent.ParentSpanId != tt.wantParentId {
				t.Errorf("parent span ID: want %q, got %q", tt.wantParentId, got.Traceparent.ParentSpanId)
			}
			if tt.wantRemoteAddr != "" && got.RemoteAddr != tt.wantRemoteAddr {
				t.Errorf("remote addr: want %q, got %q", tt.wantRemoteAddr, got.RemoteAddr)
			}
			if tt.wantUserAgent != "" && got.UserAgent != tt.wantUserAgent {
				t.Errorf("user agent: want %q, got %q", tt.wantUserAgent, got.UserAgent)
			}
			if tt.wantAuthority != "" && got.GrpcAuthority != tt.wantAuthority {
				t.Errorf("authority: want %q, got %q", tt.wantAuthority, got.GrpcAuthority)
			}
			if tt.wantMethod != "" && got.GrpcMethod != tt.wantMethod {
				t.Errorf("grpc method: want %q, got %q", tt.wantMethod, got.GrpcMethod)
			}

			if got.StartTime.Before(before) || got.StartTime.After(after) {
				t.Errorf("start time %v not within [%v, %v]", got.StartTime, before, after)
			}

			// HTTP-specific fields must be empty for gRPC requests.
			if got.Protocol != "" || got.HttpMethod != "" || got.Path != "" {
				t.Errorf("HTTP fields should be empty for gRPC telemetry: protocol=%q method=%q path=%q",
					got.Protocol, got.HttpMethod, got.Path)
			}
		})
	}
}

// ---- TelemetryFields -------------------------------------------------------

func TestTelemetryFields(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)
	parentSpan := strings.Repeat("cc", 8)

	tests := []struct {
		name          string
		telemetry     Telemetry
		mustHaveKeys  []string
		mustNotHave   []string
	}{
		{
			name: "HTTP telemetry includes all populated fields",
			telemetry: Telemetry{
				Traceparent:  Traceparent{TraceId: validTrace, SpanId: validSpan, ParentSpanId: parentSpan},
				Protocol:     "HTTP/1.1",
				HttpMethod:   "GET",
				Path:         "/api/resource",
				Host:         "api.example.com",
				Referrer:     "other.example.com",
				RemoteAddr:   "10.0.0.1",
				UserAgent:    "Mozilla/5.0",
				StartTime:    time.Now(),
			},
			mustHaveKeys: []string{
				"trace_id", "span_id", "parent_span_id",
				"remote_addr", "user_agent",
				"protocol", "http_method", "path", "host", "referrer",
				"start_time",
			},
			mustNotHave: []string{"grpc_method", "grpc_authority"},
		},
		{
			name: "gRPC telemetry includes all populated fields",
			telemetry: Telemetry{
				Traceparent:   Traceparent{TraceId: validTrace, SpanId: validSpan},
				GrpcMethod:    "/svc.Service/Method",
				GrpcAuthority: "api.example.com",
				RemoteAddr:    "10.0.0.1",
				UserAgent:     "grpc-go/1.50.0",
				StartTime:     time.Now(),
			},
			mustHaveKeys: []string{
				"trace_id", "span_id",
				"remote_addr", "user_agent",
				"grpc_method", "grpc_authority",
				"start_time",
			},
			mustNotHave: []string{"parent_span_id", "protocol", "http_method", "path", "host", "referrer"},
		},
		{
			name: "parent span ID omitted when empty",
			telemetry: Telemetry{
				Traceparent: Traceparent{TraceId: validTrace, SpanId: validSpan, ParentSpanId: ""},
				RemoteAddr:  "10.0.0.1",
				UserAgent:   "agent/1.0",
			},
			mustNotHave: []string{"parent_span_id"},
		},
		{
			name: "start time omitted when zero value",
			telemetry: Telemetry{
				Traceparent: Traceparent{TraceId: validTrace, SpanId: validSpan},
				RemoteAddr:  "10.0.0.1",
				UserAgent:   "agent/1.0",
			},
			mustNotHave: []string{"start_time"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := tt.telemetry.TelemetryFields()

			for _, key := range tt.mustHaveKeys {
				if _, found := findAttr(fields, key); !found {
					t.Errorf("expected field %q to be present", key)
				}
			}
			for _, key := range tt.mustNotHave {
				if _, found := findAttr(fields, key); found {
					t.Errorf("field %q should not be present when empty", key)
				}
			}
		})
	}
}
