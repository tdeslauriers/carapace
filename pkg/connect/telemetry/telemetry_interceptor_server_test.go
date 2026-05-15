package telemetry

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const testMethod = "/test.ExampleService/GetResource"

// ---- UnaryServerWithTelemetry ----------------------------------------------

func TestUnaryServerWithTelemetry(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)

	tests := []struct {
		name           string
		buildCtx       func() context.Context
		useNilLogger   bool
		handlerErr     error
		wantErr        bool
		checkTelemetry func(t *testing.T, tel *Telemetry)
	}{
		{
			name: "valid traceparent in metadata propagates trace ID and caller span",
			buildCtx: func() context.Context {
				md := metadata.MD{
					"traceparent": []string{fmt.Sprintf("00-%s-%s-01", validTrace, validSpan)},
				}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.Traceparent.TraceId != validTrace {
					t.Errorf("trace ID: want %q, got %q", validTrace, tel.Traceparent.TraceId)
				}
				if tel.Traceparent.ParentSpanId != validSpan {
					t.Errorf("parent span ID: want %q, got %q", validSpan, tel.Traceparent.ParentSpanId)
				}
				// SpanId is not set by the parser; the service generates it separately.
				if tel.Traceparent.SpanId != "" {
					t.Errorf("span ID should be empty after parse, got %q", tel.Traceparent.SpanId)
				}
			},
		},
		{
			name: "no metadata in context generates a fresh traceparent",
			buildCtx: func() context.Context {
				return context.Background()
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if len(tel.Traceparent.TraceId) != 32 || !isValidHexString(tel.Traceparent.TraceId) {
					t.Errorf("generated trace ID invalid: %q", tel.Traceparent.TraceId)
				}
				if len(tel.Traceparent.SpanId) != 16 || !isValidHexString(tel.Traceparent.SpanId) {
					t.Errorf("generated span ID invalid: %q", tel.Traceparent.SpanId)
				}
				if tel.Traceparent.ParentSpanId != "" {
					t.Errorf("parent span ID should be empty for new trace, got %q", tel.Traceparent.ParentSpanId)
				}
			},
		},
		{
			name: "invalid traceparent in metadata generates a fresh traceparent",
			buildCtx: func() context.Context {
				md := metadata.MD{"traceparent": []string{"not-a-valid-value"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if len(tel.Traceparent.TraceId) != 32 || !isValidHexString(tel.Traceparent.TraceId) {
					t.Errorf("generated trace ID invalid: %q", tel.Traceparent.TraceId)
				}
			},
		},
		{
			name: "gRPC method is stored in telemetry",
			buildCtx: func() context.Context {
				return context.Background()
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.GrpcMethod != testMethod {
					t.Errorf("grpc method: want %q, got %q", testMethod, tel.GrpcMethod)
				}
			},
		},
		{
			name: "user-agent from metadata is captured",
			buildCtx: func() context.Context {
				md := metadata.MD{"user-agent": []string{"grpc-go/1.50.0"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.UserAgent != "grpc-go/1.50.0" {
					t.Errorf("user agent: want %q, got %q", "grpc-go/1.50.0", tel.UserAgent)
				}
			},
		},
		{
			name: ":authority metadata is captured with port stripped",
			buildCtx: func() context.Context {
				md := metadata.MD{":authority": []string{"api.example.com:443"}}
				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.GrpcAuthority != "api.example.com" {
					t.Errorf("authority: want %q, got %q", "api.example.com", tel.GrpcAuthority)
				}
			},
		},
		{
			name: "peer context provides remote address",
			buildCtx: func() context.Context {
				p := &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 50051}}
				return peer.NewContext(context.Background(), p)
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.RemoteAddr != "10.0.0.1" {
					t.Errorf("remote addr: want %q, got %q", "10.0.0.1", tel.RemoteAddr)
				}
			},
		},
		{
			name: "start time is set",
			buildCtx: func() context.Context {
				return context.Background()
			},
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel.StartTime.IsZero() {
					t.Error("start time should not be zero")
				}
			},
		},
		{
			name: "nil logger does not panic",
			buildCtx: func() context.Context {
				return context.Background()
			},
			useNilLogger: true,
			checkTelemetry: func(t *testing.T, tel *Telemetry) {
				if tel == nil {
					t.Error("telemetry should not be nil")
				}
			},
		},
		{
			name: "handler error is propagated to caller",
			buildCtx: func() context.Context {
				return context.Background()
			},
			handlerErr: fmt.Errorf("handler failure"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var telInHandler *Telemetry

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				telInHandler, _ = ctx.Value(TelemetryKey).(*Telemetry)
				return "response", tt.handlerErr
			}

			logger := discardLogger()
			if tt.useNilLogger {
				logger = nil
			}

			info := &grpc.UnaryServerInfo{FullMethod: testMethod}
			interceptor := UnaryServerWithTelemetry(logger)
			resp, err := interceptor(tt.buildCtx(), nil, info, handler)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && resp != "response" {
				t.Errorf("handler response not propagated: got %v", resp)
			}

			// telInHandler is nil only if handler was not called or TelemetryKey was missing.
			if telInHandler == nil && !tt.wantErr {
				t.Fatal("telemetry not found in handler context")
			}

			if tt.checkTelemetry != nil && telInHandler != nil {
				tt.checkTelemetry(t, telInHandler)
			}
		})
	}
}

func TestUnaryServerWithTelemetryContextIsolation(t *testing.T) {
	// Verify that each request gets its own telemetry — the interceptor must not
	// share state between calls.
	validTrace1 := strings.Repeat("11", 16)
	validSpan1 := strings.Repeat("aa", 8)
	validTrace2 := strings.Repeat("22", 16)
	validSpan2 := strings.Repeat("bb", 8)

	makeMD := func(trace, span string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.MD{
			"traceparent": []string{fmt.Sprintf("00-%s-%s-00", trace, span)},
		})
	}

	var tel1, tel2 *Telemetry
	info := &grpc.UnaryServerInfo{FullMethod: testMethod}

	interceptor := UnaryServerWithTelemetry(discardLogger())

	captureHandler := func(out **Telemetry) grpc.UnaryHandler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			*out, _ = ctx.Value(TelemetryKey).(*Telemetry)
			return nil, nil
		}
	}

	_, _ = interceptor(makeMD(validTrace1, validSpan1), nil, info, captureHandler(&tel1))
	_, _ = interceptor(makeMD(validTrace2, validSpan2), nil, info, captureHandler(&tel2))

	if tel1 == nil || tel2 == nil {
		t.Fatal("telemetry missing from one or both handler contexts")
	}
	if tel1.Traceparent.TraceId == tel2.Traceparent.TraceId {
		t.Errorf("requests share the same trace ID %q — telemetry is not isolated per call", tel1.Traceparent.TraceId)
	}
	if tel1.Traceparent.TraceId != validTrace1 {
		t.Errorf("request 1 trace ID: want %q, got %q", validTrace1, tel1.Traceparent.TraceId)
	}
	if tel2.Traceparent.TraceId != validTrace2 {
		t.Errorf("request 2 trace ID: want %q, got %q", validTrace2, tel2.Traceparent.TraceId)
	}
}
