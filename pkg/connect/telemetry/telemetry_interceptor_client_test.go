package telemetry

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// mockInvoker returns a grpc.UnaryInvoker that captures the context it receives
// and optionally returns an error.
func mockInvoker(capturedCtx *context.Context, returnErr error) grpc.UnaryInvoker {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		opts ...grpc.CallOption,
	) error {
		if capturedCtx != nil {
			*capturedCtx = ctx
		}
		return returnErr
	}
}

// ---- BuildOutgoingTraceparent ----------------------------------------------

func TestBuildOutgoingTraceparent(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	currentSpan := strings.Repeat("a3", 8)

	current := &Traceparent{
		Version: "00",
		TraceId: validTrace,
		SpanId:  currentSpan,
		Flags:   "01",
	}

	ctx, outgoing := BuildOutgoingTraceparent(context.Background(), current, discardLogger())

	if outgoing == nil {
		t.Fatal("BuildOutgoingTraceparent returned nil Traceparent")
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "trace ID is propagated unchanged",
			check: func(t *testing.T) {
				if outgoing.TraceId != validTrace {
					t.Errorf("want %q, got %q", validTrace, outgoing.TraceId)
				}
			},
		},
		{
			name: "current span becomes the parent span of the outgoing call",
			check: func(t *testing.T) {
				if outgoing.ParentSpanId != currentSpan {
					t.Errorf("want %q, got %q", currentSpan, outgoing.ParentSpanId)
				}
			},
		},
		{
			name: "a new span ID is generated for the outgoing call",
			check: func(t *testing.T) {
				if outgoing.SpanId == currentSpan {
					t.Errorf("outgoing span %q should differ from current span %q", outgoing.SpanId, currentSpan)
				}
				if len(outgoing.SpanId) != 16 || !isValidHexString(outgoing.SpanId) {
					t.Errorf("outgoing span ID not valid 16-char hex: %q", outgoing.SpanId)
				}
			},
		},
		{
			name: "sampling flags are propagated unchanged",
			check: func(t *testing.T) {
				if outgoing.Flags != current.Flags {
					t.Errorf("want %q, got %q", current.Flags, outgoing.Flags)
				}
			},
		},
		{
			name: "traceparent is written to outgoing gRPC metadata",
			check: func(t *testing.T) {
				md, ok := metadata.FromOutgoingContext(ctx)
				if !ok {
					t.Fatal("no outgoing metadata on returned context")
				}
				if vals := md.Get(TraceparentKey); len(vals) == 0 {
					t.Errorf("key %q not found in outgoing metadata", TraceparentKey)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

func TestBuildOutgoingTraceparentHeaderFormat(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	currentSpan := strings.Repeat("a3", 8)

	current := &Traceparent{Version: "00", TraceId: validTrace, SpanId: currentSpan, Flags: "00"}
	ctx, outgoing := BuildOutgoingTraceparent(context.Background(), current, discardLogger())

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("no outgoing metadata on returned context")
	}
	vals := md.Get(TraceparentKey)
	if len(vals) == 0 {
		t.Fatal("traceparent not found in outgoing metadata")
	}

	// The W3C header format is: version-traceId-spanId-flags.
	// The third segment (spanId) is the NEW outgoing span, which the receiving
	// service will treat as its parent span.
	parts := strings.Split(vals[0], "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent in metadata has %d parts, want 4: %q", len(parts), vals[0])
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "version matches current traceparent",
			check: func(t *testing.T) {
				if parts[0] != current.Version {
					t.Errorf("want %q, got %q", current.Version, parts[0])
				}
			},
		},
		{
			name: "trace ID matches current traceparent",
			check: func(t *testing.T) {
				if parts[1] != validTrace {
					t.Errorf("want %q, got %q", validTrace, parts[1])
				}
			},
		},
		{
			name: "span ID in header is the new outgoing span — not the current span",
			check: func(t *testing.T) {
				if parts[2] != outgoing.SpanId {
					t.Errorf("header span: want outgoing span %q, got %q", outgoing.SpanId, parts[2])
				}
				if parts[2] == currentSpan {
					t.Errorf("header span should not equal the parent span %q", currentSpan)
				}
				if len(parts[2]) != 16 || !isValidHexString(parts[2]) {
					t.Errorf("header span not valid 16-char hex: %q", parts[2])
				}
			},
		},
		{
			name: "flags match current traceparent",
			check: func(t *testing.T) {
				if parts[3] != current.Flags {
					t.Errorf("want %q, got %q", current.Flags, parts[3])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

// ---- UnaryClientWithTelemetry ----------------------------------------------

func TestUnaryClientWithTelemetry(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	currentSpan := strings.Repeat("a3", 8)
	method := "/test.ExampleService/GetResource"

	existing := &Telemetry{
		Traceparent: Traceparent{
			Version: "00",
			TraceId: validTrace,
			SpanId:  currentSpan,
			Flags:   "01",
		},
	}

	tests := []struct {
		name          string
		buildCtx      func() context.Context
		useNilLogger  bool
		invokerErr    error
		wantErr       bool
		wantTraceId   string
		checkOutgoing func(t *testing.T, md metadata.MD)
	}{
		{
			name: "existing telemetry: trace ID and new span appear in outgoing metadata",
			buildCtx: func() context.Context {
				return context.WithValue(context.Background(), TelemetryKey, existing)
			},
			wantTraceId: validTrace,
			checkOutgoing: func(t *testing.T, md metadata.MD) {
				vals := md.Get(TraceparentKey)
				if len(vals) == 0 {
					t.Fatal("traceparent missing from outgoing metadata")
				}
				parts := strings.Split(vals[0], "-")
				if len(parts) != 4 {
					t.Fatalf("expected 4 parts, got %d: %q", len(parts), vals[0])
				}
				if parts[1] != validTrace {
					t.Errorf("trace ID: want %q, got %q", validTrace, parts[1])
				}
				// The span in metadata is the new outgoing child span, not currentSpan.
				newSpan := parts[2]
				if newSpan == currentSpan {
					t.Errorf("outgoing span %q should differ from parent span %q", newSpan, currentSpan)
				}
				if len(newSpan) != 16 || !isValidHexString(newSpan) {
					t.Errorf("outgoing span not valid 16-char hex: %q", newSpan)
				}
			},
		},
		{
			name: "no existing telemetry: new traceparent generated and written to metadata",
			buildCtx: func() context.Context {
				return context.Background()
			},
			checkOutgoing: func(t *testing.T, md metadata.MD) {
				vals := md.Get(TraceparentKey)
				if len(vals) == 0 {
					t.Fatal("traceparent missing from outgoing metadata")
				}
				parts := strings.Split(vals[0], "-")
				if len(parts) != 4 {
					t.Fatalf("expected 4 parts, got %d: %q", len(parts), vals[0])
				}
				if len(parts[1]) != 32 || !isValidHexString(parts[1]) {
					t.Errorf("generated trace ID not valid 32-char hex: %q", parts[1])
				}
			},
		},
		{
			name: "nil logger does not panic",
			buildCtx: func() context.Context {
				return context.WithValue(context.Background(), TelemetryKey, existing)
			},
			useNilLogger: true,
		},
		{
			name: "invoker error is propagated to caller",
			buildCtx: func() context.Context {
				return context.WithValue(context.Background(), TelemetryKey, existing)
			},
			invokerErr: fmt.Errorf("downstream unavailable"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedCtx context.Context
			inv := mockInvoker(&capturedCtx, tt.invokerErr)

			var logger = discardLogger()
			if tt.useNilLogger {
				logger = nil
			}

			interceptor := UnaryClientWithTelemetry(logger)
			err := interceptor(tt.buildCtx(), method, nil, nil, nil, inv)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if capturedCtx == nil {
				t.Fatal("invoker was not called")
			}

			if tt.checkOutgoing != nil {
				md, ok := metadata.FromOutgoingContext(capturedCtx)
				if !ok {
					t.Fatal("no outgoing metadata on context passed to invoker")
				}
				tt.checkOutgoing(t, md)
			}
		})
	}
}

func TestUnaryClientWithTelemetryFlagsPropagate(t *testing.T) {
	for _, flags := range []string{"00", "01"} {
		t.Run("flags="+flags, func(t *testing.T) {
			existing := &Telemetry{
				Traceparent: Traceparent{
					Version: "00",
					TraceId: strings.Repeat("4b", 16),
					SpanId:  strings.Repeat("a3", 8),
					Flags:   flags,
				},
			}
			ctx := context.WithValue(context.Background(), TelemetryKey, existing)

			var capturedCtx context.Context
			interceptor := UnaryClientWithTelemetry(discardLogger())
			_ = interceptor(ctx, "/svc/Method", nil, nil, nil, mockInvoker(&capturedCtx, nil))

			md, _ := metadata.FromOutgoingContext(capturedCtx)
			vals := md.Get(TraceparentKey)
			if len(vals) == 0 {
				t.Fatal("traceparent missing from outgoing metadata")
			}
			parts := strings.Split(vals[0], "-")
			if len(parts) != 4 {
				t.Fatalf("expected 4 parts: %q", vals[0])
			}
			if parts[3] != flags {
				t.Errorf("flags: want %q, got %q", flags, parts[3])
			}
		})
	}
}
