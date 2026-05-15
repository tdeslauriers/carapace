package telemetry

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// discardLogger returns a no-op logger for tests that don't care about log output.
// Declared here and shared across all test files in this package.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// isValidHexString returns true if s is a non-empty, even-length, all-hex string,
// matching the constraints used by validate.ValidateTraceId / ValidateSpanId.
func isValidHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func TestGenerateTraceId(t *testing.T) {
	t.Run("produces 32-character hex string", func(t *testing.T) {
		id := GenerateTraceId()
		if len(id) != 32 {
			t.Errorf("length: want 32, got %d (%q)", len(id), id)
		}
		if !isValidHexString(id) {
			t.Errorf("not valid hex: %q", id)
		}
	})

	t.Run("unique across 100 calls", func(t *testing.T) {
		seen := make(map[string]struct{}, 100)
		for i := range 100 {
			id := GenerateTraceId()
			if _, exists := seen[id]; exists {
				t.Fatalf("duplicate trace ID at iteration %d: %q", i, id)
			}
			seen[id] = struct{}{}
		}
	})
}

func TestGenerateSpanId(t *testing.T) {
	t.Run("produces 16-character hex string", func(t *testing.T) {
		id := GenerateSpanId()
		if len(id) != 16 {
			t.Errorf("length: want 16, got %d (%q)", len(id), id)
		}
		if !isValidHexString(id) {
			t.Errorf("not valid hex: %q", id)
		}
	})

	t.Run("unique across 100 calls", func(t *testing.T) {
		seen := make(map[string]struct{}, 100)
		for i := range 100 {
			id := GenerateSpanId()
			if _, exists := seen[id]; exists {
				t.Fatalf("duplicate span ID at iteration %d: %q", i, id)
			}
			seen[id] = struct{}{}
		}
	})
}

func TestSampledFlag(t *testing.T) {
	t.Run("returns only 00 or 01", func(t *testing.T) {
		for i := range 500 {
			flag := sampledFlag()
			if flag != "00" && flag != "01" {
				t.Errorf("call %d: invalid flag value %q", i, flag)
			}
		}
	})

	// sampleCounter is monotonically increasing. In any 10 000 consecutive calls
	// exactly 100 multiples of 100 are hit, regardless of the counter's starting value.
	t.Run("samples at exactly 1 per 100 calls over 10 000 iterations", func(t *testing.T) {
		const total = 10_000
		sampled := 0
		for range total {
			if sampledFlag() == "01" {
				sampled++
			}
		}
		if sampled != total/100 {
			t.Errorf("expected %d sampled calls in %d iterations, got %d", total/100, total, sampled)
		}
	})
}

func TestNewTraceparent(t *testing.T) {
	tp := NewTraceparent()
	if tp == nil {
		t.Fatal("NewTraceparent returned nil")
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "version is W3C default 00",
			check: func(t *testing.T) {
				if tp.Version != TraceparentVersion {
					t.Errorf("want %q, got %q", TraceparentVersion, tp.Version)
				}
			},
		},
		{
			name: "trace ID is 32-character valid hex",
			check: func(t *testing.T) {
				if len(tp.TraceId) != 32 {
					t.Errorf("length: want 32, got %d", len(tp.TraceId))
				}
				if !isValidHexString(tp.TraceId) {
					t.Errorf("not valid hex: %q", tp.TraceId)
				}
			},
		},
		{
			name: "span ID is 16-character valid hex",
			check: func(t *testing.T) {
				if len(tp.SpanId) != 16 {
					t.Errorf("length: want 16, got %d", len(tp.SpanId))
				}
				if !isValidHexString(tp.SpanId) {
					t.Errorf("not valid hex: %q", tp.SpanId)
				}
			},
		},
		{
			name: "parent span ID is empty — not set at trace origin",
			check: func(t *testing.T) {
				if tp.ParentSpanId != "" {
					t.Errorf("want empty, got %q", tp.ParentSpanId)
				}
			},
		},
		{
			name: "flags are a valid sampling value",
			check: func(t *testing.T) {
				if tp.Flags != "00" && tp.Flags != "01" {
					t.Errorf("want '00' or '01', got %q", tp.Flags)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}

	t.Run("unique trace IDs across 50 calls", func(t *testing.T) {
		seen := make(map[string]struct{}, 50)
		for i := range 50 {
			id := NewTraceparent().TraceId
			if _, exists := seen[id]; exists {
				t.Fatalf("duplicate trace ID at iteration %d: %q", i, id)
			}
			seen[id] = struct{}{}
		}
	})
}

func TestTraceparentGenerateSpanIdMethod(t *testing.T) {
	traceId := strings.Repeat("4b", 16)
	original := strings.Repeat("a3", 8)

	tp := &Traceparent{
		Version: TraceparentVersion,
		TraceId: traceId,
		SpanId:  original,
		Flags:   "01",
	}
	tp.GenerateSpanId()

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "span ID changes after call",
			check: func(t *testing.T) {
				if tp.SpanId == original {
					t.Error("span ID did not change")
				}
			},
		},
		{
			name: "new span ID is 16-character valid hex",
			check: func(t *testing.T) {
				if len(tp.SpanId) != 16 {
					t.Errorf("length: want 16, got %d", len(tp.SpanId))
				}
				if !isValidHexString(tp.SpanId) {
					t.Errorf("not valid hex: %q", tp.SpanId)
				}
			},
		},
		{
			name: "version, trace ID, and flags are unchanged",
			check: func(t *testing.T) {
				if tp.Version != TraceparentVersion {
					t.Errorf("version changed: got %q", tp.Version)
				}
				if tp.TraceId != traceId {
					t.Errorf("trace ID changed: got %q", tp.TraceId)
				}
				if tp.Flags != "01" {
					t.Errorf("flags changed: got %q", tp.Flags)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

func TestParseTraceparent(t *testing.T) {
	validTrace := strings.Repeat("4b", 16) // 32-char hex
	validSpan := strings.Repeat("a3", 8)   // 16-char hex

	tests := []struct {
		name         string
		input        string
		wantErr      bool
		wantVersion  string
		wantTraceId  string
		wantParentId string
		wantFlags    string
	}{
		{
			name:         "valid traceparent not sampled",
			input:        fmt.Sprintf("00-%s-%s-00", validTrace, validSpan),
			wantVersion:  "00",
			wantTraceId:  validTrace,
			wantParentId: validSpan,
			wantFlags:    "00",
		},
		{
			name:         "valid traceparent sampled",
			input:        fmt.Sprintf("00-%s-%s-01", validTrace, validSpan),
			wantVersion:  "00",
			wantTraceId:  validTrace,
			wantParentId: validSpan,
			wantFlags:    "01",
		},
		{
			name:         "leading and trailing whitespace is trimmed",
			input:        fmt.Sprintf("  00-%s-%s-01  ", validTrace, validSpan),
			wantVersion:  "00",
			wantTraceId:  validTrace,
			wantParentId: validSpan,
			wantFlags:    "01",
		},
		// error cases
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "three parts — missing flags segment",
			input:   fmt.Sprintf("00-%s-%s", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "five parts — extra segment appended",
			input:   fmt.Sprintf("00-%s-%s-01-extra", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "version one character too short",
			input:   fmt.Sprintf("0-%s-%s-01", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "version one character too long",
			input:   fmt.Sprintf("001-%s-%s-01", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "trace ID too short",
			input:   fmt.Sprintf("00-abc-%s-01", validSpan),
			wantErr: true,
		},
		{
			name:    "trace ID two characters too long",
			input:   fmt.Sprintf("00-%saa-%s-01", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "trace ID contains non-hex characters",
			input:   fmt.Sprintf("00-%s-%s-01", strings.Repeat("zz", 16), validSpan),
			wantErr: true,
		},
		{
			name:    "span ID too short",
			input:   fmt.Sprintf("00-%s-abc-01", validTrace),
			wantErr: true,
		},
		{
			name:    "span ID two characters too long",
			input:   fmt.Sprintf("00-%s-%saa-01", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "span ID contains non-hex characters",
			input:   fmt.Sprintf("00-%s-%s-01", validTrace, strings.Repeat("zz", 8)),
			wantErr: true,
		},
		{
			name:    "flags empty after trailing dash",
			input:   fmt.Sprintf("00-%s-%s-", validTrace, validSpan),
			wantErr: true,
		},
		{
			name:    "flags one character too long",
			input:   fmt.Sprintf("00-%s-%s-001", validTrace, validSpan),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, err := ParseTraceparent(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if tp.Version != tt.wantVersion {
				t.Errorf("version: want %q, got %q", tt.wantVersion, tp.Version)
			}
			if tp.TraceId != tt.wantTraceId {
				t.Errorf("trace ID: want %q, got %q", tt.wantTraceId, tp.TraceId)
			}
			if tp.ParentSpanId != tt.wantParentId {
				t.Errorf("parent span ID: want %q, got %q", tt.wantParentId, tp.ParentSpanId)
			}
			if tp.Flags != tt.wantFlags {
				t.Errorf("flags: want %q, got %q", tt.wantFlags, tp.Flags)
			}
			// SpanId is never set by the parser; the receiving service generates it.
			if tp.SpanId != "" {
				t.Errorf("span ID should be empty after parse, got %q", tp.SpanId)
			}
		})
	}
}

func TestBuildTraceparentString(t *testing.T) {
	validTrace := strings.Repeat("4b", 16)
	validSpan := strings.Repeat("a3", 8)

	tests := []struct {
		name         string
		tp           Traceparent
		logger       *slog.Logger
		wantContains []string
	}{
		{
			name:         "all fields set returns version-traceId-spanId-flags",
			tp:           Traceparent{Version: "00", TraceId: validTrace, SpanId: validSpan, Flags: "01"},
			logger:       discardLogger(),
			wantContains: []string{"00-", validTrace, validSpan, "-01"},
		},
		{
			name:         "missing version replaced with W3C default",
			tp:           Traceparent{TraceId: validTrace, SpanId: validSpan, Flags: "01"},
			logger:       discardLogger(),
			wantContains: []string{TraceparentVersion + "-"},
		},
		{
			name:   "missing trace ID generates a valid one",
			tp:     Traceparent{Version: "00", SpanId: validSpan, Flags: "00"},
			logger: discardLogger(),
		},
		{
			name:   "missing span ID generates a valid one",
			tp:     Traceparent{Version: "00", TraceId: validTrace, Flags: "00"},
			logger: discardLogger(),
		},
		{
			name:         "missing flags defaults to not-sampled 00",
			tp:           Traceparent{Version: "00", TraceId: validTrace, SpanId: validSpan},
			logger:       discardLogger(),
			wantContains: []string{"-00"},
		},
		{
			name:   "nil logger does not panic",
			tp:     Traceparent{Version: "00", TraceId: validTrace, SpanId: validSpan, Flags: "01"},
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tp.BuildTraceparentString(tt.logger)

			parts := strings.Split(result, "-")
			if len(parts) != 4 {
				t.Fatalf("expected 4 dash-separated parts, got %d: %q", len(parts), result)
			}
			if len(parts[0]) != 2 {
				t.Errorf("version segment: expected 2 chars, got %q", parts[0])
			}
			if len(parts[1]) != 32 || !isValidHexString(parts[1]) {
				t.Errorf("trace ID segment: expected 32-char hex, got %q", parts[1])
			}
			if len(parts[2]) != 16 || !isValidHexString(parts[2]) {
				t.Errorf("span ID segment: expected 16-char hex, got %q", parts[2])
			}
			if len(parts[3]) != 2 {
				t.Errorf("flags segment: expected 2 chars, got %q", parts[3])
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("result %q does not contain expected substring %q", result, want)
				}
			}
		})
	}
}
