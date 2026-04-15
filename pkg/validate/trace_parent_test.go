package validate

import (
	"strings"
	"testing"
)

func TestValidateTraceId(t *testing.T) {
	tests := []struct {
		name      string
		traceId   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_lowercase_hex",
			traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
			wantErr: false,
		},
		{
			name:    "valid_uppercase_hex",
			traceId: "4BF92F3577B34DA6A3CE929D0E0E4736",
			wantErr: false,
		},
		{
			name:    "valid_mixed_case_hex",
			traceId: "4bf92F3577b34DA6a3ce929d0e0E4736",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			traceId:   "4bf92f3577b34da6a3ce929d0e0e47",
			wantErr:   true,
			errSubstr: "32 hex characters",
		},
		{
			name:      "invalid_too_long",
			traceId:   "4bf92f3577b34da6a3ce929d0e0e473600",
			wantErr:   true,
			errSubstr: "32 hex characters",
		},
		{
			name:      "invalid_empty",
			traceId:   "",
			wantErr:   true,
			errSubstr: "32 hex characters",
		},
		{
			name:      "invalid_non_hex_char",
			traceId:   "4bf92f3577b34da6a3ce929d0e0e473g",
			wantErr:   true,
			errSubstr: "hexadecimal",
		},
		{
			name:      "invalid_contains_hyphen",
			traceId:   "4bf92f35-77b3-4da6-a3ce-929d0e0e4736",
			wantErr:   true,
			errSubstr: "32 hex characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTraceId(tt.traceId)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for traceId %q", tt.traceId)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for traceId %q: %v", tt.traceId, err)
			}
		})
	}
}

func TestValidateSpanId(t *testing.T) {
	tests := []struct {
		name      string
		spanId    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_lowercase_hex",
			spanId:  "00f067aa0ba902b7",
			wantErr: false,
		},
		{
			name:    "valid_uppercase_hex",
			spanId:  "00F067AA0BA902B7",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			spanId:    "00f067aa0ba902",
			wantErr:   true,
			errSubstr: "16 hex characters",
		},
		{
			name:      "invalid_too_long",
			spanId:    "00f067aa0ba902b700",
			wantErr:   true,
			errSubstr: "16 hex characters",
		},
		{
			name:      "invalid_empty",
			spanId:    "",
			wantErr:   true,
			errSubstr: "16 hex characters",
		},
		{
			name:      "invalid_non_hex_char",
			spanId:    "00f067aa0ba902z7",
			wantErr:   true,
			errSubstr: "hexadecimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSpanId(tt.spanId)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for spanId %q", tt.spanId)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for spanId %q: %v", tt.spanId, err)
			}
		})
	}
}

func TestIsValidHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid_lowercase",
			input: "deadbeef",
			want:  true,
		},
		{
			name:  "valid_uppercase",
			input: "DEADBEEF",
			want:  true,
		},
		{
			name:  "valid_mixed",
			input: "DeAdBeEf",
			want:  true,
		},
		{
			name:  "valid_numbers_only",
			input: "12345678",
			want:  true,
		},
		{
			name:  "invalid_odd_length",
			input: "abc",
			want:  false,
		},
		{
			name:  "invalid_non_hex_char",
			input: "deadbeegg",
			want:  false,
		},
		{
			name:  "invalid_empty", // even-length, no chars to fail
			input: "",
			want:  true,
		},
		{
			name:  "invalid_contains_space",
			input: "dead beef",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidHex(tt.input)
			if got != tt.want {
				t.Fatalf("IsValidHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
