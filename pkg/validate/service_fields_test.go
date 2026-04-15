package validate

import (
	"strings"
	"testing"
)

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_lowercase_letters",
			input:   "pixie",
			wantErr: false,
		},
		{
			name:    "valid_alphanumeric",
			input:   "service123",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   "ab",
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("a", ServiceNameMax),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "a",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("a", ServiceNameMax+1),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_uppercase",
			input:     "Pixie",
			wantErr:   true,
			errSubstr: "lower case letters",
		},
		{
			name:      "invalid_hyphen",
			input:     "my-service",
			wantErr:   true,
			errSubstr: "lower case letters",
		},
		{
			name:      "invalid_underscore",
			input:     "my_service",
			wantErr:   true,
			errSubstr: "lower case letters",
		},
		{
			name:      "invalid_space",
			input:     "my service",
			wantErr:   true,
			errSubstr: "lower case letters",
		},
		{
			name:      "invalid_special_char",
			input:     "svc@host",
			wantErr:   true,
			errSubstr: "lower case letters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}
