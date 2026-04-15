package validate

import (
	"strings"
	"testing"
)

func TestValidateCountryCode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_us",
			input:   "1",
			wantErr: false,
		},
		{
			name:    "valid_uk",
			input:   "44",
			wantErr: false,
		},
		{
			name:    "valid_three_digits",
			input:   "999",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_starts_with_zero",
			input:     "01",
			wantErr:   true,
			errSubstr: "numeric",
		},
		{
			name:      "invalid_four_digits",
			input:     "1234",
			wantErr:   true,
			errSubstr: "numeric",
		},
		{
			name:      "invalid_letters",
			input:     "US",
			wantErr:   true,
			errSubstr: "numeric",
		},
		{
			name:      "invalid_special_char",
			input:     "+1",
			wantErr:   true,
			errSubstr: "numeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCountryCode(tt.input)
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

func TestValidatePhoneNumber(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_4_digits",
			input:   "1234",
			wantErr: false,
		},
		{
			name:    "valid_10_digits",
			input:   "5555551234",
			wantErr: false,
		},
		{
			name:    "valid_15_digits",
			input:   strings.Repeat("1", 15),
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_3_digits",
			input:     "123",
			wantErr:   true,
			errSubstr: "4 and 15",
		},
		{
			name:      "invalid_16_digits",
			input:     strings.Repeat("1", 16),
			wantErr:   true,
			errSubstr: "4 and 15",
		},
		{
			name:      "invalid_letters",
			input:     "555CALL",
			wantErr:   true,
			errSubstr: "4 and 15",
		},
		{
			name:      "invalid_with_dash",
			input:     "555-1234",
			wantErr:   true,
			errSubstr: "4 and 15",
		},
		{
			name:      "invalid_with_parens",
			input:     "(555)1234",
			wantErr:   true,
			errSubstr: "4 and 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePhoneNumber(tt.input)
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

func TestValidateExtension(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_empty_optional",
			input:   "",
			wantErr: false,
		},
		{
			name:    "valid_1_digit",
			input:   "1",
			wantErr: false,
		},
		{
			name:    "valid_6_digits",
			input:   "123456",
			wantErr: false,
		},
		{
			name:      "invalid_7_digits",
			input:     "1234567",
			wantErr:   true,
			errSubstr: "1 and 6",
		},
		{
			name:      "invalid_letters",
			input:     "ext",
			wantErr:   true,
			errSubstr: "1 and 6",
		},
		{
			name:      "invalid_with_hash",
			input:     "#123",
			wantErr:   true,
			errSubstr: "1 and 6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExtension(tt.input)
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
