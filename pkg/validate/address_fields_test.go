package validate

import (
	"strings"
	"testing"
)

func TestValidateStreetAddress(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "123 Main St",
			wantErr: false,
		},
		{
			name:    "valid_with_apt",
			input:   "456 Elm Ave, Apt #2B",
			wantErr: false,
		},
		{
			name:    "valid_with_period",
			input:   "1 Dr. Martin Luther King Jr. Blvd",
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("A", 100),
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_whitespace_only",
			input:     "   ",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", 101),
			wantErr:   true,
			errSubstr: "invalid",
		},
		{
			name:      "invalid_special_char",
			input:     "123 Main St @home",
			wantErr:   true,
			errSubstr: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStreetAddress(tt.input)
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

func TestValidateStreetAddress2(t *testing.T) {
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
			name:    "valid_apt",
			input:   "Apt 4B",
			wantErr: false,
		},
		{
			name:    "valid_suite",
			input:   "Suite 100",
			wantErr: false,
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", 101),
			wantErr:   true,
			errSubstr: "invalid",
		},
		{
			name:      "invalid_special_char",
			input:     "Apt @4",
			wantErr:   true,
			errSubstr: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStreetAddress2(tt.input)
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

func TestValidateCity(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "Springfield",
			wantErr: false,
		},
		{
			name:    "valid_with_space",
			input:   "New York",
			wantErr: false,
		},
		{
			name:    "valid_with_apostrophe",
			input:   "O'Fallon",
			wantErr: false,
		},
		{
			name:    "valid_with_hyphen",
			input:   "Winston-Salem",
			wantErr: false,
		},
		{
			name:    "valid_with_period",
			input:   "St. Louis",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", 51),
			wantErr:   true,
			errSubstr: "2-50",
		},
		{
			name:      "invalid_number",
			input:     "City123",
			wantErr:   true,
			errSubstr: "2-50",
		},
		{
			name:      "invalid_special_char",
			input:     "City@Name",
			wantErr:   true,
			errSubstr: "2-50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCity(tt.input)
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

func TestValidateState(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_CA",
			input:   "CA",
			wantErr: false,
		},
		{
			name:    "valid_NY",
			input:   "NY",
			wantErr: false,
		},
		{
			name:    "valid_lowercase_normalized",
			input:   "tx",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_too_long",
			input:     "CAL",
			wantErr:   true,
			errSubstr: "2-letter",
		},
		{
			name:      "invalid_too_short",
			input:     "C",
			wantErr:   true,
			errSubstr: "2-letter",
		},
		{
			name:      "invalid_number",
			input:     "C1",
			wantErr:   true,
			errSubstr: "2-letter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateState(tt.input)
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

func TestValidateZipCode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_5_digit",
			input:   "12345",
			wantErr: false,
		},
		{
			name:    "valid_zip_plus_4",
			input:   "12345-6789",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_4_digits",
			input:     "1234",
			wantErr:   true,
			errSubstr: "5 digits",
		},
		{
			name:      "invalid_6_digits",
			input:     "123456",
			wantErr:   true,
			errSubstr: "5 digits",
		},
		{
			name:      "invalid_letters",
			input:     "ABCDE",
			wantErr:   true,
			errSubstr: "5 digits",
		},
		{
			name:      "invalid_zip_plus_3",
			input:     "12345-678",
			wantErr:   true,
			errSubstr: "5 digits",
		},
		{
			name:      "invalid_zip_plus_5",
			input:     "12345-67890",
			wantErr:   true,
			errSubstr: "5 digits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateZipCode(tt.input)
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

func TestValidateCountry(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "United States",
			wantErr: false,
		},
		{
			name:    "valid_short",
			input:   "US",
			wantErr: false,
		},
		{
			name:    "valid_with_period",
			input:   "U.S.A.",
			wantErr: false,
		},
		{
			name:    "valid_with_apostrophe",
			input:   "Cote d'Ivoire",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:      "invalid_single_char",
			input:     "U",
			wantErr:   true,
			errSubstr: "2-50",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", 51),
			wantErr:   true,
			errSubstr: "2-50",
		},
		{
			name:      "invalid_number",
			input:     "Country1",
			wantErr:   true,
			errSubstr: "2-50",
		},
		{
			name:      "invalid_special_char",
			input:     "Country@Name",
			wantErr:   true,
			errSubstr: "2-50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCountry(tt.input)
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
