package validate

import (
	"strings"
	"testing"
)

func TestValidatePermissionName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "Read Posts",
			wantErr: false,
		},
		{
			name:    "valid_alphanumeric",
			input:   "Admin123",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   "AB",
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("A", PermissionNameMax),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "A",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", PermissionNameMax+1),
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
			name:      "invalid_underscore",
			input:     "Read_Posts",
			wantErr:   true,
			errSubstr: "letters, numbers, or spaces",
		},
		{
			name:      "invalid_hyphen",
			input:     "Read-Posts",
			wantErr:   true,
			errSubstr: "letters, numbers, or spaces",
		},
		{
			name:      "invalid_special_char",
			input:     "Read@Posts",
			wantErr:   true,
			errSubstr: "letters, numbers, or spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePermissionName(tt.input)
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

func TestValidatePermission(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "READ",
			wantErr: false,
		},
		{
			name:    "valid_with_underscore",
			input:   "READ_POSTS",
			wantErr: false,
		},
		{
			name:    "valid_with_numbers",
			input:   "READ123",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   "AB",
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("A", PermissionMax),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "A",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("A", PermissionMax+1),
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
			name:      "invalid_lowercase",
			input:     "read_posts",
			wantErr:   true,
			errSubstr: "upper case letters",
		},
		{
			name:      "invalid_space",
			input:     "READ POSTS",
			wantErr:   true,
			errSubstr: "upper case letters",
		},
		{
			name:      "invalid_hyphen",
			input:     "READ-POSTS",
			wantErr:   true,
			errSubstr: "upper case letters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePermission(tt.input)
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
