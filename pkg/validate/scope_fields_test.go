package validate

import (
	"strings"
	"testing"
)

func TestValidateScope(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_read_wildcard",
			scope:   "r:pixie:*",
			wantErr: false,
		},
		{
			name:    "valid_write",
			scope:   "w:gandalf:posts",
			wantErr: false,
		},
		{
			name:    "valid_delete",
			scope:   "d:service:resource",
			wantErr: false,
		},
		{
			name:    "valid_exact_min_length",
			scope:   "r:ab:cd",
			wantErr: false,
		},
		{
			name:    "valid_exact_max_length",
			scope:   "r:" + strings.Repeat("a", ScopeMax-2),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			scope:     "r:ab:",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			scope:     "r:" + strings.Repeat("a", ScopeMax),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			scope:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_no_colon",
			scope:     "rservice",
			wantErr:   true,
			errSubstr: "access option",
		},
		{
			name:      "invalid_bad_access_option",
			scope:     "x:pixie:posts",
			wantErr:   true,
			errSubstr: "access option",
		},
		{
			name:      "invalid_uppercase_access_option",
			scope:     "R:pixie:posts",
			wantErr:   true,
			errSubstr: "access option",
		},
		{
			name:      "invalid_special_chars",
			scope:     "r:pixie@posts",
			wantErr:   true,
			errSubstr: "may only contain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScope(tt.scope)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for scope %q", tt.scope)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for scope %q: %v", tt.scope, err)
			}
		})
	}
}

func TestValidateScopeName(t *testing.T) {
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
			input:   strings.Repeat("A", ScopeNameMax),
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
			input:     strings.Repeat("A", ScopeNameMax+1),
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
			name:      "invalid_hyphen",
			input:     "Read-Posts",
			wantErr:   true,
			errSubstr: "letters, numbers, or spaces",
		},
		{
			name:      "invalid_colon",
			input:     "r:pixie",
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
			err := ValidateScopeName(tt.input)
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
