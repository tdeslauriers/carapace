package profile

import (
	"strings"
	"testing"
)

// validPassword satisfies all ValidatePassword rules: uppercase, lowercase, number,
// special character, no keyboard sequence, no excessive repeats.
const validPassword = "Tr0ub4dor&3exAmpl!"

// validUUID is a well-formed UUID used for optional csrf / resource_id fields.
const validUUID = "550e8400-e29b-41d4-a716-446655440000"

func TestResetCmdValidateCmd(t *testing.T) {
	tests := []struct {
		name      string
		cmd       ResetCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: ResetCmd{
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// csrf is optional; empty string skips validation entirely.
			name: "csrf_empty_skipped",
			cmd: ResetCmd{
				Csrf:            "",
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// csrf is present and a valid UUID; should pass.
			name: "csrf_valid_uuid",
			cmd: ResetCmd{
				Csrf:            validUUID,
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// csrf is present but not a valid UUID; should fail.
			name: "csrf_invalid_uuid",
			cmd: ResetCmd{
				Csrf:            "not-a-uuid",
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr:   true,
			errSubstr: "invalid csrf",
		},
		{
			// resource_id is optional; empty string skips validation entirely.
			name: "resource_id_empty_skipped",
			cmd: ResetCmd{
				ResourceId:      "",
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// resource_id is present and a valid UUID; should pass.
			name: "resource_id_valid_uuid",
			cmd: ResetCmd{
				ResourceId:      validUUID,
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// resource_id is present but not a valid UUID; should fail.
			name: "resource_id_invalid_uuid",
			cmd: ResetCmd{
				ResourceId:      "not-a-uuid",
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr:   true,
			errSubstr: "invalid resource id",
		},
		{
			// current_password is only length-checked, not fully validated.
			name: "current_password_too_short",
			cmd: ResetCmd{
				CurrentPassword: strings.Repeat("a", 15),
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr:   true,
			errSubstr: "invalid current password",
		},
		{
			name: "current_password_too_long",
			cmd: ResetCmd{
				CurrentPassword: strings.Repeat("a", 65),
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr:   true,
			errSubstr: "invalid current password",
		},
		{
			name: "current_password_at_min_length",
			cmd: ResetCmd{
				CurrentPassword: strings.Repeat("a", 16),
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			name: "current_password_at_max_length",
			cmd: ResetCmd{
				CurrentPassword: strings.Repeat("a", 64),
				NewPassword:     validPassword,
				ConfirmPassword: validPassword,
			},
			wantErr: false,
		},
		{
			// new_password is fully validated; one failing case is enough since
			// ValidatePassword is exhaustively tested in the validate package.
			name: "new_password_invalid",
			cmd: ResetCmd{
				CurrentPassword: validPassword,
				NewPassword:     "alllowercasepassword",
				ConfirmPassword: "alllowercasepassword",
			},
			wantErr:   true,
			errSubstr: "invalid new password",
		},
		{
			// confirm_password must match new_password after TrimSpace.
			name: "confirm_password_mismatch",
			cmd: ResetCmd{
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: validPassword + "X",
			},
			wantErr:   true,
			errSubstr: "do not match",
		},
		{
			// Leading/trailing whitespace on confirm_password is trimmed before comparison.
			name: "confirm_password_matches_after_trim",
			cmd: ResetCmd{
				CurrentPassword: validPassword,
				NewPassword:     validPassword,
				ConfirmPassword: "  " + validPassword + "  ",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.ValidateCmd()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
		})
	}
}
