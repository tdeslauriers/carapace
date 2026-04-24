package profile

import (
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// ResetCmd is the model struct for the password reset command where the user knows their current password
type ResetCmd struct {
	Csrf       string `json:"csrf,omitempty"`        // wont be sent thru to the identity service
	ResourceId string `json:"resource_id,omitempty"` // wont be sent thru to the identity service, only the s2s service

	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ValidateCmd performs input validation check on reset cmd fields.
// For the new password, it uses the same validation as the register command.
func (r *ResetCmd) ValidateCmd() error {

	// validate csrf
	// Note: csrf is not sent to the identity or s2s service, only the gateway
	if r.Csrf != "" && validate.ValidateUuid(r.Csrf) != nil {
		return fmt.Errorf("invalid csrf")
	}

	// validate resource id if present
	// Note: resource id is not sent to the identity, only the s2s service
	if r.ResourceId != "" && validate.ValidateUuid(r.ResourceId) != nil {
		return fmt.Errorf("invalid resource id")
	}

	// lightweight validation to make sure it isnt to short or too long
	if len(r.CurrentPassword) < validate.PasswordMin || len(r.CurrentPassword) > validate.PasswordMax {
		return fmt.Errorf("invalid current password: must be greater than %d and less than %d characters long", validate.PasswordMin, validate.PasswordMax)
	}

	// true input validation since this will be the incoming password in the identity service
	if err := validate.ValidatePassword(r.NewPassword); err != nil {
		return fmt.Errorf("invalid new password: %v", err)
	}

	// check to make sure the new password and confirm password match
	if strings.TrimSpace(r.NewPassword) != strings.TrimSpace(r.ConfirmPassword) {
		return fmt.Errorf("new password and confirm password do not match")
	}

	return nil
}
