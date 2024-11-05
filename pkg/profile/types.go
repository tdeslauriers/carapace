package profile

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// User is a model struct that represents a user in the accounts table of the identity service db.
// note: it omits the password field for security reasons.
type User struct {
	Id             string          `json:"id,omitempty" db:"uuid"`
	Username       string          `json:"username" db:"username"`
	Firstname      string          `json:"firstname" db:"firstname"`
	Lastname       string          `json:"lastname" db:"lastname"`
	BirthDate      string          `json:"birth_date,omitempty" db:"birth_date"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
}

func (u *User) ValidateCmd() error {

	// validate Id:  Only checks if it is a uuid, not if it is the correct uuid
	// Note: for operations this model is used in, id is often dropped or not the lookup key,
	// check for nil or empty string if needed
	if u.Id != "" && !validate.IsValidUuid(u.Id) {
		return fmt.Errorf("invalid or not well formatted user id")
	}

	// Username is immutable at this time.
	// TODO: make funcitonality to change username
	// only lightweight validation to make sure it isnt too long
	// Note: may not be present in all operations, check for nil or empty string if needed
	if u.Username != "" {
		if len(u.Username) < validate.EmailMin || len(u.Username) > validate.EmailMax {
			return fmt.Errorf("invalid username: must be greater than %d and less than %d characters long", validate.EmailMin, validate.EmailMax)
		}
	}

	// validate Firstname
	if err := validate.IsValidName(u.Firstname); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	// validate Lastname
	if err := validate.IsValidName(u.Lastname); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	// validate Birthdate
	if err := validate.IsValidBirthday(u.BirthDate); err != nil {
		return fmt.Errorf("invalid birthdate: %v", err)
	}

	// validate slug is well formatted if present
	// Note: only checks if it is a uuid, not if it is the correct uuid
	// Slug may or may not be present depending on the operation,
	// if it is supposed to be present, and is not, that will need to be checked elsewhere
	if u.Slug != "" && !validate.IsValidUuid(u.Slug) {
		return fmt.Errorf("invalid or not well formatted slug")
	}

	// CreatedAt is a timestamp, no validation needed, will be dropped on all updates

	// Enabled is a boolean, no validation needed

	// AccountExpired is a boolean, no validation needed

	// AccountLocked is a boolean, no validation needed

	return nil
}

// ResetCmd is the model struct for the password reset command where the user knows their current password
type ResetCmd struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ValidateCmd performs input validation check on reset cmd fields.
// For the new password, it uses the same validation as the register command.
func (r *ResetCmd) ValidateCmd() error {

	// lightweight validation to make sure it isnt to short or too long
	if len(r.CurrentPassword) < validate.PasswordMin || len(r.CurrentPassword) > validate.PasswordMax {
		return fmt.Errorf("invalid current password: must be greater than %d and less than %d characters long", validate.PasswordMin, validate.PasswordMax)
	}

	// true input validation since this will be the incoming password in the identity service
	if err := validate.IsValidPassword(r.NewPassword); err != nil {
		return fmt.Errorf("invalid new password: %v", err)
	}

	// check to make sure the new password and confirm password match
	if r.NewPassword != r.ConfirmPassword {
		return fmt.Errorf("new password and confirm password do not match")
	}

	return nil
}
