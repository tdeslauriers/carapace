package types

import (
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// UserRegisterCmd is a struct to hold incoming user registration values to a /register endpoint.
type UserRegisterCmd struct {
	Username  string `json:"username"` // email address
	Password  string `json:"password,omitempty"`
	Confirm   string `json:"confirm_password,omitempty"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`

	// Birthdate is an optional user input field
	Birthdate string `json:"birthdate,omitempty"`

	ClientId string `json:"client_id,omitempty"`

	Session string `json:"session,omitempty"`
	Csrf    string `json:"csrf,omitempty"`
}

// ValidateCmd performs regex checks on user register cmd fields.
// Note: ClientId, Session, Csrf, and Birthdate are not validated here
// because they are not required fields in all use cases.
func (cmd *UserRegisterCmd) ValidateCmd() error {

	if err := validate.IsValidEmail(cmd.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if err := validate.IsValidName(cmd.Firstname); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	if err := validate.IsValidName(cmd.Lastname); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	if err := validate.IsValidBirthday(cmd.Birthdate); err != nil {
		return fmt.Errorf("invalid birthdate: %v", err)
	}

	if cmd.Password != cmd.Confirm {
		return errors.New("password does not match confirm password")
	}

	if err := validate.IsValidPassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	return nil
}
