package session

import (
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/validate"
)

type RegistrationService interface {
	Register(RegisterCmd) error
}

type RegisterCmd struct {
	Username  string `json:"username"` // email address
	Password  string `json:"password"`
	Confirm   string `json:"confirm_password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Birthdate string `json:"bithdate,omitempty"`
}

type MariaAuthRegistrationService struct {
	Dao data.SqlRepository
}

func NewAuthRegistrationService(sql data.SqlRepository) *MariaAuthRegistrationService {
	return &MariaAuthRegistrationService{
		Dao: sql,
	}
}

func (r *MariaAuthRegistrationService) Register(cmd RegisterCmd) error {

	if err := validate.ValidateEmail(cmd.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if cmd.Password != cmd.Confirm {
		return errors.New("password does not match confirm password")
	}

	if err := validate.ValidatePassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	return nil
}
