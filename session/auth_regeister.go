package session

import "github.com/tdeslauriers/carapace/data"

type RegistrationService interface{
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

func (r *MariaAuthRegistrationService) Register() error {
	
}