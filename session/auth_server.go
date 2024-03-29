package session

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/validate"
)

// s2s login service -> validates incoming login
type AuthService interface {
	ValidateCredentials(id, secret string) error
	GetUserScopes(uuid, service string) ([]Scope, error)
	MintAuthzToken(subject, service string) (*jwt.JwtToken, error) // assumes valid creds
}

type S2sAuthService interface {
	AuthService
	RefreshService[S2sRefresh]
}

type UserAuthService interface {
	AuthService
	RefreshService[UserRefresh]
}

// for config/service setup
type S2sCredentials struct {
	ClientId     string
	ClientSecret string
}

// for s2s login call -> needs service name
type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ServiceName  string `json:"service_name,omitempty"`
}

func (cmd S2sLoginCmd) ValidateCmd() error {
	// field input restrictions
	if !validate.IsValidUuid(cmd.ClientId) {
		return fmt.Errorf("invalid client id")
	}

	if err := validate.IsValidPassword(cmd.ClientSecret); err != nil {
		return fmt.Errorf("invalid client secret")
	}

	if !validate.IsValidServiceName(cmd.ServiceName) {
		return fmt.Errorf("invalid service name")
	}

	return nil
}

type UserLoginCmd struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (cmd UserLoginCmd) ValidateCmd() error {

	// field input restrictions
	if err := validate.IsValidEmail(cmd.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if err := validate.IsValidPassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	return nil
}

type UserRegisterCmd struct {
	Username  string `json:"username"` // email address
	Password  string `json:"password,omitempty"`
	Confirm   string `json:"confirm_password,omitempty"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Birthdate string `json:"birthdate,omitempty"`
}

// input validation
func (cmd UserRegisterCmd) ValidateCmd() error {

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
		return fmt.Errorf("invalid birthday: %v", err)
	}

	if cmd.Password != cmd.Confirm {
		return errors.New("password does not match confirm password")
	}

	if err := validate.IsValidPassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	return nil
}

type S2sClientData struct {
	Uuid           string `db:"uuid" json:"client_id"`
	Password       string `db:"password" json:"client_secret"`
	Name           string `db:"name" json:"name"`
	Owner          string `db:"owner" json:"owner"`
	CreatedAt      string `db:"created_at" json:"created_at"`
	Enabled        bool   `db:"enabled"  json:"enabled"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked"`
}

type UserAccountData struct {
	Uuid           string `db:"uuid" json:"uuid,omitempty"`
	Username       string `db:"username" json:"username"`
	UserIndex      string `db:"user_index" json:"user_index,omitempty"`
	Password       string `db:"password" json:"password,omitempty"`
	Firstname      string `db:"firstname" json:"firstname"`
	Lastname       string `db:"lastname" json:"lastname"`
	Birthdate      string `db:"birthdate" json:"bithdate,omitempty"` // string because field encrypted in db
	CreatedAt      string `db:"created_at" json:"created_at"`
	Enabled        bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked,omitempty"`
}

// maps db table data, not jwt string
type Scope struct {
	Uuid        string `db:"uuid" json:"scope_id"`
	ServiceName string `db:"service_name" json:"service_name"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
}

type AccountScopeXref struct {
	Id          int    `db:"id" json:"id"`
	AccountUuid string `db:"account_uuid" json:"account_uuid"`
	ScopeUuid   string `db:"scope_uuid" json:"scope_uuid"`
	CreatedAt   string `db:"created_at" json:"created_at"`
}

// helper func to build audience []string from scopes
func BuildAudiences(scopes []Scope) (unique []string) {

	var services []string
	for _, v := range scopes {
		s := strings.Split(v.Scope, ":") // splits scope by : -> w:service:*
		services = append(services, s[1])
	}

	set := make(map[string]struct{}, 0) // ie, one of each value
	for _, service := range services {
		if _, ok := set[service]; !ok {
			set[service] = struct{}{}
			unique = append(unique, service)
		}
	}

	return unique
}
