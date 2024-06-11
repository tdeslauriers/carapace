package session

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/validate"
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

// ValidateCmd performs regex checks on s2s login cmd fields.
func (cmd S2sLoginCmd) ValidateCmd() error {
	// field input restrictions
	if !validate.IsValidUuid(cmd.ClientId) {
		return fmt.Errorf("invalid client id")
	}

	if !validate.IsValidServiceName(cmd.ServiceName) {
		return fmt.Errorf("invalid service name")
	}

	if validate.TooShort(cmd.ClientSecret, validate.PasswordMin) || validate.TooLong(cmd.ClientSecret, validate.EmailMax) {
		return fmt.Errorf("invalid client secret: must be between %d and %d characters", validate.PasswordMin, validate.EmailMax)
	}

	return nil
}

type UserLoginCmd struct {
	Username string `json:"username"`
	Password string `json:"password"`
	State    string `json:"state,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	ClientId string `json:"client_id,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

// ValidateCmd performs very limited checks login cmd fields.
func (cmd UserLoginCmd) ValidateCmd() error {

	// field input restrictions
	if validate.TooShort(cmd.Username, validate.EmailMin) || validate.TooLong(cmd.Username, validate.EmailMax) {
		return fmt.Errorf("invalid username: must be between %d and %d characters", validate.EmailMin, validate.EmailMax)
	}

	if validate.TooShort(cmd.Password, validate.PasswordMin) || validate.TooLong(cmd.Password, validate.PasswordMax) {
		return fmt.Errorf("invalid password: must be between %d and %d characters", validate.PasswordMin, validate.PasswordMax)
	}

	if validate.TooShort(cmd.State, 16) || validate.TooLong(cmd.State, 64) {
		return fmt.Errorf("invalid state: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.Nonce, 16) || validate.TooLong(cmd.Nonce, 64) {
		return fmt.Errorf("invalid nonce: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 66) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.Redirect, 6) || validate.TooLong(cmd.Redirect, 2048) {
		return fmt.Errorf("invalid redirect: must be between %d and %d characters", 16, 64)

	}

	return nil
}

type AuthCodeResponse struct {
	AuthCode string `json:"auth_code"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	ClientId string `json:"client_id"`
	Redirect string `json:"redirect"`
}

type AccessTokenResponse struct {
	AccessToken    string          `json:"access_token" db:"access_token"`
	AccessExpires  data.CustomTime `json:"access_expires" db:"access_expires"`
	IdConnect      string          `json:"id_token" db:"id_token"`
	IdExpires      data.CustomTime `json:"id_expires" db:"id_expires"`
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
}

type UserRegisterCmd struct {
	Username  string `json:"username"` // email address
	Password  string `json:"password,omitempty"`
	Confirm   string `json:"confirm_password,omitempty"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Birthdate string `json:"birthdate,omitempty"`
}

// ValidateCmd performs regex checks on user register cmd fields.
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

// BuildAudiences is a helper func to build audience []string from scopes for jwt struct.
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

type AuthcodeResponse struct {
	AuthCode string `json:"auth_code"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	ClientId string `json:"client_id"`
	Redirect string `json:"redirect"`
}
