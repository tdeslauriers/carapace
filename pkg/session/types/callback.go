package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// // GrantType is a string type that represents the type of grant being requested from the authroization server,
// // eg., authorization_code, refresh_token, client_credentials, or password
// type GrantType string

// const (
// 	AuthorizationCode GrantType = "authorization_code"
// 	RefreshToken      GrantType = "refresh_token"
// 	ClientCredentials GrantType = "client_credentials"
// 	Password          GrantType = "password"
// )

// AuthCodeCmd is a struct to hold incoming authcode and session values
// that are forwaded to the callback endpoint gateway as part of
// the oauth2 authorization code flow.
// Note: is is possibe session value will be empty if session token is sent as a cookie header.
type AuthCodeCmd struct {
	Session string `json:"session,omitempty"`

	AuthCode     string       `json:"auth_code"`
	ResponseType ResponseType `json:"response_type"`
	State        string       `json:"state"`
	Nonce        string       `json:"nonce"`
	ClientId     string       `json:"client_id"`
	Redirect     string       `json:"redirect"`
}

// ValidateCmd conducts light-weight validation of incoming authcode and session values
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *AuthCodeCmd) ValidateCmd() error {

	if validate.TooShort(cmd.Session, 16) || validate.TooLong(cmd.Session, 64) {
		return fmt.Errorf("invalid session: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(string(cmd.ResponseType), 4) || validate.TooLong(string(cmd.ResponseType), 8) {
		return fmt.Errorf("invalid response type: must be between %d and %d characters", 4, 8)
	}

	if validate.TooShort(cmd.State, 16) || validate.TooLong(cmd.State, 254) {
		return fmt.Errorf("invalid state: must be between %d and %d characters", 16, 254)
	}

	if validate.TooShort(cmd.Nonce, 16) || validate.TooLong(cmd.Nonce, 64) {
		return fmt.Errorf("invalid nonce: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.Redirect, 6) || validate.TooLong(cmd.Redirect, 2048) {
		return fmt.Errorf("invalid redirect: must be between %d and %d characters", 16, 2048)
	}

	return nil

}

// // AccessTokenCmd is a struct to hold incoming access token values
// // that are forwaded to the callback endpoint gateway to the authroization server
// // as part of the oauth2 authorization code flow.
// type AccessTokenCmd struct {
// 	Grant       GrantType `json:"grant_type"`
// 	AuthCode    string    `json:"auth_code"`
// 	ClientId    string    `json:"client_id"`
// 	RedirectUrl string    `json:"redirect_url"`
// }

// // ValidateCmd conducts light-weight validation of incoming access token values
// // This is not a complete validation.  The real validation is/should be done in by services
// // checking against these values stored in persistent storage.
// // This is just a basic check to make sure the values are within the expected range.
// func (cmd *AccessTokenCmd) ValidateCmd() error {
// 	if validate.TooShort(string(cmd.Grant), 4) || validate.TooLong(string(cmd.Grant), 32) {
// 		return fmt.Errorf("invalid grant type: must be between %d and %d characters", 4, 32)
// 	}

// 	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
// 		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
// 	}

// 	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
// 		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
// 	}

// 	if validate.TooShort(cmd.RedirectUrl, 6) || validate.TooLong(cmd.RedirectUrl, 2048) {
// 		return fmt.Errorf("invalid redirect url: must be between %d and %d characters", 16, 2048)
// 	}

// 	return nil
// }
