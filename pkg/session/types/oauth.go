package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// ResponseType is a string type that represents the type of response being requested from the authroization server,
type ResponseType string

const (
	AuthCode ResponseType = "code"
	Token    ResponseType = "token"
	IdToken  ResponseType = "id_token"
)

// AuthCodeExchange is a struct to hold incoming authcode values requied for the oauth2 authorization code flow.
type AuthCodeExchange struct {
	AuthCode     string       `json:"auth_code"`
	ResponseType ResponseType `json:"response_type"`
	State        string       `json:"state"`
	Nonce        string       `json:"nonce"`
	ClientId     string       `json:"client_id"`
	Redirect     string       `json:"redirect"`
}

// ValidateCmd is light validation for auth code exchange.
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *AuthCodeExchange) ValidateCmd() error {
	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(string(cmd.ResponseType), 4) || validate.TooLong(string(cmd.ResponseType), 8) {
		return fmt.Errorf("invalid response type: must be between %d and %d characters", 4, 8)
	}

	if validate.TooShort(cmd.State, 16) || validate.TooLong(cmd.State, 64) {
		return fmt.Errorf("invalid state: must be between %d and %d characters", 16, 64)
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
