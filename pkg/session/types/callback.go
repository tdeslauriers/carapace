package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

type AuthCodeCmd struct {
	Session string `json:"session"`

	AuthCode     string `json:"auth_code"`
	ResponseType string `json:"response_type"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	ClientId     string `json:"client_id"`
	Redirect     string `json:"redirect"`
}

func (cmd *AuthCodeCmd) ValidateCmd() error {
	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ResponseType, 4) || validate.TooLong(cmd.ResponseType, 8) {
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

type AccessTokenCmd struct {
	GrantType   string `json:"grant_type"`
	AuthCode    string `json:"auth_code"`
	ClientId    string `json:"client_id"`
	RedirectUrl string `json:"redirect_url"`
}

func (cmd *AccessTokenCmd) ValidateCmd() error {
	if validate.TooShort(cmd.GrantType, 4) || validate.TooLong(cmd.GrantType, 8) {
		return fmt.Errorf("invalid grant type: must be between %d and %d characters", 4, 8)
	}

	if validate.TooShort(cmd.AuthCode, 16) || validate.TooLong(cmd.AuthCode, 64) {
		return fmt.Errorf("invalid auth code: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.RedirectUrl, 6) || validate.TooLong(cmd.RedirectUrl, 2048) {
		return fmt.Errorf("invalid redirect url: must be between %d and %d characters", 16, 2048)
	}

	return nil
}
