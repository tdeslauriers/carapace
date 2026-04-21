package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// S2sLoginCmd is a struct for a service-to-service login request endpoint to consume.
type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ServiceName  string `json:"service_name,omitempty"`
}

// ValidateCmd performs regex checks on s2s login cmd fields.
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd *S2sLoginCmd) ValidateCmd() error {
	// field input restrictions
	if validate.ValidateUuid(cmd.ClientId) != nil {
		return fmt.Errorf("invalid client id")
	}

	if err := validate.ValidateServiceName(cmd.ServiceName); err != nil {
		return fmt.Errorf("invalid service in s2s login payload: %v", err)
	}

	if validate.TooShort(cmd.ClientSecret, validate.PasswordMin) || validate.TooLong(cmd.ClientSecret, validate.EmailMax) {
		return fmt.Errorf("invalid client secret: must be between %d and %d characters", validate.PasswordMin, validate.EmailMax)
	}

	return nil
}

