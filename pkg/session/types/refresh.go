package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Refresh is an interface that abstracts the S2sRefresh and UserRefresh structs
// so that they can be used as generic types in the RefreshService interface.
type Refresh interface {
	S2sRefresh | UserRefresh
}

// RefreshService is an interface for services that handle refresh token retrieval and persistence.
type RefreshService[T Refresh] interface {
	// GetRefreshToken retrieves a refresh token by token string
	GetRefreshToken(token string) (*T, error)

	// PersistRefresh persists a refresh token to the database or cache
	PersistRefresh(refresh T) error

	// DestroyRefresh destroys a refresh token by deleting it from the database or cache
	DestroyRefresh(token string) error

	// RevokeRefresh revokes a refresh token by setting the revoked flag to true in the database or cache
	RevokeRefresh(token string) error
}

// S2sRefresh is a model for the service-to-service refresh table data.
type S2sRefresh struct {
	Uuid         string          `db:"uuid"`
	RefreshIndex string          `db:"refresh_index"`
	ServiceName  string          `db:"service_name"`
	RefreshToken string          `db:"refresh_token"`
	ClientId     string          `db:"client_uuid"`
	ClientIndex  string          `db:"client_index"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

// S2sRefreshCmd is a struct for a s2s refresh token request endpoint to consume.
type S2sRefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
	ServiceName  string `json:"service_name,omitempty"`
}

// ValidateCmd performs very limited checks login cmd fields.
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd S2sRefreshCmd) ValidateCmd() error {

	if validate.TooShort(cmd.RefreshToken, 16) || validate.TooLong(cmd.RefreshToken, 64) {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	if ok, err := validate.IsValidServiceName(cmd.ServiceName); !ok {
		return fmt.Errorf("invalid service name in s2s refresh payload: %v", err)
	}

	return nil
}

// UserRefresh is a model for the user refresh table data.
type UserRefresh struct {
	Uuid          string          `db:"uuid"`
	RefreshIndex  string          `db:"refresh_index"`
	ClientId      string          `db:"client_id"`
	RefreshToken  string          `db:"refresh_token"`
	Username      string          `db:"username"`
	UsernameIndex string          `db:"username_index"`
	Scopes        string          `db:"scopes"`
	CreatedAt     data.CustomTime `db:"created_at"`
	Revoked       bool            `db:"revoked"`
}

// UserRefreshCmd is a struct for a user refresh token request endpoint to consume.
type UserRefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
	ClientId     string `json:"client_id,omitempty"`
}

// ValidateCmd performs very limited checks login cmd fields.
// This is not a complete validation.  The real validation is/should be done in by services
// checking against these values stored in persistent storage.
// This is just a basic check to make sure the values are within the expected range.
func (cmd UserRefreshCmd) ValidateCmd() error {

	if validate.TooShort(cmd.RefreshToken, 16) || validate.TooLong(cmd.RefreshToken, 64) {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}

	if validate.TooShort(cmd.ClientId, 16) || validate.TooLong(cmd.ClientId, 64) {
		return fmt.Errorf("invalid client id: must be between %d and %d characters", 16, 64)
	}

	return nil
}

// DestroyRefreshCmd is a struct for a refresh token destroy request endpoint to consume.
type DestroyRefreshCmd struct {
	DestroyRefreshToken string `json:"destroy_refresh"`
}

func (cmd DestroyRefreshCmd) ValidateCmd() error {
	if validate.TooShort(cmd.DestroyRefreshToken, 16) || validate.TooLong(cmd.DestroyRefreshToken, 64) {
		return fmt.Errorf("invalid refresh token: must be between %d and %d characters", 16, 64)
	}
	return nil
}
