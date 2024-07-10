package types

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

type Refresh interface {
	S2sRefresh | UserRefresh
}

type RefreshService[T Refresh] interface {
	GetRefreshToken(token string) (*T, error)
	PersistRefresh(refresh T) error
}

// S2sRefresh is a model for the service-to-service refresh table data.
type S2sRefresh struct {
	Uuid         string          `db:"uuid"`
	RefreshIndex string          `db:"refresh_index"`
	ServiceName  string          `db:"service_name"`
	RefreshToken string          `db:"refresh_token"`
	ClientId     string          `db:"client_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

// UserRefresh is a model for the suer refresh table data.
type UserRefresh struct {
	Uuid         string          `db:"uuid"`
	RefreshIndex string          `db:"refresh_index"`
	ServiceName  string          `db:"service_name"`
	RefreshToken string          `db:"refresh_token"`
	AccountId    string          `db:"account_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

// RefreshCmd is a struct for a refresh token request endpoint to consume.
type RefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
	ServiceName  string `json:"service_name,omitempty"`
}

// ValidateCmd performs regex checks on refresh cmd fields.
func (cmd RefreshCmd) ValidateCmd() error {

	// field input restrictions
	if !validate.IsValidUuid(cmd.RefreshToken) {
		return fmt.Errorf("invalid refresh token")
	}

	if !validate.IsValidServiceName(cmd.ServiceName) {
		return fmt.Errorf("invalid service name")
	}

	return nil
}
