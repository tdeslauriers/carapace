package session

import (
	"fmt"

	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/validate"
)

type Refresh interface {
	S2sRefresh | UserRefresh
}

type RefreshService[T Refresh] interface {
	GetRefreshToken(token string) (*T, error)
	PersistRefresh(refresh T) error
}

// refresh table data
type S2sRefresh struct {
	Uuid         string          `db:"uuid"`
	RefreshToken string          `db:"refresh_token"`
	ClientId     string          `db:"client_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

type UserRefresh struct {
	Uuid         string          `db:"uuid"`
	RefreshToken string          `db:"refresh_token"`
	AccountId    string          `db:"account_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
	Revoked      bool            `db:"revoked"`
}

type RefreshCmd struct {
	RefreshToken string `json:"refresh_token"`
}

func (cmd RefreshCmd) ValidateCmd() error {

	// field input restrictions
	if !validate.IsValidUuid(cmd.RefreshToken) {
		return fmt.Errorf("invalid refresh token")
	}

	return nil
}
