package session

import "time"

type Refresh struct {
	Uuid         string    `db:"uuid"`
	RefreshToken string    `db:"refresh_token"`
	ClientId     string    `db:"client_uuid"`
	CreatedAt    time.Time `db:"created_at"`
	Revoked      bool      `db:"revoked"`
}
