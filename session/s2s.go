package session

import "time"

type S2sLoginCmd struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type S2sClientData struct {
	Uuid           string    `db:"uuid"`
	Password       string    `db:"password"`
	Name           string    `db:"name"`
	Owner          string    `db:"owner"`
	CreatedAt      time.Time `db:"created_at"`
	Enabled        bool      `db:"enabled"`
	AccountExpired bool      `db:"acccount_expired"`
	AccountLocked  bool      `db:"account_locked"`
}
