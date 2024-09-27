package profile

import "github.com/tdeslauriers/carapace/pkg/data"

// User is a model struct that represents a user in the accounts table of the identity service db.
// note: it omits the password field for security reasons.
type User struct {
	Id             string          `json:"id" db:"uuid"`
	Username       string          `json:"username" db:"username"`
	Firstname      string          `json:"firstname" db:"firstname"`
	Lastname       string          `json:"lastname" db:"lastname"`
	BirthDate      string          `json:"birth_date,omitempty" db:"birth_date"`
	Slug           string          `json:"slug,omitempty" db:"slug"`
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`
	Enabled        bool            `json:"enabled" db:"enabled"`
	AccountExpired bool            `json:"account_expired" db:"account_expired"`
	AccountLocked  bool            `json:"account_locked" db:"account_locked"`
}
