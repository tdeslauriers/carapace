package types

// S2sClient is a model for the service-to-service client table data.
type S2sClient struct {
	Uuid           string `db:"uuid" json:"client_id,omitempty"`
	Password       string `db:"password" json:"client_secret,omitempty"`
	Name           string `db:"name" json:"name"`
	Owner          string `db:"owner" json:"owner"`
	CreatedAt      string `db:"created_at" json:"created_at,omitempty"`
	Enabled        bool   `db:"enabled"  json:"enabled"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked"`
	Slug           string `db:"slug" json:"slug,omitempty"`
}
