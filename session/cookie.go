package session

type Session struct {
	Uuid         string `db:"uuid"`
	SessionToken string `db:"session_token"`
	CreatedAt    string `db:"created_at"`
	ExpiresAt    string `db:"expires_at"`
}
