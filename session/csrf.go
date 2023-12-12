package session

import (
	"time"
)

type CSRF struct {
	Id      int64
	Csrf    string // uuid in string form
	Created time.Time
	Expiry  time.Time
}
