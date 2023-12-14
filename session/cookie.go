package session

import (
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
)

type Session struct {
	Uuid         string `db:"uuid"`
	SessionToken string `db:"session_token"`
	CsrfToken    string `db:"csrf_token"`
	CreatedAt    string `db:"created_at"`
	ExpiresAt    string `db:"expires_at"`
}

func BuildSession() Session {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create Session identifier uuid: %v", err)
	}
	sessionToken, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create Session token uuid: %v", err)
	}
	csrfToken, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("Unable to create CSRF token uuid: %v", err)
	}

	return Session{
		Uuid:         id.String(),
		SessionToken: sessionToken.String(),
		CsrfToken:    csrfToken.String(),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
		ExpiresAt:    time.Now().Add(time.Minute * 15).Format("2006-01-02 15:04:05"),
	}
}

func CreateSession(crud data.SqlDbConnector) Session {

	s := BuildSession()

	if err := crud.InsertRecord("uxsession", s); err != nil {
		log.Panicf("Unable to load session data into db: %v", err)
	}

	return s
}
