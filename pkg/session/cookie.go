package session

import (
	"carapace/pkg/data"
	"log"
	"time"

	"github.com/google/uuid"
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

type SessionService interface {
	CreateSession(s *Session) error
}

func NewSessionService(dao data.SqlRepository) SessionService {
	return &sessionService{
		Db: dao,
	}
}

var _ SessionService = (*sessionService)(nil)

type sessionService struct {
	Db data.SqlRepository
}

func (session *sessionService) CreateSession(s *Session) error {

	if err := session.Db.InsertRecord("uxsession", s); err != nil {
		return err
	}

	return nil
}
