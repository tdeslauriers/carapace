package session

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
)

type Session struct {
	Uuid         string `db:"uuid"`
	SessionToken string `db:"session_token"`
	CsrfToken    string `db:"csrf_token"`
	CreatedAt    string `db:"created_at"`
	ExpiresAt    string `db:"expires_at"`
}

func Build() (*Session, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create Session identifier uuid: %v", err)
	}
	sessionToken, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create Session token uuid: %v", err)
	}
	csrfToken, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create CSRF token uuid: %v", err)
	}

	return &Session{
		Uuid:         id.String(),
		SessionToken: sessionToken.String(),
		CsrfToken:    csrfToken.String(),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
		ExpiresAt:    time.Now().Add(time.Minute * 15).Format("2006-01-02 15:04:05"),
	}, nil
}

type SessionService interface {
	Persist(s *Session) error
}

func NewSessionService(dao data.SqlRepository) SessionService {
	return &sessionService{
		db: dao,
	}
}

var _ SessionService = (*sessionService)(nil)

type sessionService struct {
	db data.SqlRepository
}

func (svc *sessionService) Persist(s *Session) error {

	if err := svc.db.InsertRecord("uxsession", s); err != nil {
		return err
	}

	return nil
}
