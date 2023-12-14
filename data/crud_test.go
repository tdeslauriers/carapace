package data

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/connect"
)

func TestCrud(t *testing.T) {

	dbPki := connect.Pki{
		CertFile: os.Getenv("CLIENT_CERT"),
		KeyFile:  os.Getenv("CLIENT_KEY"),
		CaFiles:  []string{os.Getenv("DB_CA_CERT")},
	}
	clientConfig := connect.ClientConfig{Config: &dbPki}

	url := DbUrl{
		Username: os.Getenv("CARAPACE_MARIADB_USERNAME"),
		Password: os.Getenv("CARAPACE_MARIADB_PASSWORD"),
		Addr:     os.Getenv("CARAPACE_MARIADB_URL"),
		Name:     os.Getenv("CARAPACE_MARIADB_NAME"),
	}

	dbConnector := &SqlDbConnector{
		TlsConfig:     clientConfig,
		ConnectionUrl: url.Build(),
	}

	id, _ := uuid.NewRandom()
	sessionToken, _ := uuid.NewRandom()

	// anonymous struct to avoid circular imports in testing.
	s := struct {
		Uuid         string `db:"uuid"`
		SessionToken string `db:"session_token"`
		CreatedAt    string `db:"created_at"`
		ExpiresAt    string `db:"expires_at"`
	}{
		Uuid:         id.String(),
		SessionToken: sessionToken.String(),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
		ExpiresAt:    time.Now().Add(time.Minute * 15).Format("2006-01-02 15:04:05"),
	}

	if err := dbConnector.InsertRecord("uxsession", s); err != nil {
		t.Logf("Failed to insert session: %v, Error: %v", s, err)
		t.Fail()
	}

	// anonymous struct to avoid circular imports in testing.
	var records []struct {
		Uuid         string `db:"uuid"`
		SessionToken string `db:"session_token"`
		CreatedAt    string `db:"created_at"`
		ExpiresAt    string `db:"expires_at"`
	}
	p := " order by created_at desc"
	err := dbConnector.SelectRecords("uxsession", p, &records)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	for _, v := range records {
		t.Logf("%v", v)
	}

}
