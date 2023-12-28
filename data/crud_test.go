package data

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/certs"
	"github.com/tdeslauriers/carapace/connect"
)

// env vars in db_connect_test.go

func TestCrud(t *testing.T) {

	// setup
	// gen client certs
	// need to use ca installed in maria as rootCA
	leafClient := certs.CertFields{
		CertName:     "db-client",
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         certs.Client,
		CaCertName:   "db-ca",
	}
	leafClient.GenerateEcdsaCert()

	// read in db-ca-cert.pem, new db-client .pems to env vars
	// need to use ca that signed maria's tls leaf certs
	var envVars [][]string
	envVars = append(envVars, []string{DbServerCaCert, fmt.Sprintf("%s-cert.pem", "db-ca")})
	envVars = append(envVars, []string{DbClientCert, fmt.Sprintf("%s-cert.pem", leafClient.CertName)})
	envVars = append(envVars, []string{DbClientKey, fmt.Sprintf("%s-key.pem", leafClient.CertName)})

	// loop thru setting env
	for _, v := range envVars {

		fileData, _ := os.ReadFile(v[1])
		encodedData := base64.StdEncoding.EncodeToString(fileData)
		if err := os.Setenv(v[0], encodedData); err != nil {
			log.Fatalf("Unable to load env var: %s", v[0])
		}
	}

	dbPki := connect.Pki{
		CertFile: os.Getenv(DbClientCert),
		KeyFile:  os.Getenv(DbClientKey),
		CaFiles:  []string{os.Getenv(DbServerCaCert)},
	}
	clientConfig := connect.ClientConfig{Config: &dbPki}

	url := DbUrl{
		Username: os.Getenv(MariaDbUsername),
		Password: os.Getenv(MariaDbPassword),
		Addr:     os.Getenv(MariaDbUrl),
		Name:     os.Getenv(MariaDbName),
	}

	dbConnector := &SqlDbConnector{
		TlsConfig:     clientConfig,
		ConnectionUrl: url.Build(),
	}

	id, _ := uuid.NewRandom()
	sessionToken, _ := uuid.NewRandom()
	csrf, _ := uuid.NewRandom()

	// anonymous struct to avoid circular imports in testing.
	s := struct {
		Uuid         string `db:"uuid"`
		SessionToken string `db:"session_token"`
		CsrfToken    string `db:"csrf_token"`
		CreatedAt    string `db:"created_at"`
		ExpiresAt    string `db:"expires_at"`
	}{
		Uuid:         id.String(),
		SessionToken: sessionToken.String(),
		CsrfToken:    csrf.String(),
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
		CsrfToken    string `db:"csrf_token"`
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
