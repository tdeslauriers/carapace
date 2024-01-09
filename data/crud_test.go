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
		CaCertName:   "ca",
	}
	leafClient.GenerateEcdsaCert()

	// read in db-ca-cert.pem, new db-client .pems to env vars
	// need to use ca that signed maria's tls leaf certs
	var envVars [][]string
	envVars = append(envVars, []string{DbServerCaCert, fmt.Sprintf("%s-cert.pem", "ca")})
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

	dbConnector := &MariaDbConnector{
		TlsConfig:     clientConfig,
		ConnectionUrl: url.Build(),
	}

	dao := MariaDbRepository{dbConnector}

	// insert record
	id, _ := uuid.NewRandom()
	sessionToken, _ := uuid.NewRandom()
	csrf, _ := uuid.NewRandom()
	created := time.Now()
	exprires := time.Now().Add(time.Minute * 15)

	// anonymous struct to avoid circular imports in testing.
	insert := struct {
		Uuid         string
		SessionToken string
		CsrfToken    string
		CreatedAt    string
		ExpiresAt    string
	}{
		Uuid:         id.String(),
		SessionToken: sessionToken.String(),
		CsrfToken:    csrf.String(),
		CreatedAt:    created.Format("2006-01-02 15:04:05"),
		ExpiresAt:    exprires.Format("2006-01-02 15:04:05"),
	}

	query := "INSERT INTO uxsession (uuid, session_token, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
	if err := dao.InsertRecord(query, insert); err != nil {
		t.Logf("Failed to insert session: %v, Error: %v", insert, err)
		t.Fail()
	}

	// // anonymous struct to avoid circular imports in testing.
	var records []struct {
		Uuid         string
		SessionToken string
		CsrfToken    string
		CreatedAt    string
		ExpiresAt    string
	}
	query = "SELECT * FROM uxsession WHERE DATE(created_at) = ?"
	year, month, day := created.Date()
	err := dao.SelectRecords(query, &records, fmt.Sprintf("%d-%d-%d", year, month, day))
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Log("Select records output:")
	for _, v := range records {
		t.Logf("%v", v)
	}

	var record struct {
		Uuid         string
		SessionToken string
		CsrfToken    string
		CreatedAt    string
		ExpiresAt    string
	}
	query = "SELECT * FROM uxsession WHERE uuid = ?"
	err = dao.SelectRecord(query, &record, id)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Logf("Select record output:\n%v", record)
}
