package data

import (
	"log"
	"os"
	"testing"

	"github.com/tdeslauriers/carapace/connect"
)

func TestDBConnect(t *testing.T) {
	dbPki := connect.Pki{
		CertFile: os.Getenv("CLIENT_CERT"),
		KeyFile:  os.Getenv("CLIENT_KEY"),
		CaFiles:  []string{os.Getenv("CA_CERT")},
	}
	clientConfig := connect.ClientConfig{Config: &dbPki}

	url := DbUrl{
		Username: os.Getenv("CARAPACE_MARIADB_USERNAME"),
		Password: os.Getenv("CARAPACE_MARIADB_PASSWORD"),
		Addr:     os.Getenv("CARAPACE_MARIADB_URL"),
		Name:     os.Getenv("CARAPACE_MARIADB_NAME"),
	}

	dbConnector := &MariaDbConnector{
		TlsConfig:     clientConfig,
		ConnectionUrl: url.Build(),
	}

	db, err := dbConnector.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping test database: %v", err)
	}
}
