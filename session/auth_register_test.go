package session

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
)

const (
	AuthServerMariaDbName      = "CARAPACE_AUTH_SERVER_MARIADB_NAME"
	AuthServerMariaDbUrl       = "CARAPACE_AUTH_SERVER_MARIADB_URL"
	AuthServerMariaDbUsername  = "CARAPACE_AUTH_SERVER_MARIADB_USERNAME"
	AuthServerMariaDbPassword  = "CARAPACE_AUTH_SERVER_MARIADB_PASSWORD"
	AuthServerMariaDbIndexHmac = "CARAPACE_AUTH_SERVER_MARIADB_INDEX_HMAC"
	AuthServerAesKey           = "CARAPACE_FIELD_LEVEL_AES_KEY"
)

func TestRegister(t *testing.T) {

	setUpCerts()

	// set up auth server db client
	authServerDbClientPki := &connect.Pki{
		CertFile: os.Getenv(AUTH_SERVER_DB_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(AUTH_SERVER_DB_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}
	authServerDbClientConfig := connect.ClientConfig{Config: authServerDbClientPki}

	authServerDbUrl := data.DbUrl{
		Name:     os.Getenv(AuthServerMariaDbName),
		Addr:     os.Getenv(AuthServerMariaDbUrl),
		Username: os.Getenv(AuthServerMariaDbUsername),
		Password: os.Getenv(AuthServerMariaDbPassword),
	}

	authServerDbConector := &data.MariaDbConnector{
		TlsConfig:     authServerDbClientConfig,
		ConnectionUrl: authServerDbUrl.Build(),
	}

	authServerDao := &data.MariaDbRepository{
		SqlDb: authServerDbConector,
	}

	// set up field level encryption cryptor
	aes, _ := base64.StdEncoding.DecodeString(os.Getenv(AuthServerAesKey))
	cryptor := data.NewServiceAesGcmKey(aes)

	// set up indexer
	hmacSecret := os.Getenv(AuthServerMariaDbIndexHmac)
	indexer := data.NewHmacIndexer(hmacSecret)

	authRegistrationService := NewAuthRegistrationService(authServerDao, cryptor, indexer)

}
