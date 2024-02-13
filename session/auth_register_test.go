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
	AuthServerAesKey           = "CARAPACE_AUTH_FIELD_LEVEL_AES_KEY"
	AuthS2sClientId            = "CARAPACE_AUTH_SERVER_S2S_CLIENT_ID"
	AuthS2sClientSecret        = "CARAPACE_AUTH_SERVER_S2S_CLIENT_SECRET"
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
	t.Logf("%d", len(aes))
	cryptor := data.NewServiceAesGcmKey(aes)

	// set up indexer
	hmacSecret, _ := base64.StdEncoding.DecodeString(os.Getenv(AuthServerAesKey))
	indexer := data.NewHmacIndexer(hmacSecret)

	// set up s2s provider
	s2sClientPki := connect.Pki{
		CertFile: os.Getenv(S2S_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(S2S_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	s2sClientConfig := connect.ClientConfig{Config: &s2sClientPki}
	s2sClient, _ := s2sClientConfig.NewTlsClient()

	s2sCmd := S2sLoginCmd{
		ClientId:     os.Getenv(AuthS2sClientId),
		ClientSecret: os.Getenv(AuthS2sClientSecret),
	}

	s2sJwtProvder := NewS2sTokenProvider("https://localhoset:8443", s2sCmd, s2sClient, authServerDao)

	authRegistrationService := NewAuthRegistrationService(authServerDao, cryptor, indexer, s2sJwtProvder)

	cmd := RegisterCmd{
		Username:  "darth.vader@empire.com",
		Password:  "2-Suns-Tattooine",
		Confirm:   "2-Suns-Tattooine",
		Firstname: "Darth",
		Lastname:  "Vader",
		Birthdate: "1977-05-25", // A New Hope release date
	}

	if err := authRegistrationService.Register(cmd); err != nil {
		t.Logf("test registration failed: %v", err)
		t.Fail()
	}

}
