package session

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/diagnostics"
	"github.com/tdeslauriers/carapace/jwt"
	"github.com/tdeslauriers/carapace/sign"
	"golang.org/x/crypto/bcrypt"
)

const (
	S2sServerMariaDbName     = "CARAPACE_SERVER_MARIADB_NAME"
	S2sServerMariaDbUrl      = "CARAPACE_SERVER_MARIADB_URL"
	S2sServerMariaDbUsername = "CARAPACE_SERVER_MARIADB_USERNAME"
	S2sServerMariaDbPassword = "CARAPACE_SERVER_MARIADB_PASSWORD"

	S2sClientMariaDbName     = "CARAPACE_CLIENT_MARIADB_NAME"
	S2sClientMariaDbUrl      = "CARAPACE_CLIENT_MARIADB_URL"
	S2sClientMariaDbUsername = "CARAPACE_CLIENT_MARIADB_USERNAME"
	S2sClientMariaDbPassword = "CARAPACE_CLIENT_MARIADB_PASSWORD"

	S2sClientId     = "CARAPACE_S2S_CLIENT_ID"
	S2sClientSecret = "CARAPACE_S2S_CLIENT_SECRET"
)

func TestS2sLogin(t *testing.T) {

	setUpCerts()

	// set up s2s server
	serverPki := &connect.Pki{
		CertFile: os.Getenv(S2S_SERVER_CERT_ENV),
		KeyFile:  os.Getenv(S2S_SERVER_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	tls, _ := connect.NewTLSConfig("mutual", serverPki)

	// set up s2s server db client
	s2sServerDbClientPki := &connect.Pki{
		CertFile: os.Getenv(S2S_SERVER_DB_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(S2S_SERVER_DB_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}
	s2sServerDbClientConfig := connect.ClientConfig{Config: s2sServerDbClientPki}

	s2sServerDbUrl := data.DbUrl{
		Name:     os.Getenv(S2sServerMariaDbName),
		Addr:     os.Getenv(S2sServerMariaDbUrl),
		Username: os.Getenv(S2sServerMariaDbUsername),
		Password: os.Getenv(S2sServerMariaDbPassword),
	}

	s2sServerDbConnector := &data.MariaDbConnector{
		TlsConfig:     s2sServerDbClientConfig,
		ConnectionUrl: s2sServerDbUrl.Build(),
	}

	s2sServerDao := &data.MariaDbRepository{
		SqlDb: s2sServerDbConnector,
	}

	// set up signer
	priv, _ := sign.GenerateEcdsaSigningKey()           // pub not used here
	privPem, _ := base64.StdEncoding.DecodeString(priv) // read from env var in prod
	privBlock, _ := pem.Decode(privPem)

	s2sPrivateKey, _ := x509.ParseECPrivateKey(privBlock.Bytes)
	s2sSigner := jwt.JwtSignerService{PrivateKey: s2sPrivateKey}

	s2sLoginService := NewS2SLoginService("ran", s2sServerDao, &s2sSigner)
	s2sLoginHander := NewS2sLoginHandler(s2sLoginService)
	s2sRefreshHandler := NewS2sRefreshHandler(s2sLoginService)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/login", s2sLoginHander.HandleS2sLogin)
	mux.HandleFunc("/refresh", s2sRefreshHandler.HandleS2sRefresh)

	s2sServer := &connect.TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: tls,
	}

	go func() {
		if err := s2sServer.Initialize(); err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
		time.Sleep(1 * time.Second)
	}()

	// set up s2s client config
	s2sClientPki := connect.Pki{
		CertFile: os.Getenv(S2S_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(S2S_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	s2sClientConfig := connect.ClientConfig{Config: &s2sClientPki}
	s2sClient, _ := s2sClientConfig.NewTlsClient()

	// set up s2s client-side db config
	s2sClientDbPki := connect.Pki{
		CertFile: os.Getenv(S2S_CLIENT_DB_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(S2S_CLIENT_DB_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}
	s2sClientDbClientConfig := connect.ClientConfig{Config: &s2sClientDbPki}

	s2sClientDbUrl := data.DbUrl{
		Name:     os.Getenv(S2sClientMariaDbName),
		Addr:     os.Getenv(S2sClientMariaDbUrl),
		Username: os.Getenv(S2sClientMariaDbUsername),
		Password: os.Getenv(S2sClientMariaDbPassword),
	}

	s2sClientDbConnector := &data.MariaDbConnector{
		TlsConfig:     s2sClientDbClientConfig,
		ConnectionUrl: s2sClientDbUrl.Build(),
	}

	repository := data.MariaDbRepository{
		SqlDb: s2sClientDbConnector,
	}

	cmd := S2sLoginCmd{
		ClientId:     os.Getenv(S2sClientId),
		ClientSecret: os.Getenv(S2sClientSecret),
	}

	s2sJwtProvider := S2sTokenProvider{
		S2sAuthUrl:  "https://localhost:8443",
		Credentials: cmd,
		S2sClient:   s2sClient,
		Dao:         &repository,
	}

	auth, err := s2sJwtProvider.GetServiceToken()
	if err != nil {
		t.Logf("failed to get service token: %v", err)
	}
	time.Sleep(1 * time.Second) // so refresh persist go funcs can complete.
	if auth == "" {
		t.Logf("s2s service token not returned.")
		t.Fail()
	}

}

// set up test env vars
const (
	CA_CERT_ENV                    = "CA_CERT"
	S2S_SERVER_CERT_ENV            = "S2S_SERVER_CERT"
	S2S_SERVER_KEY_ENV             = "S2S_SERVER_KEY"
	S2S_SERVER_DB_CLIENT_CERT_ENV  = "S2S_SERVER_DB_CLIENT_CERT"
	S2S_SERVER_DB_CLIENT_KEY_ENV   = "S2S_SERVER_DB_CLIENT_KEY"
	S2S_CLIENT_CERT_ENV            = "S2S_CLIENT_CERT"
	S2S_CLIENT_KEY_ENV             = "S2S_CLIENT_KEY"
	S2S_CLIENT_DB_CLIENT_CERT_ENV  = "S2S_CLIENT_DB_CLIENT_CERT"
	S2S_CLIENT_DB_CLIENT_KEY_ENV   = "S2S_CLIENT_DB_CLIENT_KEY"
	AUTH_SERVER_DB_CLIENT_CERT_ENV = "AUTH_SERVER_DB_CLIENT_CERT"
	AUTH_SERVER_DB_CLIENT_KEY_ENV  = "AUTH_SERVER_DB_CLIENT_KEY"
)

const (
	CaCert                 string = "../data/ca"
	S2sServerName          string = "s2s-server"
	S2sServerDbClientName         = "s2s-server-db-client"
	S2sClientName                 = "s2s-client"
	S2sClientDbClientName         = "s2s-client-db-client"
	AuthServerDbClientName        = "auth-db-client"
)

func setUpCerts() {
	// setup server
	leafServer := sign.CertFields{
		CertName:     S2sServerName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Server,
		CaCertName:   CaCert,
	}
	leafServer.GenerateEcdsaCert()

	// gen db client certs
	// need to use ca installed in maria as rootCA
	leafDbClient := sign.CertFields{
		CertName:     S2sServerDbClientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   CaCert,
	}
	leafDbClient.GenerateEcdsaCert()

	// gen s2s client certs
	leafS2sClient := sign.CertFields{
		CertName:     S2sClientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   CaCert,
	}
	leafS2sClient.GenerateEcdsaCert()

	// gen s2s client db client certs
	leafS2sClientDbClient := sign.CertFields{
		CertName:     S2sClientDbClientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   CaCert,
	}
	leafS2sClientDbClient.GenerateEcdsaCert()

	leafAuthClientDbClient := sign.CertFields{
		CertName:     AuthServerDbClientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   CaCert,
	}
	leafAuthClientDbClient.GenerateEcdsaCert()

	// make base64 strings from pem files
	// set cert base64 vals files to environmental vars to be injested by docker/k8s
	// expected by tls package code
	var envVars [][]string
	envVars = append(envVars, []string{CA_CERT_ENV, fmt.Sprintf("%s-cert.pem", CaCert)})
	envVars = append(envVars, []string{S2S_SERVER_CERT_ENV, fmt.Sprintf("%s-cert.pem", S2sServerName)})
	envVars = append(envVars, []string{S2S_SERVER_KEY_ENV, fmt.Sprintf("%s-key.pem", S2sServerName)})
	envVars = append(envVars, []string{S2S_SERVER_DB_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", S2sServerDbClientName)})
	envVars = append(envVars, []string{S2S_SERVER_DB_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", S2sServerDbClientName)})
	envVars = append(envVars, []string{S2S_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", S2sClientName)})
	envVars = append(envVars, []string{S2S_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", S2sClientName)})
	envVars = append(envVars, []string{S2S_CLIENT_DB_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", S2sClientDbClientName)})
	envVars = append(envVars, []string{S2S_CLIENT_DB_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", S2sClientDbClientName)})
	envVars = append(envVars, []string{AUTH_SERVER_DB_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", AuthServerDbClientName)})
	envVars = append(envVars, []string{AUTH_SERVER_DB_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", AuthServerDbClientName)})

	// loop thru setting env
	for _, v := range envVars {

		fileData, _ := os.ReadFile(v[1])
		encodedData := base64.StdEncoding.EncodeToString(fileData)
		if err := os.Setenv(v[0], encodedData); err != nil {
			log.Fatalf("Unable to load env var: %s", v[0])
		}

		// clean up/remove pems
		// if err := os.Remove(v[1]); err != nil {
		// 	log.Fatalf("Unable to remove pem file: %s", v[1])
		// }
	}

}

func TestBcrypt(t *testing.T) {

	// p := ""
	// h, _ := bcrypt.GenerateFromPassword([]byte(p), 13)
	// t.Logf("%s", h)

	pt := os.Getenv(S2sClientSecret)
	hash, _ := bcrypt.GenerateFromPassword([]byte(pt), 13)

	err := bcrypt.CompareHashAndPassword(hash, []byte(pt))
	if err != nil {
		t.Log("pw doesnt match.")
		t.Fail()
	}

}
