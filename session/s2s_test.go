package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/connect"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/diagnostics"
	"github.com/tdeslauriers/carapace/sign"
	"golang.org/x/crypto/bcrypt"
)

const (
	ServerMariaDbName     = "CARAPACE_SERVER_MARIADB_NAME"
	ServerMariaDbUrl      = "CARAPACE_SERVER_MARIADB_URL"
	ServerMariaDbUsername = "CARAPACE_SERVER_MARIADB_USERNAME"
	ServerMariaDbPassword = "CARAPACE_SERVER_MARIADB_PASSWORD"

	ClientMariaDbName     = "CARAPACE_CLIENT_MARIADB_NAME"
	ClientMariaDbUrl      = "CARAPACE_CLIENT_MARIADB_URL"
	ClientMariaDbUsername = "CARAPACE_CLIENT_MARIADB_USERNAME"
	ClientMariaDbPassword = "CARAPACE_CLIENT_MARIADB_PASSWORD"
)

func TestS2sLogin(t *testing.T) {

	setUpCerts()

	// set up server
	serverPki := &connect.Pki{
		CertFile: os.Getenv(LOGIN_SERVER_CERT_ENV),
		KeyFile:  os.Getenv(LOGIN_SERVER_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	tls, _ := connect.NewTLSConfig("mutual", serverPki)

	// set up db client
	serverDbClientPki := &connect.Pki{
		CertFile: os.Getenv(LOGIN_SERVER_DB_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(LOGIN_SERVER_DB_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}
	serverDbClientConfig := connect.ClientConfig{Config: serverDbClientPki}

	dbUrl := data.DbUrl{
		Name:     os.Getenv(ServerMariaDbName),
		Addr:     os.Getenv(ServerMariaDbUrl),
		Username: os.Getenv(ServerMariaDbUsername),
		Password: os.Getenv(ServerMariaDbPassword),
	}

	dbConnector := &data.MariaDbConnector{
		TlsConfig:     serverDbClientConfig,
		ConnectionUrl: dbUrl.Build(),
	}

	dao := &data.MariaDbRepository{
		SqlDb: dbConnector,
	}

	loginService := NewS2SLoginService(dao)
	loginHander := NewS2sLoginHandler(loginService)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/login", loginHander.HandleS2sLogin)

	server := &connect.TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: tls,
	}

	go func() {
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	clientPki := connect.Pki{
		CertFile: os.Getenv(S2S_CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(S2S_CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	clientConfig := connect.ClientConfig{Config: &clientPki}
	client, _ := clientConfig.NewTlsClient()

	cmd := S2sLoginCmd{

		ClientId:     "669543c1-e3b4-414a-bb6f-039f3b4bb301",
		ClientSecret: "3, 2, 1, let's jam!",
	}
	jsonData, _ := json.Marshal(cmd)
	req, _ := http.NewRequest("POST", "https://localhost:8443/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := client.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Did not get 200 for correct credentials: %s", string(body))
		t.Fail()
	}
}

const (
	CA_CERT_ENV                     = "CA_CERT"
	LOGIN_SERVER_CERT_ENV           = "LOGIN_SERVER_CERT"
	LOGIN_SERVER_KEY_ENV            = "LOGIN_SERVER_KEY"
	LOGIN_SERVER_DB_CLIENT_CERT_ENV = "LOGIN_SERVER_DB_CLIENT_CERT"
	LOGIN_SERVER_DB_CLIENT_KEY_ENV  = "LOGIN_SERVER_DB_CLIENT_KEY"
	S2S_CLIENT_CERT_ENV             = "S2S_CLIENT_CERT"
	S2S_CLIENT_KEY_ENV              = "S2S_CLIENT_KEY"
)

const (
	CaCert                  string = "../data/ca"
	LoginServerName         string = "login-server"
	LoginServerDbClientName string = "db-client"
	S2sCLientName                  = "s2s-client"
)

func setUpCerts() {
	// setup server
	leafServer := sign.CertFields{
		CertName:     LoginServerName,
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
		CertName:     LoginServerDbClientName,
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
		CertName:     S2sCLientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   CaCert,
	}
	leafS2sClient.GenerateEcdsaCert()

	// make base64 strings from pem files
	// set cert base64 vals files to environmental vars to be injested by docker/k8s
	// expected by tls package code
	var envVars [][]string
	envVars = append(envVars, []string{CA_CERT_ENV, fmt.Sprintf("%s-cert.pem", CaCert)})
	envVars = append(envVars, []string{LOGIN_SERVER_CERT_ENV, fmt.Sprintf("%s-cert.pem", LoginServerName)})
	envVars = append(envVars, []string{LOGIN_SERVER_KEY_ENV, fmt.Sprintf("%s-key.pem", LoginServerName)})
	envVars = append(envVars, []string{LOGIN_SERVER_DB_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", LoginServerDbClientName)})
	envVars = append(envVars, []string{LOGIN_SERVER_DB_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", LoginServerDbClientName)})
	envVars = append(envVars, []string{S2S_CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", S2sCLientName)})
	envVars = append(envVars, []string{S2S_CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", S2sCLientName)})

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

	pt := "3, 2, 1, let's jam!"
	hash, _ := bcrypt.GenerateFromPassword([]byte(pt), 13)
	uuid, _ := uuid.NewRandom()
	t.Logf("%s", uuid.String())
	t.Logf("%s", hash)

	err := bcrypt.CompareHashAndPassword(hash, []byte(pt))
	if err != nil {
		t.Log("pw doesnt match.")
		t.Fail()
	}

}
