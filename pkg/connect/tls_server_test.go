package connect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/diagnostics"
	"github.com/tdeslauriers/carapace/pkg/sign"
)

const (
	CA_CERT_ENV     = "CA_CERT"
	SERVER_CERT_ENV = "SERVER_CERT"
	SERVER_KEY_ENV  = "SERVER_KEY"
	CLIENT_CERT_ENV = "CLIENT_CERT"
	CLIENT_KEY_ENV  = "CLIENT_KEY"
)

const (
	CaName     string = "rootCa"
	ServerName string = "server"
	ClientName string = "client"
)

func setUpCerts() {

	// create *.pem files
	ca := sign.CertFields{
		CertName:     CaName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "RebelAlliance ECDSA-SHA256",
		Role:         sign.CA,
	}
	ca.GenerateEcdsaCert()

	leafServer := sign.CertFields{
		CertName:     ServerName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Server,
		CaCertName:   ca.CertName,
	}
	leafServer.GenerateEcdsaCert()

	leafClient := sign.CertFields{
		CertName:     ClientName,
		Organisation: []string{"Rebel Alliance"},
		CommonName:   "localhost",
		San:          []string{"localhost"},
		SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
		Role:         sign.Client,
		CaCertName:   ca.CertName,
	}
	leafClient.GenerateEcdsaCert()

	// make base64 strings from pem files
	// set cert base64 vals files to environmental vars to be injested by docker/k8s
	// expected by tls package code
	var envVars [][]string
	envVars = append(envVars, []string{CA_CERT_ENV, fmt.Sprintf("%s-cert.pem", CaName)})
	envVars = append(envVars, []string{SERVER_CERT_ENV, fmt.Sprintf("%s-cert.pem", ServerName)})
	envVars = append(envVars, []string{SERVER_KEY_ENV, fmt.Sprintf("%s-key.pem", ServerName)})
	envVars = append(envVars, []string{CLIENT_CERT_ENV, fmt.Sprintf("%s-cert.pem", ClientName)})
	envVars = append(envVars, []string{CLIENT_KEY_ENV, fmt.Sprintf("%s-key.pem", ClientName)})

	// loop thru setting env
	for _, v := range envVars {

		fileData, _ := os.ReadFile(v[1])
		encodedData := base64.StdEncoding.EncodeToString(fileData)
		if err := os.Setenv(v[0], encodedData); err != nil {
			log.Fatalf("Unable to load env var: %s", v[0])
		}

		// clean up/remove pems
		if err := os.Remove(v[1]); err != nil {
			log.Fatalf("Unable to remove pem file: %s", v[1])
		}
	}

	// remove ca key pem
	if err := os.Remove(fmt.Sprintf("%s-key.pem", CaName)); err != nil {
		log.Fatalf("Unable to remove pem file: %s", fmt.Sprintf("%s-key.pem", CaName))
	}

}

func TestStandardTls(t *testing.T) {

	setUpCerts()

	serverPki := &Pki{
		CertFile: os.Getenv(SERVER_CERT_ENV),
		KeyFile:  os.Getenv(SERVER_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	serverConfig, _ := NewTlsServerConfig("standard", serverPki).Build()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: serverConfig,
	}

	go func() {
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatal("Failed to start Server: ", err)
		}
	}()

	clientPki := &Pki{
		CertFile: os.Getenv(CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	clientConfig := NewTlsClientConfig(clientPki)
	client, err := NewTlsClient(clientConfig)
	if err != nil {
		t.Log("Failed to create tls client: ", err)
	}

	req, err := http.NewRequest("GET", "https://www.google.com", nil)
	if err != nil {
		t.Log("Failed to create public internet request: ", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Log("Call to google failed: ", err)
	}
	defer resp.Body.Close()

	req, err = http.NewRequest("GET", "https://localhost:8443/health", nil)
	if err != nil {
		t.Log("Failed to create health check request: ", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Log("Health check request failed: ", err)
	}
	defer resp.Body.Close()

	var h diagnostics.HealthCheck
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Log("Could not decode health check json:", err)
	}
	if h.Status != "UP" {
		t.Log("Health Check did not equal \"Ok\"")
		t.Fail()
	}
}

func TestMutualTls(t *testing.T) {

	setUpCerts()

	pki := &Pki{
		CertFile: os.Getenv(SERVER_CERT_ENV),
		KeyFile:  os.Getenv(SERVER_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	tls, _ := NewTlsServerConfig("mutual", pki).Build()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &TlsServer{
		Addr:      ":8444",
		Mux:       mux,
		TlsConfig: tls,
	}

	go func() {
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatal("Failed to start Server: ", err)
		}
	}()

	clientPki := &Pki{
		CertFile: os.Getenv(CLIENT_CERT_ENV),
		KeyFile:  os.Getenv(CLIENT_KEY_ENV),
		CaFiles:  []string{os.Getenv(CA_CERT_ENV)},
	}

	clientConfig := NewTlsClientConfig(clientPki)
	client, err := NewTlsClient(clientConfig)
	if err != nil {
		t.Log("Failed to create tls client: ", err)
	}

	req, err := http.NewRequest("GET", "https://localhost:8444/health", nil)
	if err != nil {
		t.Log("Failed to create health check request: ", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Log("Health check request failed: ", err)
	}
	defer resp.Body.Close()

	var h diagnostics.HealthCheck
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Log("Could not decode health check json:", err)
	}
	if h.Status != "UP" {
		t.Log("Health Check did not equal \"Ok\"")
		t.Fail()
	}
}
