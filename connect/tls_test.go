package connect

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/tdeslauriers/carapace/diagnostics"
)

func TestStandardTls(t *testing.T) {
	pki := &Pki{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
		CaFiles:  []string{os.Getenv("CA_CERT")},
	}

	tls, _ := NewTLSConfig("standard", pki)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &TlsServer{
		Addr:      ":8443",
		Mux:       mux,
		TlsConfig: tls,
	}

	go func() {
		if err := server.Initialize(); err != http.ErrServerClosed {
			log.Fatal("Failed to start Server: ", err)
		}
	}()

	clientConfig := &ClientConfig{Config: pki}
	client, err := clientConfig.NewMtlsClient()
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
	if h.Status != "Ok" {
		t.Log("Health Check did not equal \"Ok\"")
		t.Fail()
	}
}

func TestMutalTls(t *testing.T) {
	pki := &Pki{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
		CaFiles:  []string{os.Getenv("CA_CERT")},
	}

	tls, _ := NewTLSConfig("mutual", pki)

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
		CertFile: os.Getenv("CLIENT_CERT"),
		KeyFile:  os.Getenv("CLIENT_KEY"),
		CaFiles:  []string{os.Getenv("CA_CERT")},
	}

	clientConfig := &ClientConfig{Config: clientPki}
	client, err := clientConfig.NewMtlsClient()
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
	if h.Status != "Ok" {
		t.Log("Health Check did not equal \"Ok\"")
		t.Fail()
	}

}
