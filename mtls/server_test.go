package mtls

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"testing"
)

func TestMtlsServer(t *testing.T) {

	serverPki := &PkiCerts{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
		CaFile:   []string{os.Getenv("CA_CERT")},
	}

	serverConfig := &MtlsServerPkiConfigurer{Config: serverPki}
	tlsconfig, err := serverConfig.SetupPki()
	if err != nil {
		t.Log("Failed to set up TLS config: ", err)
	}
	serv := &MtlsServer{
		Address:   ":8443",
		TlsConfig: tlsconfig,
	}
	go func() {

		log.Printf("Starting mTLS server on %s...", serv.Address[1:])
		if err := serv.Start(); err != http.ErrServerClosed {
			t.Log("Failed to start Server: ", err)
		}

	}()

	clientPki := &PkiCerts{
		CertFile: os.Getenv("CLIENT_CERT"),
		KeyFile:  os.Getenv("CLIENT_KEY"),
		CaFile:   []string{os.Getenv("CA_CERT")},
	}

	clientConfig := &MtlsClientPkiConfigurer{Config: clientPki}
	client, err := clientConfig.NewMtlsClient()
	if err != nil {
		t.Log("Failed to create mTLS client: ", err)
	}

	req, err := http.NewRequest("GET", "https://localhost:8443/health", nil)
	if err != nil {
		t.Log("Failed to create health check request: ", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Log("Health check request failed: ", err)
	}
	defer resp.Body.Close()

	var h HealthCheck
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Log("Could not decode health check json:", err)
	}
	if h.Status != "Ok" {
		t.Log("Health Check did not equal \"Ok\"")
		t.Fail()
	}

	// bad request: endpooint does not exist
	noEndpoint, err := http.NewRequest("GET", "https://localhost:8443/doesntExist", nil)
	if err != nil {
		t.Log("Failed to create health check request: ", err)
	}
	resp, err = client.Do(noEndpoint)
	if err != nil {
		t.Log("Health check request failed: ", err)
	}
	if resp.StatusCode != 404 {
		t.Log("Expected /doesntExist to return 404, but was ", resp.StatusCode)
		t.Fail()
	}

}