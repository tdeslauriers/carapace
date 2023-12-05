package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
)

// base64'd *.pem file --> container env vars --> k8s secret
type Pki struct {
	CertFile string
	KeyFile  string
	CaFiles  []string
}

type TlsConfig interface {
	Configure() (*tls.Config, error)
}

type TLSConnection interface {
	Initialize() error
}

type StandardTlsConfig struct {
	Config *Pki
}

func (pki *StandardTlsConfig) Configure() (*tls.Config, error) {

	certPem, err := base64.StdEncoding.DecodeString(pki.Config.CertFile)
	if err != nil {
		return nil, err
	}
	keyPem, err := base64.StdEncoding.DecodeString(pki.Config.KeyFile)
	if err != nil {
		return nil, err
	}

	// public/private key pair
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

type MutualTlsConfig struct {
	Config *Pki
}

func (pki *MutualTlsConfig) Configure() (*tls.Config, error) {

	certPem, err := base64.StdEncoding.DecodeString(pki.Config.CertFile)
	if err != nil {
		return nil, err
	}
	keyPem, err := base64.StdEncoding.DecodeString(pki.Config.KeyFile)
	if err != nil {
		return nil, err
	}

	// public/private key pair
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	// ca(s) of clients
	clientCaPool := x509.NewCertPool()
	for _, v := range pki.Config.CaFiles {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if ok := clientCaPool.AppendCertsFromPEM(ca); !ok {
			log.Fatalf("Failed to load client CA cert.")
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCaPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func NewTLSConfig(tlsType string, pki *Pki) (*tls.Config, error) {
	switch tlsType {
	case "standard":

		standard := &StandardTlsConfig{Config: pki}
		tls, err := standard.Configure()
		if err != nil {
			log.Fatal("Failed to set up standard tls config: ", err)
		}
		return tls, nil
	case "mutual":
		mutual := &MutualTlsConfig{Config: pki}
		mtls, err := mutual.Configure()
		if err != nil {
			log.Fatal("Failed to set up mutual tls config: ", err)
		}
		return mtls, nil
	default:
		return nil, fmt.Errorf("invalid TLS type")
	}
}

type TlsServer struct {
	Addr      string // listens on port, eg, ":8443"
	Mux       *http.ServeMux
	TlsConfig *tls.Config
}

func (s *TlsServer) Initialize() error {

	server := &http.Server{
		Addr:      s.Addr,
		Handler:   s.Mux,
		TLSConfig: s.TlsConfig,
	}

	log.Printf("Starting HTTP server on %s\n", s.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		return err
	}
	return nil
}

type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

type TlsClient struct {
	httpClient *http.Client
}

func (c *TlsClient) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

type ClientConfig struct {
	Config *Pki
}

func (pki *ClientConfig) NewMtlsClient() (*TlsClient, error) {

	certPem, err := base64.StdEncoding.DecodeString(pki.Config.CertFile)
	if err != nil {
		return nil, err
	}

	keyPem, err := base64.StdEncoding.DecodeString(pki.Config.KeyFile)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	// Load host's CA certificates
	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("Could not get system cert pool: %v", err)
	}

	// ca(s) of servers
	for _, v := range pki.Config.CaFiles {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if ok := systemCertPool.AppendCertsFromPEM(ca); !ok {
			log.Fatalf("Could not append additional ca.")
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      systemCertPool,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &TlsClient{httpClient: httpClient}, nil
}
