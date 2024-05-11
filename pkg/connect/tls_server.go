package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
)

type TlsServerConfig interface {
	Build() (*tls.Config, error)
}

func NewTlsServerConfig(tlsType string, pki *Pki) TlsServerConfig {
	return &tlsServerConfig{
		Type: tlsType,
		Pki: pki,
	}
}

type tlsServerConfig struct {
	Type string // standard or mutual
	Pki *Pki
}

var _ TlsServerConfig = (*tlsServerConfig)(nil)

func (config *tlsServerConfig) Build() (*tls.Config, error) {

	certPem, err := base64.StdEncoding.DecodeString(config.Pki.CertFile)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode cert file: %v", err)
	}
	keyPem, err := base64.StdEncoding.DecodeString(config.Pki.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode key file: %v", err)
	}

	// public/private key pair
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("could not parse x509 key pair: %v", err)
	}

	switch config.Type {
	case "standard":
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	case "mutual":
		// ca(s) of clients
		clientCaPool := x509.NewCertPool()
		for _, v := range config.Pki.CaFiles {
			ca, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			if ok := clientCaPool.AppendCertsFromPEM(ca); !ok {
				log.Fatalf("failed to load client CA cert.")
			}
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    clientCaPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}, nil
	default:
		return nil, fmt.Errorf("invalid TLS type")
	}
}

type TLSServer interface {
	Initialize() error
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