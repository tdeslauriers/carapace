package standard

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"

	"github.com/tdeslauriers/carapace/diagnostics"
)

// base64'd *.pem file --> container env vars --> k8s secret
type PkiCerts struct {
	CertFile string
	KeyFile  string
	CaFile   []string
}

type PkiConfigurer interface {
	SetupPki() (*tls.Config, error)
}

type TlsServer interface {
	Start() error
}

type ServerPkiConfigurer struct {
	Config *PkiCerts
}

func (pki *ServerPkiConfigurer) SetupPki() (*tls.Config, error) {

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

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return tlsConfig, nil
}

type Server struct {
	Address   string
	TlsConfig *tls.Config
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &http.Server{
		Addr:      s.Address,
		Handler:   mux,
		TLSConfig: s.TlsConfig,
	}

	return server.ListenAndServeTLS("", "")
}
