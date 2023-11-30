package mtls

import (
	"crypto/tls"
	"crypto/x509"
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

type MutualTlsServer interface {
	Start() error
}

type MtlsServerPkiConfigurer struct {
	Config *PkiCerts
}

func (pki *MtlsServerPkiConfigurer) SetupPki() (*tls.Config, error) {

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
	for _, v := range pki.Config.CaFile {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		clientCaPool.AppendCertsFromPEM(ca)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCaPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return tlsConfig, nil
}

type MtlsServer struct {
	Address   string
	TlsConfig *tls.Config
}

func (s *MtlsServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)

	server := &http.Server{
		Addr:      s.Address,
		Handler:   mux,
		TLSConfig: s.TlsConfig,
	}

	return server.ListenAndServeTLS("", "")
}
