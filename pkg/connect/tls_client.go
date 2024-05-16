package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
)

type TlsClientConfig interface {
	Build() (*tls.Config, error)
}

func NewTlsClientConfig(pki *Pki) TlsClientConfig {
	return &tlsClientConfig{
		Pki: pki,
	}

}

type tlsClientConfig struct {
	Pki *Pki
}

var _ TlsClientConfig = (*tlsClientConfig)(nil)

func (config *tlsClientConfig) Build() (*tls.Config, error) {
	certPem, err := base64.StdEncoding.DecodeString(config.Pki.CertFile)
	if err != nil {
		return nil, err
	}

	keyPem, err := base64.StdEncoding.DecodeString(config.Pki.KeyFile)
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
		return nil, fmt.Errorf("failed to get system cert pool: %v", err)
	}

	// ca(s) of internal servers
	for _, v := range config.Pki.CaFiles {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if ok := systemCertPool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("failed to append additional ca cert to system cert pool")
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      systemCertPool,
	}, nil
}

type TlsClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewTlsClient(config TlsClientConfig) (TlsClient, error) {

	tlsConfig, err := config.Build()
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &tlsClient{httpClient: client}, nil
}

var _ TlsClient = (*tlsClient)(nil)

type tlsClient struct {
	httpClient *http.Client
}

func (client *tlsClient) Do(req *http.Request) (*http.Response, error) {
	return client.httpClient.Do(req)
}
