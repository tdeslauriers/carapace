package standard

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
)

type MutalTlsClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient *http.Client
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

type ClientPkiConfigurer struct {
	Config *PkiCerts
}

func (pki *ClientPkiConfigurer) NewMtlsClient() (*Client, error) {

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

	// ca(s) of servers
	serverCaPool := x509.NewCertPool()
	for _, v := range pki.Config.CaFile {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		serverCaPool.AppendCertsFromPEM(ca)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      serverCaPool,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &Client{httpClient: httpClient}, nil
}
