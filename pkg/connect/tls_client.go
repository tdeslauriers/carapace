package connect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"
)

// TlsClientConfig is an interface that defines the method to build a tls.Config for a client.
type TlsClientConfig interface {

	// Build constructs a tls.Config based on the implementation of the TlsClientConfig interface.
	Build() (*tls.Config, error)
}

// NewTlsClientConfig is a constructor function that creates a new instance of TlsClientConfig
// using the provided Pki configuration.
func NewTlsClientConfig(pki *Pki) TlsClientConfig {

	return &tlsClientConfig{
		Pki: pki,
	}

}

// tlsClientConfig is a concrete implementation of the TlsClientConfig interface that holds the Pki configuration.
type tlsClientConfig struct {
	Pki *Pki
}

var _ TlsClientConfig = (*tlsClientConfig)(nil)

// Build constructs a tls.Config for the client based on the Pki configuration. It decodes the certificate and key,
// loads the system certificate pool, and appends any additional CA certificates provided in the Pki configuration.
func (cfg *tlsClientConfig) Build() (*tls.Config, error) {
	certPem, err := base64.StdEncoding.DecodeString(cfg.Pki.CertFile)
	if err != nil {
		return nil, err
	}

	keyPem, err := base64.StdEncoding.DecodeString(cfg.Pki.KeyFile)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %v", err)
	}

	// cloned so never mutates the platform-provided pool
	rootCAs := systemCertPool.Clone()

	for _, v := range cfg.Pki.CaFiles {
		ca, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode ca cert: %v", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("failed to append internal ca cert to root ca pool")
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// TlsClient is an interface that defines the method to perform an HTTP request using TLS.
type TlsClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// TlsClientOption is a function type that defines the signature for options that can be applied to a TlsClient.
type TlsClientOption func(*tlsClient)

// WithDialTimeout is an option function that sets the dial timeout for the TlsClient.
func WithDialTimeout(d time.Duration) TlsClientOption {
	return func(c *tlsClient) { c.dialTimeout = d }
}

// WithTLSHandshakeTimeout is an option function that sets the TLS handshake timeout for the TlsClient.
func WithTLSHandshakeTimeout(d time.Duration) TlsClientOption {
	return func(c *tlsClient) { c.tlsHandshakeTimeout = d }
}

// WithResponseHeaderTimeout is an option function that sets the response header timeout for the TlsClient.
func WithResponseHeaderTimeout(d time.Duration) TlsClientOption {
	return func(c *tlsClient) { c.responseHeaderTimeout = d }
}

// WithIdleConnTimeout is an option function that sets the idle connection timeout for the TlsClient.
func WithIdleConnTimeout(d time.Duration) TlsClientOption {
	return func(c *tlsClient) { c.idleConnTimeout = d }
}

// NewTlsClient is a constructor function that creates a new instance of TlsClient
// using the provided TlsClientConfig and options.
func NewTlsClient(config TlsClientConfig, opts ...TlsClientOption) (TlsClient, error) {

	tlsConfig, err := config.Build()
	if err != nil {
		return nil, err
	}

	c := &tlsClient{}
	for _, opt := range opts {
		opt(c)
	}

	dialTimeout := c.dialTimeout
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}

	tlsHandshakeTimeout := c.tlsHandshakeTimeout
	if tlsHandshakeTimeout == 0 {
		tlsHandshakeTimeout = 10 * time.Second
	}

	responseHeaderTimeout := c.responseHeaderTimeout
	if responseHeaderTimeout == 0 {
		responseHeaderTimeout = 30 * time.Second
	}

	idleConnTimeout := c.idleConnTimeout
	if idleConnTimeout == 0 {
		idleConnTimeout = 90 * time.Second
	}

	c.httpClient = &http.Client{

		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			IdleConnTimeout:       idleConnTimeout,
		},
	}

	return c, nil
}

var _ TlsClient = (*tlsClient)(nil)

// tlsClient is a concrete implementation of the TlsClient interface. It contains an http.Client that is configured
// with the TLS settings and timeouts specified in the options.
type tlsClient struct {
	httpClient            *http.Client
	dialTimeout           time.Duration
	tlsHandshakeTimeout   time.Duration
	responseHeaderTimeout time.Duration
	idleConnTimeout       time.Duration
}

// Do performs an HTTP request using the configured http.Client and returns the response or an error.
func (c *tlsClient) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
