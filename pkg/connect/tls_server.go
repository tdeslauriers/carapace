package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
)

type TlsServerConfig interface {
	Build() (*tls.Config, error)
}

func NewTlsServerConfig(tlsType config.ServerTls, pki *Pki) TlsServerConfig {
	return &tlsServerConfig{
		Type: tlsType,
		Pki:  pki,
	}
}

type tlsServerConfig struct {
	Type config.ServerTls // standard or mutual
	Pki  *Pki
}

var _ TlsServerConfig = (*tlsServerConfig)(nil)

func (cfg *tlsServerConfig) Build() (*tls.Config, error) {

	certPem, err := base64.StdEncoding.DecodeString(cfg.Pki.CertFile)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode cert file: %v", err)
	}
	keyPem, err := base64.StdEncoding.DecodeString(cfg.Pki.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode key file: %v", err)
	}

	// public/private key pair
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("could not parse x509 key pair: %v", err)
	}

	switch cfg.Type {
	case config.StandardTls:
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	case config.MutualTls:
		// ca(s) of clients
		clientCaPool := x509.NewCertPool()
		for _, v := range cfg.Pki.CaFiles {
			ca, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			if ok := clientCaPool.AppendCertsFromPEM(ca); !ok {
				return nil, fmt.Errorf("failed to load client CA cert")
			}
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    clientCaPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}, nil
	default:
		return nil, fmt.Errorf("invalid TLS type")
	}
}

// TlsServer is an interface that represents a TLS server. It has a single method, Initialize, which
// starts the server and blocks until the context is cancelled or an error occurs.
type TlsServer interface {

	// Initialize starts the TLS server and blocks until the context is cancelled or an error occurs. It uses the
	// timeouts set on the tlsServer, or defaults if they were not set, to configure the http.Server.
	// It listens and serves TLS on the specified address and handler, and shuts down gracefully when the context is cancelled.
	Initialize(ctx context.Context) error
}

// TlsServerOption is a functional option for configuring the TLS server. It is a
// function that takes a pointer to a tlsServer and modifies it.
type TlsServerOption func(*tlsServer)

// WithReadHeaderTimeout sets the ReadHeaderTimeout field of the tlsServer. This is
// the amount of time allowed to read request headers.
func WithReadHeaderTimeout(d time.Duration) TlsServerOption {
	return func(s *tlsServer) { s.readHeaderTimeout = d }
}

// WithReadTimeout sets the ReadTimeout field of the tlsServer. This is the
// amount of time allowed to read the entire request, including the body.
func WithReadTimeout(d time.Duration) TlsServerOption {
	return func(s *tlsServer) { s.readTimeout = d }
}

// WithWriteTimeout sets the WriteTimeout field of the tlsServer. This is the
// amount of time allowed to write the response.
func WithWriteTimeout(d time.Duration) TlsServerOption {
	return func(s *tlsServer) { s.writeTimeout = d }
}

// WithIdleTimeout sets the IdleTimeout field of the tlsServer. This is the amount of time
// allowed for the server to wait for the next request when keep-alives are enabled.
func WithIdleTimeout(d time.Duration) TlsServerOption {
	return func(s *tlsServer) { s.idleTimeout = d }
}

// NewTlsServer creates a new TlsServer with the given address, handler, TLS configuration, and options.
// The server is not started until the Initialize method is called.
func NewTlsServer(addr string, mux *http.ServeMux, tlsConfig *tls.Config, opts ...TlsServerOption) TlsServer {

	s := &tlsServer{
		addr:      addr,
		mux:       mux,
		tlsConfig: tlsConfig,
	}

	// apply options if any
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// tlsServer is a concrete implementation of the TlsServer interface. It contains
// the address to listen on, the HTTP handler, the TLS configuration, and the various timeouts for the server.
// The Initialize method starts the server and blocks until the context is cancelled or an error occurs.
type tlsServer struct {
	addr              string
	mux               *http.ServeMux
	tlsConfig         *tls.Config
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
}

var _ TlsServer = (*tlsServer)(nil)

// Initialize starts the TLS server and blocks until the context is cancelled or an error occurs. It uses the
// timeouts set on the tlsServer, or defaults if they were not set, to configure the http.Server.
// It listens and serves TLS on the specified address and handler, and shuts down gracefully when the context is cancelled.
func (s *tlsServer) Initialize(ctx context.Context) error {

	// check if timeouts were set on initialization, if not set defaults
	readHeaderTimeout := s.readHeaderTimeout
	if readHeaderTimeout == 0 {
		readHeaderTimeout = 5 * time.Second
	}

	readTimeout := s.readTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}

	writeTimeout := s.writeTimeout
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}

	idleTimeout := s.idleTimeout
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}

	server := &http.Server{
		Addr:              s.addr,
		Handler:           s.mux,
		TLSConfig:         s.tlsConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}
