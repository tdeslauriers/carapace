package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
)

// =============================================================================
// Test PKI helpers
//
// Real TLS tests need real certificates. Rather than embedding static PEM files
// (which expire and need rotation), we generate an in-memory CA + server cert +
// client cert at test time using ECDSA P-256 keys. Each cert is valid for one
// hour, which is more than enough for any test run.
//
// The trust chain is intentionally simple:
//
//   test-ca  ──signs──>  server cert  (serverAuth EKU, SAN: localhost/127.0.0.1)
//   test-ca  ──signs──>  client cert  (clientAuth EKU)
//
// Both the client and server Pki structs get the same CA so they can verify
// each other.
// =============================================================================

type testPKI struct {
	caPEM         []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// newTestPKI generates a complete test PKI with a self-signed CA, a server
// certificate, and a client certificate, all signed by that CA.
func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	// CA key + self-signed certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Server certificate — SANs cover both "localhost" and 127.0.0.1
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}

	// Client certificate — clientAuth EKU lets mTLS servers verify it
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	return &testPKI{
		caPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		serverCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		serverKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
		clientCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		clientKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}),
	}
}

// serverPki returns a Pki whose CaFiles list is used by the server in mTLS mode
// to verify incoming client certificates.
func (p *testPKI) serverPki() *Pki {
	return &Pki{
		CertFile: base64.StdEncoding.EncodeToString(p.serverCertPEM),
		KeyFile:  base64.StdEncoding.EncodeToString(p.serverKeyPEM),
		CaFiles:  []string{base64.StdEncoding.EncodeToString(p.caPEM)},
	}
}

// clientPki returns a Pki whose CaFiles list is used by the client to verify
// the server certificate, and whose CertFile/KeyFile are presented during mTLS.
func (p *testPKI) clientPki() *Pki {
	return &Pki{
		CertFile: base64.StdEncoding.EncodeToString(p.clientCertPEM),
		KeyFile:  base64.StdEncoding.EncodeToString(p.clientKeyPEM),
		CaFiles:  []string{base64.StdEncoding.EncodeToString(p.caPEM)},
	}
}

// startTLSTestServer starts a minimal HTTPS test server on a kernel-assigned
// port using tls.Listen directly (no httptest, no fixed port, no TOCTOU).
// It returns the base URL ("https://127.0.0.1:PORT") and registers a cleanup
// to shut the server down when the test ends.
//
// Using tls.Listen instead of httptest.NewTLSServer lets us inject our own
// tls.Config — including mTLS client CA pools — without httptest overwriting
// the certificate.
func startTLSTestServer(t *testing.T, tlsConfig *tls.Config, handler http.Handler) string {
	t.Helper()

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(l) //nolint:errcheck — Serve returns ErrServerClosed on cleanup
	t.Cleanup(func() { srv.Close() })

	return "https://" + l.Addr().String()
}

// =============================================================================
// Unit tests — Build()
//
// These exercise the config builders with no network traffic. They verify that
// valid PKI data produces the right tls.Config fields, and that invalid inputs
// (bad base64, garbage PEM) are rejected cleanly.
// =============================================================================

func TestTlsClientConfig_Build(t *testing.T) {
	pki := newTestPKI(t)

	tests := []struct {
		name    string
		pki     *Pki
		wantErr bool
	}{
		{
			name:    "valid",
			pki:     pki.clientPki(),
			wantErr: false,
		},
		{
			name: "invalid_cert_not_base64",
			pki: &Pki{
				CertFile: "!!!not-base64",
				KeyFile:  base64.StdEncoding.EncodeToString(pki.clientKeyPEM),
				CaFiles:  []string{base64.StdEncoding.EncodeToString(pki.caPEM)},
			},
			wantErr: true,
		},
		{
			name: "invalid_key_not_base64",
			pki: &Pki{
				CertFile: base64.StdEncoding.EncodeToString(pki.clientCertPEM),
				KeyFile:  "!!!not-base64",
				CaFiles:  []string{base64.StdEncoding.EncodeToString(pki.caPEM)},
			},
			wantErr: true,
		},
		{
			name: "invalid_ca_not_base64",
			pki: &Pki{
				CertFile: base64.StdEncoding.EncodeToString(pki.clientCertPEM),
				KeyFile:  base64.StdEncoding.EncodeToString(pki.clientKeyPEM),
				CaFiles:  []string{"!!!not-base64"},
			},
			wantErr: true,
		},
		{
			name: "invalid_ca_not_pem",
			pki: &Pki{
				CertFile: base64.StdEncoding.EncodeToString(pki.clientCertPEM),
				KeyFile:  base64.StdEncoding.EncodeToString(pki.clientKeyPEM),
				CaFiles:  []string{base64.StdEncoding.EncodeToString([]byte("garbage"))},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTlsClientConfig(tt.pki).Build()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.MinVersion != tls.VersionTLS13 {
				t.Errorf("MinVersion: got %d, want TLS 1.3", got.MinVersion)
			}
			if len(got.Certificates) != 1 {
				t.Errorf("Certificates: got %d, want 1", len(got.Certificates))
			}
			if got.RootCAs == nil {
				t.Error("RootCAs: expected non-nil pool")
			}
		})
	}
}

func TestTlsServerConfig_Build(t *testing.T) {
	pki := newTestPKI(t)

	tests := []struct {
		name    string
		tlsType config.ServerTls
		pki     *Pki
		wantErr bool
		check   func(t *testing.T, got *tls.Config)
	}{
		{
			name:    "standard_tls",
			tlsType: config.StandardTls,
			pki:     pki.serverPki(),
			check: func(t *testing.T, got *tls.Config) {
				if got.ClientAuth != tls.NoClientCert {
					t.Errorf("ClientAuth: got %v, want NoClientCert", got.ClientAuth)
				}
				if got.ClientCAs != nil {
					t.Error("ClientCAs: expected nil for standard TLS")
				}
			},
		},
		{
			name:    "mutual_tls",
			tlsType: config.MutualTls,
			pki:     pki.serverPki(),
			check: func(t *testing.T, got *tls.Config) {
				if got.ClientAuth != tls.RequireAndVerifyClientCert {
					t.Errorf("ClientAuth: got %v, want RequireAndVerifyClientCert", got.ClientAuth)
				}
				if got.ClientCAs == nil {
					t.Error("ClientCAs: expected non-nil pool for mTLS")
				}
				if got.MinVersion != tls.VersionTLS13 {
					t.Errorf("MinVersion: got %d, want TLS 1.3", got.MinVersion)
				}
			},
		},
		{
			name:    "invalid_tls_type",
			tlsType: config.ServerTls("bogus"),
			pki:     pki.serverPki(),
			wantErr: true,
		},
		{
			name:    "invalid_cert_not_pem",
			tlsType: config.StandardTls,
			pki: &Pki{
				CertFile: base64.StdEncoding.EncodeToString([]byte("not-a-cert")),
				KeyFile:  base64.StdEncoding.EncodeToString(pki.serverKeyPEM),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTlsServerConfig(tt.tlsType, tt.pki).Build()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// =============================================================================
// Unit tests — transport defaults and option overrides
//
// Because the test file is in package connect (same package as the production
// code), it can access unexported fields directly. This lets us assert the
// exact duration values baked into the http.Transport without making a network
// call.
// =============================================================================

func TestNewTlsClient_DefaultTimeouts(t *testing.T) {
	pki := newTestPKI(t)

	client, err := NewTlsClient(NewTlsClientConfig(pki.clientPki()))
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	c := client.(*tlsClient)
	tr := c.httpClient.Transport.(*http.Transport)

	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout: got %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout: got %v, want 30s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout: got %v, want 90s", tr.IdleConnTimeout)
	}
}

func TestNewTlsClient_OptionOverridesDefault(t *testing.T) {
	pki := newTestPKI(t)

	client, err := NewTlsClient(
		NewTlsClientConfig(pki.clientPki()),
		WithResponseHeaderTimeout(60*time.Second),
		WithIdleConnTimeout(30*time.Second),
	)
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	c := client.(*tlsClient)
	tr := c.httpClient.Transport.(*http.Transport)

	if tr.ResponseHeaderTimeout != 60*time.Second {
		t.Errorf("ResponseHeaderTimeout: got %v, want 60s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout: got %v, want 30s", tr.IdleConnTimeout)
	}
	// unset options must still use defaults
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout: got %v, want 10s (default)", tr.TLSHandshakeTimeout)
	}
}

// =============================================================================
// Integration tests — real TLS handshakes over TCP
//
// startTLSTestServer binds a real socket so the handshake exercises the full
// crypto/tls stack. No mocking, no httptest certificate substitution.
// =============================================================================

func TestTlsClient_StandardTLS(t *testing.T) {
	pki := newTestPKI(t)

	serverTLSCfg, err := NewTlsServerConfig(config.StandardTls, pki.serverPki()).Build()
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}

	url := startTLSTestServer(t, serverTLSCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	client, err := NewTlsClient(NewTlsClientConfig(pki.clientPki()))
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestTlsClient_MutualTLS(t *testing.T) {
	pki := newTestPKI(t)

	serverTLSCfg, err := NewTlsServerConfig(config.MutualTls, pki.serverPki()).Build()
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}

	url := startTLSTestServer(t, serverTLSCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	client, err := NewTlsClient(NewTlsClientConfig(pki.clientPki()))
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

// TestTlsClient_MutualTLS_RejectsUntrustedClientCert confirms the mTLS server
// rejects a client certificate signed by a CA it does not know. The client
// still trusts the server (it has the correct server CA), so the only failure
// is the server rejecting the unknown client cert during the handshake.
func TestTlsClient_MutualTLS_RejectsUntrustedClientCert(t *testing.T) {
	pki := newTestPKI(t)
	unknownPKI := newTestPKI(t) // separate CA — server has never seen it

	serverTLSCfg, err := NewTlsServerConfig(config.MutualTls, pki.serverPki()).Build()
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}

	url := startTLSTestServer(t, serverTLSCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Client presents a cert from unknownPKI but still trusts the server's CA
	untrustedClientPki := &Pki{
		CertFile: base64.StdEncoding.EncodeToString(unknownPKI.clientCertPEM),
		KeyFile:  base64.StdEncoding.EncodeToString(unknownPKI.clientKeyPEM),
		CaFiles:  []string{base64.StdEncoding.EncodeToString(pki.caPEM)},
	}

	client, err := NewTlsClient(NewTlsClientConfig(untrustedClientPki))
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected TLS handshake error for untrusted client cert, got nil")
	}
}

// =============================================================================
// Integration test — tlsServer.Initialize + graceful shutdown
//
// This is the only test that exercises our actual tlsServer.Initialize()
// implementation. The other integration tests use startTLSTestServer (a raw
// tls.Listen helper) because they focus on the client code path. Here we need
// a real server started by our code so we can verify context-driven shutdown.
//
// Port selection uses net.Listen(":0") to let the OS assign a free port, then
// closes that listener before passing the address to NewTlsServer. There is a
// small TOCTOU window, but it is acceptable in a test context.
// =============================================================================

func TestTlsServer_Initialize_Shutdown(t *testing.T) {
	pki := newTestPKI(t)

	serverTLSCfg, err := NewTlsServerConfig(config.StandardTls, pki.serverPki()).Build()
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}

	// Grab a free port from the OS, then release it for our server to bind
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := fmt.Sprintf(":%d", l.Addr().(*net.TCPAddr).Port)
	l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewTlsServer(addr, mux, serverTLSCfg)
	initDone := make(chan error, 1)
	go func() { initDone <- srv.Initialize(ctx) }()

	// Poll with raw TCP dials until the server is accepting connections.
	// A raw TCP dial is sufficient — we just need to know the port is open
	// before making an HTTPS request.
	serverAddr := "127.0.0.1" + addr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", serverAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	client, err := NewTlsClient(NewTlsClientConfig(pki.clientPki()))
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+serverAddr, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}

	// Cancel the context and verify Initialize returns cleanly within 3s
	cancel()
	select {
	case err := <-initDone:
		if err != nil {
			t.Errorf("Initialize returned unexpected error after shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not shut down within 3 seconds after context cancel")
	}
}

// =============================================================================
// Timeout test — ResponseHeaderTimeout
//
// A server handler that sleeps 500ms is paired with a client configured for a
// 50ms ResponseHeaderTimeout. The client must return an error before the
// handler wakes up.
// =============================================================================

func TestTlsClient_ResponseHeaderTimeout(t *testing.T) {
	pki := newTestPKI(t)

	serverTLSCfg, err := NewTlsServerConfig(config.StandardTls, pki.serverPki()).Build()
	if err != nil {
		t.Fatalf("build server TLS config: %v", err)
	}

	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	url := startTLSTestServer(t, serverTLSCfg, slowHandler)

	client, err := NewTlsClient(
		NewTlsClientConfig(pki.clientPki()),
		WithResponseHeaderTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewTlsClient: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout in error message, got: %v", err)
	}
}
