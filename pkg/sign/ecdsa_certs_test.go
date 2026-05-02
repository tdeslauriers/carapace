package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// mockOpService is a test double for onepassword.Service shared across sign package test files.
type mockOpService struct {
	getDocumentFn    func(title, vault string) ([]byte, error)
	upsertDocumentFn func(path, title, vault string, tags []string) error
	getItemFn        func(title, vault string) (*onepassword.Item, error)
	upsertItemFn     func(item *onepassword.Item) error
	capturedItem     *onepassword.Item
}

func (m *mockOpService) GetDocument(title, vault string) ([]byte, error) {
	if m.getDocumentFn != nil {
		return m.getDocumentFn(title, vault)
	}
	return nil, nil
}

func (m *mockOpService) UpsertDocument(path, title, vault string, tags []string) error {
	if m.upsertDocumentFn != nil {
		return m.upsertDocumentFn(path, title, vault, tags)
	}
	return nil
}

func (m *mockOpService) GetItem(title, vault string) (*onepassword.Item, error) {
	if m.getItemFn != nil {
		return m.getItemFn(title, vault)
	}
	return nil, nil
}

func (m *mockOpService) UpsertItem(item *onepassword.Item) error {
	m.capturedItem = item
	if m.upsertItemFn != nil {
		return m.upsertItemFn(item)
	}
	return nil
}

// encodePrivKey marshals a private key to the requested PEM type and returns the
// base64-encoded result, mirroring the shape stored in 1Password.
func encodePrivKey(t *testing.T, key *ecdsa.PrivateKey, pemType string) string {
	t.Helper()
	var (
		der []byte
		err error
	)
	switch pemType {
	case "PRIVATE KEY":
		der, err = x509.MarshalPKCS8PrivateKey(key)
	case "EC PRIVATE KEY":
		der, err = x509.MarshalECPrivateKey(key)
	default:
		t.Fatalf("unsupported pemType: %s", pemType)
	}
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
}

// makeTestCA generates an in-memory self-signed CA certificate and private key PEM.
// keyFormat must be "PRIVATE KEY" (PKCS#8) or "EC PRIVATE KEY" (SEC 1).
func makeTestCA(t *testing.T, keyFormat string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("makeTestCA: generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("makeTestCA: serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("makeTestCA: create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	var keyBytes []byte
	switch keyFormat {
	case "PRIVATE KEY":
		keyBytes, err = x509.MarshalPKCS8PrivateKey(priv)
	case "EC PRIVATE KEY":
		keyBytes, err = x509.MarshalECPrivateKey(priv)
	default:
		t.Fatalf("makeTestCA: unknown key format: %q", keyFormat)
	}
	if err != nil {
		t.Fatalf("makeTestCA: marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: keyFormat, Bytes: keyBytes})
	return certPEM, keyPEM
}

// makeRSAPKCS8KeyPEM returns a PKCS#8-wrapped RSA private key PEM for testing the
// "CA key is not an ECDSA key" error path.
func makeRSAPKCS8KeyPEM(t *testing.T) []byte {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("makeRSAPKCS8KeyPEM: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("makeRSAPKCS8KeyPEM: marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
}

func TestBuildTemplate(t *testing.T) {
	cb := &certBuilder{logger: slog.Default()}

	sanIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	tests := []struct {
		name   string
		fields CertFields
		check  func(t *testing.T, tmpl *x509.Certificate, fields CertFields)
	}{
		{
			name: "ca_role_key_usage_and_validity",
			fields: CertFields{
				CertName:     "test-ca",
				Organisation: []string{"Test Org"},
				CommonName:   "Test CA",
				Role:         CA,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if !tmpl.IsCA {
					t.Error("IsCA: want true")
				}
				if tmpl.KeyUsage&x509.KeyUsageCertSign == 0 {
					t.Error("KeyUsageCertSign not set")
				}
				if tmpl.KeyUsage&x509.KeyUsageCRLSign == 0 {
					t.Error("KeyUsageCRLSign not set")
				}
				if len(tmpl.ExtKeyUsage) != 0 {
					t.Errorf("ExtKeyUsage: want nil, got %v", tmpl.ExtKeyUsage)
				}
				if !tmpl.BasicConstraintsValid {
					t.Error("BasicConstraintsValid: want true")
				}
				want := 365 * 24 * time.Hour
				got := tmpl.NotAfter.Sub(tmpl.NotBefore)
				if got < want-time.Minute || got > want+time.Minute {
					t.Errorf("validity period: want ~365d, got %v", got)
				}
			},
		},
		{
			name: "server_role_key_usage_and_validity",
			fields: CertFields{
				CertName:     "test-server",
				Organisation: []string{"Test Org"},
				CommonName:   "server.example.com",
				Role:         Server,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if tmpl.IsCA {
					t.Error("IsCA: want false")
				}
				if tmpl.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					t.Error("KeyUsageDigitalSignature not set")
				}
				if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
					t.Errorf("ExtKeyUsage: want [ServerAuth], got %v", tmpl.ExtKeyUsage)
				}
				want := 90 * 24 * time.Hour
				got := tmpl.NotAfter.Sub(tmpl.NotBefore)
				if got < want-time.Minute || got > want+time.Minute {
					t.Errorf("validity period: want ~90d, got %v", got)
				}
			},
		},
		{
			name: "client_role_key_usage_and_validity",
			fields: CertFields{
				CertName:     "test-client",
				Organisation: []string{"Test Org"},
				CommonName:   "client.example.com",
				Role:         Client,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if tmpl.IsCA {
					t.Error("IsCA: want false")
				}
				if tmpl.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					t.Error("KeyUsageDigitalSignature not set")
				}
				if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
					t.Errorf("ExtKeyUsage: want [ClientAuth], got %v", tmpl.ExtKeyUsage)
				}
				want := 90 * 24 * time.Hour
				got := tmpl.NotAfter.Sub(tmpl.NotBefore)
				if got < want-time.Minute || got > want+time.Minute {
					t.Errorf("validity period: want ~90d, got %v", got)
				}
			},
		},
		{
			// Any unrecognized CertRole falls through to the default (client) branch.
			name: "unknown_role_defaults_to_client_behavior",
			fields: CertFields{
				CertName: "test-unknown",
				Role:     CertRole(99),
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if tmpl.IsCA {
					t.Error("IsCA: want false for default case")
				}
				if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
					t.Errorf("ExtKeyUsage: want [ClientAuth] for default case, got %v", tmpl.ExtKeyUsage)
				}
			},
		},
		{
			name: "serial_number_is_non_nil_and_non_negative",
			fields: CertFields{
				CertName: "test-serial",
				Role:     CA,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if tmpl.SerialNumber == nil {
					t.Fatal("SerialNumber: want non-nil")
				}
				if tmpl.SerialNumber.Sign() < 0 {
					t.Error("SerialNumber: want non-negative")
				}
			},
		},
		{
			name: "serial_numbers_are_unique_across_calls",
			fields: CertFields{
				CertName: "test-serial-unique",
				Role:     CA,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, f CertFields) {
				other, err := cb.BuildTemplate(f)
				if err != nil {
					t.Fatalf("second BuildTemplate call failed: %v", err)
				}
				if tmpl.SerialNumber.Cmp(other.SerialNumber) == 0 {
					t.Error("two BuildTemplate calls produced the same serial number")
				}
			},
		},
		{
			name: "notbefore_is_utc_and_recent",
			fields: CertFields{
				CertName: "test-time",
				Role:     Server,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if tmpl.NotBefore.Location() != time.UTC {
					t.Errorf("NotBefore location: want UTC, got %v", tmpl.NotBefore.Location())
				}
				delta := time.Since(tmpl.NotBefore)
				if delta < 0 || delta > 2*time.Second {
					t.Errorf("NotBefore is not recent: delta=%v", delta)
				}
			},
		},
		{
			name: "subject_organisation_and_common_name",
			fields: CertFields{
				CertName:     "test-subject",
				Organisation: []string{"Rebel Alliance", "Resistance"},
				CommonName:   "rebel.example.com",
				Role:         Server,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, f CertFields) {
				if len(tmpl.Subject.Organization) != len(f.Organisation) {
					t.Fatalf("Organization length: want %d, got %d", len(f.Organisation), len(tmpl.Subject.Organization))
				}
				for i, o := range f.Organisation {
					if tmpl.Subject.Organization[i] != o {
						t.Errorf("Organization[%d]: want %q, got %q", i, o, tmpl.Subject.Organization[i])
					}
				}
				if tmpl.Subject.CommonName != f.CommonName {
					t.Errorf("CommonName: want %q, got %q", f.CommonName, tmpl.Subject.CommonName)
				}
			},
		},
		{
			name: "san_dns_names_and_ip_addresses",
			fields: CertFields{
				CertName: "test-san",
				Role:     Server,
				San:      []string{"a.example.com", "b.example.com"},
				SanIps:   sanIPs,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, f CertFields) {
				if len(tmpl.DNSNames) != len(f.San) {
					t.Fatalf("DNSNames length: want %d, got %d", len(f.San), len(tmpl.DNSNames))
				}
				for i, s := range f.San {
					if tmpl.DNSNames[i] != s {
						t.Errorf("DNSNames[%d]: want %q, got %q", i, s, tmpl.DNSNames[i])
					}
				}
				if len(tmpl.IPAddresses) != len(f.SanIps) {
					t.Fatalf("IPAddresses length: want %d, got %d", len(f.SanIps), len(tmpl.IPAddresses))
				}
				for i, ip := range f.SanIps {
					if !tmpl.IPAddresses[i].Equal(ip) {
						t.Errorf("IPAddresses[%d]: want %v, got %v", i, ip, tmpl.IPAddresses[i])
					}
				}
			},
		},
		{
			name: "basic_constraints_valid_is_always_set",
			fields: CertFields{
				CertName: "test-constraints",
				Role:     Client,
			},
			check: func(t *testing.T, tmpl *x509.Certificate, _ CertFields) {
				if !tmpl.BasicConstraintsValid {
					t.Error("BasicConstraintsValid: want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := cb.BuildTemplate(tt.fields)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, tmpl, tt.fields)
			}
		})
	}
}

func TestGenerateEcdsaCert(t *testing.T) {
	caCertPKCS8, caKeyPKCS8 := makeTestCA(t, "PRIVATE KEY")
	caCertSEC1, caKeySEC1 := makeTestCA(t, "EC PRIVATE KEY")
	rsaKeyPEM := makeRSAPKCS8KeyPEM(t)

	invalidPEM := []byte("this is not a PEM block")
	wrongTypePEM := pem.EncodeToMemory(&pem.Block{Type: "GARBAGE", Bytes: []byte("not a cert")})

	baseFields := CertFields{
		Organisation: []string{"Test Org"},
		CommonName:   "test.example.com",
		San:          []string{"test.example.com"},
		CaCertName:   "test-ca",
		OpVault:      "test-vault",
		OpTags:       []string{"test-tag"},
	}

	newFields := func(certName string, role CertRole) CertFields {
		f := baseFields
		f.CertName = certName
		f.Role = role
		return f
	}

	// docsByTitle routes GetDocument responses based on the title suffix so that
	// cert and key fetches can return different payloads from a single mock function.
	docsByTitle := func(certDoc, keyDoc []byte, certErr, keyErr error) func(string, string) ([]byte, error) {
		return func(title, vault string) ([]byte, error) {
			if strings.HasSuffix(title, "_cert") {
				return certDoc, certErr
			}
			return keyDoc, keyErr
		}
	}

	tests := []struct {
		name      string
		fields    CertFields
		setupMock func() *mockOpService
		wantErr   bool
		errSubstr string
	}{
		{
			name:   "ca_cert_success",
			fields: newFields("gen-ca", CA),
			setupMock: func() *mockOpService {
				return &mockOpService{} // UpsertDocument defaults to success
			},
		},
		{
			name:   "server_cert_pkcs8_ca_key_success",
			fields: newFields("gen-srv-pkcs8", Server),
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, caKeyPKCS8, nil, nil),
				}
			},
		},
		{
			// SEC 1 CA keys stored before the PKCS#8 migration must still sign leaf certs.
			name:   "server_cert_sec1_ca_key_backward_compat",
			fields: newFields("gen-srv-sec1", Server),
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertSEC1, caKeySEC1, nil, nil),
				}
			},
		},
		{
			name:   "client_cert_success",
			fields: newFields("gen-cli", Client),
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, caKeyPKCS8, nil, nil),
				}
			},
		},
		{
			name:      "get_ca_cert_document_fails",
			fields:    newFields("gen-err-get-cert", Server),
			wantErr:   true,
			errSubstr: "failed to get",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(nil, nil, errors.New("1password unavailable"), nil),
				}
			},
		},
		{
			name:      "get_ca_key_document_fails",
			fields:    newFields("gen-err-get-key", Server),
			wantErr:   true,
			errSubstr: "failed to get",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, nil, nil, errors.New("1password unavailable")),
				}
			},
		},
		{
			name:      "invalid_ca_cert_pem",
			fields:    newFields("gen-err-bad-cert", Server),
			wantErr:   true,
			errSubstr: "failed to decode ca cert pem",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(invalidPEM, caKeyPKCS8, nil, nil),
				}
			},
		},
		{
			name:      "ca_cert_wrong_pem_type",
			fields:    newFields("gen-err-cert-type", Server),
			wantErr:   true,
			errSubstr: "failed to decode ca cert pem",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(wrongTypePEM, caKeyPKCS8, nil, nil),
				}
			},
		},
		{
			name:      "invalid_ca_key_pem",
			fields:    newFields("gen-err-bad-key", Server),
			wantErr:   true,
			errSubstr: "failed to decode ca key pem",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, invalidPEM, nil, nil),
				}
			},
		},
		{
			name:      "ca_key_unsupported_pem_type",
			fields:    newFields("gen-err-key-type", Server),
			wantErr:   true,
			errSubstr: "unsupported PEM block type",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, wrongTypePEM, nil, nil),
				}
			},
		},
		{
			// A PKCS#8-wrapped RSA key triggers the ECDSA type-assertion failure.
			name:      "ca_key_pkcs8_rsa_not_ecdsa",
			fields:    newFields("gen-err-rsa", Server),
			wantErr:   true,
			errSubstr: "not an ECDSA key",
			setupMock: func() *mockOpService {
				return &mockOpService{
					getDocumentFn: docsByTitle(caCertPKCS8, rsaKeyPEM, nil, nil),
				}
			},
		},
		{
			name:      "upsert_cert_document_fails",
			fields:    newFields("gen-err-upsert-cert", CA),
			wantErr:   true,
			errSubstr: "failed to upsert",
			setupMock: func() *mockOpService {
				return &mockOpService{
					upsertDocumentFn: func(path, title, vault string, tags []string) error {
						return errors.New("upsert failed")
					},
				}
			},
		},
		{
			// The cert upsert succeeds; the key upsert fails.
			name:      "upsert_key_document_fails",
			fields:    newFields("gen-err-upsert-key", CA),
			wantErr:   true,
			errSubstr: "failed to upsert",
			setupMock: func() *mockOpService {
				return &mockOpService{
					upsertDocumentFn: func(path, title, vault string, tags []string) error {
						if strings.HasSuffix(title, "_cert") {
							return nil
						}
						return errors.New("key upsert failed")
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register cleanup for any backup directory the function may create.
			dir, _ := os.Getwd()
			now := time.Now()
			backupDir := filepath.Join(dir, fmt.Sprintf("backup_%s_%d_%d_%d",
				tt.fields.CertName, now.Year(), now.Month(), now.Day()))
			t.Cleanup(func() { os.RemoveAll(backupDir) })

			cb := &certBuilder{
				op:     tt.setupMock(),
				logger: slog.Default(),
			}

			err := cb.GenerateEcdsaCert(tt.fields)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParsePrivateEcdsaCert(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pkcs8Base64 := encodePrivKey(t, privKey, "PRIVATE KEY")
	sec1Base64 := encodePrivKey(t, privKey, "EC PRIVATE KEY")

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "pkcs8_format",
			input:   pkcs8Base64,
			wantErr: false,
		},
		{
			name:    "sec1_format",
			input:   sec1Base64,
			wantErr: false,
		},
		{
			name:      "empty_string",
			input:     "",
			wantErr:   true,
			errSubstr: "empty",
		},
		{
			name:      "invalid_base64",
			input:     "not-valid-base64!!!",
			wantErr:   true,
			errSubstr: "failed to decode",
		},
		{
			name:      "invalid_pem",
			input:     base64.StdEncoding.EncodeToString([]byte("not a PEM block")),
			wantErr:   true,
			errSubstr: "failed to decode PEM block",
		},
		{
			name:      "unsupported_pem_type",
			input:     base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")})),
			wantErr:   true,
			errSubstr: "unsupported PEM block type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateEcdsaCert(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key, got nil")
			}
		})
	}
}

func TestParsePublicEcdsaCert(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_public_key",
			input:   pubBase64,
			wantErr: false,
		},
		{
			name:      "empty_string",
			input:     "",
			wantErr:   true,
			errSubstr: "empty",
		},
		{
			name:      "invalid_base64",
			input:     "not-valid-base64!!!",
			wantErr:   true,
			errSubstr: "failed to decode",
		},
		{
			name:      "invalid_pem",
			input:     base64.StdEncoding.EncodeToString([]byte("not a PEM block")),
			wantErr:   true,
			errSubstr: "failed to decode PEM block",
		},
		{
			// Passing a private key PEM where a public key is expected should
			// be rejected with a clear type error, not a cryptic ASN.1 parse failure.
			name:      "wrong_pem_type_private_key_passed",
			input:     encodePrivKey(t, privKey, "PRIVATE KEY"),
			wantErr:   true,
			errSubstr: "unsupported PEM block type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePublicEcdsaCert(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key, got nil")
			}
		})
	}
}
