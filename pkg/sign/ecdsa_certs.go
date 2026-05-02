package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// CertBuilder is an interface which generates certificates
type CertBuilder interface {

	// GenerateEcdsaCert generates an ecdsa certificate and private key pair
	GenerateEcdsaCert(f CertFields) error

	// BuildTemplate builds a certificate template for use in certificate generation
	BuildTemplate(f CertFields) (*x509.Certificate, error)
}

// NewCertBuilder is a factory function that returns a new CertBuilder interface
func NewCertBuilder() CertBuilder {
	return &certBuilder{
		op: onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentCert)),
	}
}

var _ CertBuilder = (*certBuilder)(nil)

// certBuilder is the concrete implementation of the CertBuilder interface
type certBuilder struct {
	op onepassword.Service

	logger *slog.Logger
}

func (cb *certBuilder) GenerateEcdsaCert(fields CertFields) error {

	certPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to create %s private key: %w", fields.CertName, err)
	}

	cb.logger.Info("successfully generated certificate/key pair",
		slog.String("cert_name", fields.CertName))

	certTemplate, err := cb.BuildTemplate(fields)
	if err != nil {
		return err
	}

	cb.logger.Info("successfully built certificate template",
		slog.String("cert_name", fields.CertName))

	var parentTemplate *x509.Certificate
	var signingPriv *ecdsa.PrivateKey
	if fields.Role == CA {
		parentTemplate = certTemplate
		signingPriv = certPriv
	} else {

		caCertPem, err := cb.op.GetDocument(fmt.Sprintf("%s_cert", fields.CaCertName), fields.OpVault)
		if err != nil {
			return fmt.Errorf("failed to get %s_cert.pem from 1password: %w", fields.CaCertName, err)
		}

		caKeyPem, err := cb.op.GetDocument(fmt.Sprintf("%s_key", fields.CaCertName), fields.OpVault)
		if err != nil {
			return fmt.Errorf("failed to get %s_key.pem from 1password: %w", fields.CaCertName, err)
		}

		caCertBlock, _ := pem.Decode(caCertPem)
		if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode ca cert pem")
		}

		caKeyBlock, _ := pem.Decode(caKeyPem)
		if caKeyBlock == nil {
			return fmt.Errorf("failed to decode ca key pem")
		}

		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse %s certificate: %w", fields.CaCertName, err)
		}

		// Support both PKCS#8 ("PRIVATE KEY") and SEC 1 ("EC PRIVATE KEY") so that
		// existing CA keys stored before the PKCS#8 migration continue to work.
		var caPriv *ecdsa.PrivateKey
		switch caKeyBlock.Type {
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse %s private key: %w", fields.CaCertName, err)
			}
			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("%s private key is not an ECDSA key", fields.CaCertName)
			}
			caPriv = ecKey
		case "EC PRIVATE KEY":
			caPriv, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse %s private key: %w", fields.CaCertName, err)
			}
		default:
			return fmt.Errorf("unsupported PEM block type for %s private key: %s", fields.CaCertName, caKeyBlock.Type)
		}

		parentTemplate = caCert
		signingPriv = caPriv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, parentTemplate, &certPriv.PublicKey, signingPriv)
	if err != nil {
		return fmt.Errorf("failed to create DER for %s certificate: %w", fields.CertName, err)
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	now := time.Now()
	outputDir := fmt.Sprintf("backup_%s_%d_%d_%d", fields.CertName, now.Year(), now.Month(), now.Day())
	fullPath := filepath.Join(dir, outputDir)

	// 0700: backup directory contains private key material — owner access only.
	if err := os.MkdirAll(fullPath, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
	}

	certPath := filepath.Join(fullPath, fmt.Sprintf("%s_cert.pem", fields.CertName))
	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file %s_cert.pem: %w", fields.CertName, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write %s certificate to file: %w", fields.CertName, err)
	}

	if err := certOut.Close(); err != nil {
		return fmt.Errorf("failed to close %s certificate file: %w", fields.CertName, err)
	}

	keyPath := filepath.Join(fullPath, fmt.Sprintf("%s_key.pem", fields.CertName))
	// 0600: private key files must be readable by the owner only.
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file %s_key.pem: %w", fields.CertName, err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(certPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal ecdsa private key for %s: %w", fields.CertName, err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("failed to write %s private key to file: %w", fields.CertName, err)
	}

	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("failed to close %s private key file: %w", fields.CertName, err)
	}

	cb.logger.Info("successfully saved certificate/key pair to backup file",
		slog.String("cert_name", fields.CertName))

	if err := cb.op.UpsertDocument(certPath, fmt.Sprintf("%s_cert", fields.CertName), fields.OpVault, fields.OpTags); err != nil {
		return fmt.Errorf("failed to upsert %s certificate into 1password: %w", fields.CertName, err)
	}

	if err := cb.op.UpsertDocument(keyPath, fmt.Sprintf("%s_key", fields.CertName), fields.OpVault, fields.OpTags); err != nil {
		return fmt.Errorf("failed to upsert %s private key into 1password: %w", fields.CertName, err)
	}

	cb.logger.Info("successfully upserted certificate/key pair into 1password",
		slog.String("cert_name", fields.CertName))

	return nil
}

func (cb *certBuilder) BuildTemplate(fields CertFields) (*x509.Certificate, error) {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("unable to generate serial number for %s certificate template: %w", fields.CertName, err)
	}

	notBefore := time.Now().UTC()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: fields.Organisation,
			CommonName:   fields.CommonName,
		},
		NotBefore:             notBefore,
		BasicConstraintsValid: true,
		DNSNames:              fields.San,
		IPAddresses:           fields.SanIps,
	}

	switch fields.Role {
	case CA:
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = nil
		template.NotAfter = notBefore.Add(365 * 24 * time.Hour)
		template.IsCA = true
	case Server:
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.NotAfter = notBefore.Add(90 * 24 * time.Hour)
		template.IsCA = false
	default: // client
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.NotAfter = notBefore.Add(90 * 24 * time.Hour)
		template.IsCA = false
	}

	return &template, nil
}
