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

	// priave key (golang struct w/ objects and methods)
	certPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to create %s private key: %v", fields.CertName, err)
	}

	cb.logger.Info(fmt.Sprintf("successfully generated %s certificate/key pair", fields.CertName))

	// certTemplate
	certTemplate, err := cb.BuildTemplate(fields)
	if err != nil {
		return err
	}

	cb.logger.Info(fmt.Sprintf("successfully built %s template for certifcate/key pair", fields.CertName))

	// signing cert template
	var parentTemplate *x509.Certificate
	var signingPriv *ecdsa.PrivateKey
	if fields.Role == CA {
		// CA is self-signed
		parentTemplate = certTemplate
		signingPriv = certPriv
	} else {

		// fetch the CA cert from 1password

		caCertPem, err := cb.op.GetDocument(fmt.Sprintf("%s_cert", fields.CaCertName), fields.OpVault)
		if err != nil {
			return fmt.Errorf("failed to get %s_cert.pem from 1password: %v", fields.CaCertName, err)
		}

		// fetch ca key from 1password
		caKeyPem, err := cb.op.GetDocument(fmt.Sprintf("%s_key", fields.CaCertName), fields.OpVault)
		if err != nil {
			return fmt.Errorf("failed to get %s_key.pem from 1password: %v", fields.CaCertName, err)
		}

		// decode pems to der
		caCertBlock, _ := pem.Decode(caCertPem)

		if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode ca cert pem")
		}

		caKeyBlock, _ := pem.Decode(caKeyPem)
		if caKeyBlock == nil || caKeyBlock.Type != "EC PRIVATE KEY" {
			return fmt.Errorf("failed to decode ca key pem")
		}

		// parse root ca values
		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse %s certificate: %v", fields.CaCertName, err)

		}
		caPriv, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse %s private key: %v", fields.CaCertName, err)
		}

		parentTemplate = caCert
		signingPriv = caPriv
	}

	// create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, parentTemplate, &certPriv.PublicKey, signingPriv)
	if err != nil {
		return fmt.Errorf("failed to create DER for %s certificate: %v", fields.CertName, err)
	}

	// get current directory
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %v", err)
	}

	// create an directory to store the certs
	now := time.Now()
	outputDir := fmt.Sprintf("backup_%s_%d_%d_%d", fields.CertName, now.Year(), now.Month(), now.Day())
	fullPath := filepath.Join(dir, outputDir)

	if err := os.MkdirAll(fullPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", fullPath, err)
	}

	// write cert to file
	certPath := filepath.Join(fullPath, fmt.Sprintf("%s_cert.pem", fields.CertName))
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s-cert.pem: %v", fields.CertName, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	certOut.Close()

	// write private key out to file
	keyPath := filepath.Join(fullPath, fmt.Sprintf("%s_key.pem", fields.CertName))
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s-key.pem: %v", fields.CertName, err)
	}
	defer keyOut.Close()

	key, err := x509.MarshalECPrivateKey(certPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal ecdsa private key for %s: %v", fields.CertName, err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})

	keyOut.Close()

	cb.logger.Info(fmt.Sprintf("successfully saved %s certificate/key pair to back up file", fields.CertName))

	// upsert certificate into 1password
	if err := cb.op.UpsertDocument(certPath, fmt.Sprintf("%s_%s", fields.CertName, "cert"), fields.OpVault, fields.OpTags); err != nil {
		return fmt.Errorf("failed to upsert %s certificate into 1password: %v", fmt.Sprintf("%s_%s", fields.CertName, "key"), err)
	}

	// upsert private key into 1password
	if err := cb.op.UpsertDocument(keyPath, fmt.Sprintf("%s_%s", fields.CertName, "key"), fields.OpVault, fields.OpTags); err != nil {
		return fmt.Errorf("failed to upsert %s private key into 1password: %v", fmt.Sprintf("%s_%s", fields.CertName, "key"), err)
	}

	cb.logger.Info(fmt.Sprintf("successfully upserted %s certificate/key pair into 1password", fields.CertName))

	return nil
}

func (cb *certBuilder) BuildTemplate(fields CertFields) (*x509.Certificate, error) {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("unable to generate serial number for %s certificate template: %v", fields.CertName, err)
	}

	// validity period:
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
		template.ExtKeyUsage = nil // not needed for CA
		template.NotAfter = notBefore.Add(365 * 24 * time.Hour)
		template.IsCA = true
	case Server:
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.NotAfter = notBefore.Add(90 * 24 * time.Hour)
		template.IsCA = false
	default: // client case
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.NotAfter = notBefore.Add(90 * 24 * time.Hour)
		template.IsCA = false
	}

	return &template, nil
}
