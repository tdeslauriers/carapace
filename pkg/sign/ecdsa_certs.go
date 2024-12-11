package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
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
	GenerateEcdsaCert() error

	// BuildTemplate builds a certificate template for use in certificate generation
	BuildTemplate() (*x509.Certificate, error)
}

// NewCertBuilder is a factory function that returns a new CertBuilder interface
func NewCertBuilder(d CertData) CertBuilder {
	return &certBuilder{
		fields: d,
		op:     onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentSign)),
	}
}

var _ CertBuilder = (*certBuilder)(nil)

// certBuilder is the concrete implementation of the CertBuilder interface
type certBuilder struct {
	fields CertData
	op     onepassword.Service

	logger *slog.Logger
}

func (cb *certBuilder) GenerateEcdsaCert() error {

	// priave key (golang struct w/ objects and methods)
	certPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Panicf("failed to create %s private key: %v", cb.fields.CertName, err)
	}

	// certTemplate
	certTemplate, err := cb.BuildTemplate()
	if err != nil {
		return err
	}

	// signing cert template
	var parentTemplate x509.Certificate
	var signingPriv *ecdsa.PrivateKey
	if cb.fields.Role == CA {
		// CA is self-signed
		parentTemplate = *certTemplate
		signingPriv = certPriv
	} else {

		// fetch the CA cert from 1password
		caCertPem, err := cb.op.GetDocument(fmt.Sprintf("%s_cert", cb.fields.CaCertName), "Shared")
		if err != nil {
			log.Panicf("failed to get %s_cert.pem from 1password: %v", cb.fields.CaCertName, err)
		}

		// fetch ca key from 1password
		caKeyPem, err := cb.op.GetDocument(fmt.Sprintf("%s_key", cb.fields.CaCertName), "Shared")
		if err != nil {
			log.Panicf("failed to get %s_key.pem from 1password: %v", cb.fields.CaCertName, err)
		}

		// decode pems to der
		caCertBlock, _ := pem.Decode(caCertPem)

		if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
			log.Panic("failed to decode ca cert pem")
		}

		caKeyBlock, _ := pem.Decode(caKeyPem)
		if caKeyBlock == nil || caKeyBlock.Type != "EC PRIVATE KEY" {
			log.Panic("failed to decode ca key pem")
		}

		// parse root ca values
		caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)
		caPriv, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)

		parentTemplate = *caCert
		signingPriv = caPriv
	}

	// create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, &parentTemplate, &certPriv.PublicKey, signingPriv)
	if err != nil {
		log.Panicf("failed to create DER for %s certificate: %v", cb.fields.CertName, err)
	}

	// get current directory
	dir, err := os.Getwd()
	if err != nil {
		log.Panicf("failed to get current directory: %v", err)
	}

	// create an directory to store the certs
	now := time.Now()
	outputDir := fmt.Sprintf("backup_%s_%d_%d_%d", cb.fields.CertName, now.Year(), now.Month(), now.Day())
	fullPath := filepath.Join(dir, outputDir)

	if err := os.MkdirAll(fullPath, os.ModePerm); err != nil {
		log.Panicf("failed to create directory %s: %v", fullPath, err)
	}

	// write cert to file
	certPath := filepath.Join(fullPath, fmt.Sprintf("%s_cert.pem", cb.fields.CertName))
	certOut, err := os.Create(certPath)
	if err != nil {
		log.Panicf("failed to create file %s-cert.pem: %v", cb.fields.CertName, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	certOut.Close()

	// write private key out to file
	keyPath := filepath.Join(fullPath, fmt.Sprintf("%s_key.pem", cb.fields.CertName))
	keyOut, err := os.Create(keyPath)
	if err != nil {
		log.Panicf("failed to create file %s-key.pem: %v", cb.fields.CertName, err)
	}
	defer keyOut.Close()

	key, err := x509.MarshalECPrivateKey(certPriv)
	if err != nil {
		log.Panicf("failed to marshal ecdsa private key for %s: %v", cb.fields.CertName, err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})

	keyOut.Close()

	// upsert certificate into 1password
	if err := cb.op.UpsertDocument(certPath, fmt.Sprintf("%s_%s", cb.fields.CertName, "cert"), "Shared", []string{"Family Site"}); err != nil {
		log.Panicf("failed to upsert %s certificate into 1password: %v", fmt.Sprintf("%s_%s", cb.fields.CertName, "key"), err)
	}

	// upsert private key into 1password
	if err := cb.op.UpsertDocument(keyPath, fmt.Sprintf("%s_%s", cb.fields.CertName, "key"), "Shared", []string{"Family Site"}); err != nil {
		log.Panicf("failed to upsert %s private key into 1password: %v", fmt.Sprintf("%s_%s", cb.fields.CertName, "key"), err)
	}

	return nil
}

func (cb *certBuilder) BuildTemplate() (*x509.Certificate, error) {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("unable to generate serial number for %s certificate template: %v", cb.fields.CertName, err)
	}

	// validity period:
	notBefore := time.Now().UTC()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: cb.fields.Organisation,
			CommonName:   cb.fields.CommonName,
		},
		NotBefore:             notBefore,
		BasicConstraintsValid: true,
		DNSNames:              cb.fields.San,
		IPAddresses:           cb.fields.SanIps,
	}

	switch cb.fields.Role {
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
