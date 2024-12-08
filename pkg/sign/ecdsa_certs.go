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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertRole int

const (
	CA CertRole = iota
	Server
	Client
)

type CertFields struct {
	CertName     string
	Organisation []string
	CommonName   string // org + signature algo, leaf: domain
	San          []string
	SanIps       []net.IP
	Role         CertRole
	CaCertName   string
}

func (fields *CertFields) GenerateEcdsaCert() {

	// priave key (golang struct w/ objects and methods)
	certPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Panicf("failed to create %s private key: %v", fields.CertName, err)
	}

	// certTemplate
	certTemplate := fields.BuildTemplate()

	// signing cert template
	var parentTemplate x509.Certificate
	var signingPriv *ecdsa.PrivateKey
	if fields.Role == CA {
		// CA is self-signed
		parentTemplate = certTemplate
		signingPriv = certPriv
	} else {
		// load ca cert
		caCertPem, err := os.ReadFile(fmt.Sprintf("%s-cert.pem", fields.CaCertName))
		if err != nil {
			log.Panicf("unable to read %s-cert.pem file", fields.CaCertName)
		}

		// load ca key
		caKeyPem, err := os.ReadFile(fmt.Sprintf("%s-key.pem", fields.CaCertName))
		if err != nil {
			log.Panicf("unable to read %s-key.pem file", fields.CaCertName)
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
	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &parentTemplate, &certPriv.PublicKey, signingPriv)
	if err != nil {
		log.Panicf("failed to create DER for %s certificate: %v", fields.CertName, err)
	}

	// get current directory
	dir, err := os.Getwd()
	if err != nil {
		log.Panicf("failed to get current directory: %v", err)
	}

	// create an directory to store the certs
	now := time.Now()
	outputDir := fmt.Sprintf("backup_%s_%d_%d_%d", fields.CertName, now.Year(), now.Month(), now.Day())
	fullPath := filepath.Join(dir, outputDir)

	if err := os.MkdirAll(fullPath, os.ModePerm); err != nil {
		log.Panicf("failed to create directory %s: %v", fullPath, err)
	}

	// write cert to file
	certPath := filepath.Join(fullPath, fmt.Sprintf("%d_%d_%d_%s_cert.pem", now.Year(), now.Month(), now.Day(), fields.CertName))
	certOut, err := os.Create(certPath)
	if err != nil {
		log.Panicf("failed to create file %s-cert.pem: %v", fields.CertName, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	certOut.Close()

	// write private key out to file
	keyPath := filepath.Join(fullPath, fmt.Sprintf("%d_%d_%d_%s_key.pem", now.Year(), now.Month(), now.Day(), fields.CertName))
	keyOut, err := os.Create(keyPath)
	if err != nil {
		log.Panicf("failed to create file %s-key.pem: %v", fields.CertName, err)
	}
	defer keyOut.Close()

	key, err := x509.MarshalECPrivateKey(certPriv)
	if err != nil {
		log.Panicf("failed to marshal ecdsa private key for %s: %v", fields.CertName, err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})
	keyOut.Close()
}

func (fields *CertFields) BuildTemplate() x509.Certificate {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Panicf("unable to generate serial number for %s certificate template: %v", fields.CertName, err)
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

	return template
}
