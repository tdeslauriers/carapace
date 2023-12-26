package certs

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
	"os"
	"time"
)

func GenerateEcdsaCert(certName, org string, isCA bool) {

	// priave key (golang struct w/ objects and methods)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Panicf("failed to create %s private key: %v", certName, err)
	}

	// certTemplate
	certTemplate := buildTemplate(certName, org, isCA)

	// signing cert template
	var parentTemplate x509.Certificate
	var caKey *ecdsa.PrivateKey
	if isCA {
		parentTemplate = certTemplate
	} else {
		// load ca cert
		caCertPem, err := os.ReadFile("rootCA-cert.pem")
		if err != nil {
			log.Panic("unable to read rootCA-cert.pem file")
		}

		// load ca key
		caKeyPem, err := os.ReadFile("rootCA-key.pem")
		if err != nil {
			log.Panic("unable to read rootCA-key.pem file")
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
		caKey = caPriv
	}

	// create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &parentTemplate, &priv.PublicKey, priv)
	if err != nil {
		log.Panicf("failed to create DER for %s certificate: %v", certName, err)
	}

	// write cert to file
	certOut, err := os.Create(fmt.Sprintf("%s-cert.pem", certName))
	if err != nil {
		log.Panicf("failed to create file %s-cert.pem: %v", certName, err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	certOut.Close()

	// write private key out to file
	keyOut, err := os.Create(fmt.Sprintf("%s-key.pem", certName))
	if err != nil {
		log.Panicf("failed to create file %s-key.pem: %v", certName, err)
	}
	defer keyOut.Close()

	key, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Panicf("failed to marshal ecdsa private key for %s: %v", certName, err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})
	keyOut.Close()
}

func buildTemplate(certName, org string, isCA bool) x509.Certificate {

	// validity period:
	notBefore := time.Now()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Panicf("unable to generate serial number for %s certificate template: %v", certName, err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	// usage
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.NotAfter = notBefore.Add(365 * 24 * time.Hour)
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.NotAfter = notBefore.Add(90 * 24 * time.Hour)
		template.Subject.CommonName = "localhost"
	}

	return template
}
