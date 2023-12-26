package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestCaGen(t *testing.T) {

	GenerateEcdsaCert("rootCA", "des Lauriers", true)
}

func TestGenServCert(t *testing.T) {

	// load ca cert
	caCertPem, _ := os.ReadFile("rootCA-cert.pem")

	// load ca key
	caKeyPem, _ := os.ReadFile("rootCA-key.pem")

	// decode pems to der
	caCertBlock, _ := pem.Decode(caCertPem)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		t.Log("failed to decode ca cert pem")
	}

	caKeyBlock, _ := pem.Decode(caKeyPem)
	if caKeyBlock == nil || caKeyBlock.Type != "EC PRIVATE KEY" {
		t.Log("failed to decode ca key pem")
	}

	// parse root ca values
	caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)
	caKey, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)

	// generate server key
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// server template
	serverCertTemplate := buildTemplate("server", "des Lauriers", false)

	// sign with ca
	servCertDer, _ := x509.CreateCertificate(rand.Reader, &serverCertTemplate, caCert, &serverKey.PublicKey, caKey)

	// save server cert to file
	servCertOut, _ := os.Create("server-cert.pem")
	defer servCertOut.Close()

	pem.Encode(servCertOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: servCertDer,
	})
	servCertOut.Close()

	// save server key to file
	servKeyOut, _ := os.Create("server-key.pem")
	defer servKeyOut.Close()

	key, _ := x509.MarshalECPrivateKey(serverKey)

	pem.Encode(servKeyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})
	servKeyOut.Close()

}
