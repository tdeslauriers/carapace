package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

func TestCertValidation(t *testing.T) {

	// set up
	var ca, leaf, org string = "rootCA", "server", "Rebel Alliance"
	GenerateEcdsaCert(ca, org, true)
	GenerateEcdsaCert(leaf, org, false)

	// read generated certs
	caCertPem, _ := os.ReadFile(fmt.Sprintf("%s-cert.pem", ca))
	caDer, _ := pem.Decode(caCertPem)
	caCert, _ := x509.ParseCertificate(caDer.Bytes)

	leafCertPem, _ := os.ReadFile(fmt.Sprintf("%s-cert.pem", leaf))
	leafDer, _ := pem.Decode(leafCertPem)
	leafCert, _ := x509.ParseCertificate(leafDer.Bytes)

	t.Log(leafCert.SignatureAlgorithm)

	// cert pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// verify server cert
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		t.Logf("failed to validate server cert: %v", err)
		t.Fail()
	}

	// clean up
	os.Remove(fmt.Sprintf("%s-cert.pem", ca))
	os.Remove(fmt.Sprintf("%s-key.pem", ca))
	os.Remove(fmt.Sprintf("%s-cert.pem", leaf))
	os.Remove(fmt.Sprintf("%s-key.pem", leaf))

}
