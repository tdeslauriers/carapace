package sign

import (
	"testing"
)

func TestCertValidation(t *testing.T) {

	// TODO: re-write test to use the new cert generation service

	// set up
	// ca := CertData{
	// 	CertName:     "db-ca",
	// 	Organisation: []string{"Rebel Alliance"},
	// 	CommonName:   "RebelAlliance ECDSA-SHA256",
	// 	Role:         CA,
	// }
	// ca.GenerateEcdsaCert()

	// leaf := CertData{
	// 	CertName:     "db-server",
	// 	Organisation: []string{"Rebel Alliance"},
	// 	CommonName:   "localhost",
	// 	San:          []string{"localhost"},
	// 	SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
	// 	Role:         Server,
	// 	CaCertName:   ca.CertName,
	// }
	// leaf.GenerateEcdsaCert()

	// client := CertData{
	// 	CertName:     "db-client",
	// 	Organisation: []string{"Rebel Alliance"},
	// 	CommonName:   "localhost",
	// 	San:          []string{"localhost"},
	// 	SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
	// 	Role:         Client,
	// 	CaCertName:   ca.CertName,
	// }
	// client.GenerateEcdsaCert()

	// // read generated certs
	// caCertPem, _ := os.ReadFile(fmt.Sprintf("%s-cert.pem", ca.CertName))
	// caDer, _ := pem.Decode(caCertPem)
	// caCert, _ := x509.ParseCertificate(caDer.Bytes)

	// leafCertPem, _ := os.ReadFile(fmt.Sprintf("%s-cert.pem", leaf.CertName))
	// leafDer, _ := pem.Decode(leafCertPem)
	// leafCert, _ := x509.ParseCertificate(leafDer.Bytes)

	// // cert pool
	// roots := x509.NewCertPool()
	// roots.AddCert(caCert)

	// // verify server cert
	// opts := x509.VerifyOptions{
	// 	Roots: roots,
	// }

	// if _, err := leafCert.Verify(opts); err != nil {
	// 	t.Logf("failed to validate server cert: %v", err)
	// 	t.Fail()
	// }

	// clean up
	// os.Remove(fmt.Sprintf("%s-cert.pem", ca.CertName))
	// os.Remove(fmt.Sprintf("%s-key.pem", ca.CertName))
	// os.Remove(fmt.Sprintf("%s-cert.pem", leaf.CertName))
	// os.Remove(fmt.Sprintf("%s-key.pem", leaf.CertName))

}
