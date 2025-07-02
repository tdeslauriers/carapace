package storage

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

const testImage = "2025/72be0c9b-6981-4a70-918b-715fba4280a3.jpg"

func TestGetSignedUrl(t *testing.T) {

	config, tls, err := setUp()
	if err != nil {
		t.Fatalf("failed to set up test: %v", err)
	}

	minio, err := New(*config, tls, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to create minio client: %v", err)
	}

	signedUrl, err := minio.GetSignedUrl(testImage)
	if err != nil {
		t.Fatalf("failed to get signed URL: %v", err)
	}
	if signedUrl == nil {
		t.Fatal("expected a signed URL, got nil")
	}
	if signedUrl.String() == "" {
		t.Fatal("expected a non-empty signed URL")
	}

	t.Logf("Signed URL: %s", signedUrl.String())
}

func setUp() (*Config, *tls.Config, error) {

	op := onepassword.NewCli()

	// get minio creds
	minioCreds, err := op.GetItem("pixie_minio_dev", "world_site")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get minio credentials: %v", err)
	}

	var accessKey, secretKey string
	for _, cred := range minioCreds.Fields {
		if cred.Label == "username" {
			accessKey = cred.Value

		}
		if cred.Label == "password" {
			secretKey = cred.Value

		}
	}

	config := Config{
		Url:       "localhost:9000",
		Bucket:    "gallerydev",
		AccessKey: accessKey,
		SecretKey: secretKey,
	}

	// get CA cert for minio endpoint
	ca, err := op.GetDocument("service_ca_dev_cert", "world_site")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get CA certificate: %v", err)
	}

	certPem, err := op.GetDocument("pixie_service_client_dev_cert", "world_site")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client certificate: %v", err)
	}
	keyPem, err := op.GetDocument("pixie_service_client_dev_key", "world_site")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client key: %v", err)
	}

	cert, err := tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse X509 key pair: %v", err)
	}

	// load CA certificates
	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get system cert pool: %v", err)
	}
	if ok := systemCertPool.AppendCertsFromPEM(ca); !ok {
		return nil, nil, fmt.Errorf("failed to append additional ca cert to system cert pool")
	}
	// create tls config with CA cert
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            systemCertPool,
		InsecureSkipVerify: false,
	}

	return &config, tlsConfig, nil
}
