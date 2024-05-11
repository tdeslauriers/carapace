package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
)

const TestPrivateKey, TestPublicKey string = "TEST_PRIVATE_KEY", "TEST_PUBLIC_KEY"

func TestGenSigningKey(t *testing.T) {

	// test run
	priv, pub := GenerateEcdsaSigningKey()
	t.Logf("priv: %s\n\npub: %s", priv, pub)
	os.Setenv(TestPrivateKey, priv)
	os.Setenv(TestPublicKey, pub)

	privPem, _ := base64.StdEncoding.DecodeString(os.Getenv(TestPrivateKey))
	privBlock, _ := pem.Decode(privPem)

	privateKey, _ := x509.ParseECPrivateKey(privBlock.Bytes)

	pubPem, _ := base64.StdEncoding.DecodeString(os.Getenv(TestPublicKey))
	pubBlock, _ := pem.Decode(pubPem)

	genericPublicKey, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Log("Not an ECDSA public key")
	}

	plaintext := "Atomic Dog..."
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, []byte(plaintext))

	if !ecdsa.Verify(publicKey, []byte(plaintext), r, s) {
		t.Log("could not verify signed msg with pub key.")
	}
}
