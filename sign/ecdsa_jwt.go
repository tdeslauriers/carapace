package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
)

func GenerateEcdsaSigningKey() (private, public string) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	pulicKey := &privateKey.PublicKey

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	privPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		})

	pubBytes, err := x509.MarshalPKIXPublicKey(pulicKey)
	if err != nil {
		log.Fatalf("Unable to marshal public key: %v", err)
	}
	pubPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

	privBase64 := base64.StdEncoding.EncodeToString(privPem)
	pubBase64 := base64.StdEncoding.EncodeToString(pubPem)

	return privBase64, pubBase64
}
