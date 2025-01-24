package sign

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ParsePrivateEcdsaCert is a helper function that parses a private ecdsa cert in pem format from
// a base64 encoded string, for example, a kubernetes secret value.
// Note: the *ecdsa.PrivateKey also includes the public key as a field.
func ParsePrivateEcdsaCert(privateKey string) (*ecdsa.PrivateKey, error) {

	if privateKey == "" {
		return nil, fmt.Errorf("private key string provided is empty")
	}

	PrivateKeyPem, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa private key from base64: %v", err)
	}

	PrivatePemBlock, _ := pem.Decode(PrivateKeyPem)
	ecdsaPrivateKey, err := x509.ParseECPrivateKey(PrivatePemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse priv Block to private key: %v", err)
	}

	return ecdsaPrivateKey, nil
}

// ParsePublicEcdsaCert is a helper function that parses a public ecdsa cert in pem formatt from
// a base64 encoded string, for example, a kubernetes secret value.
func ParsePublicEcdsaCert(publicKey string) (*ecdsa.PublicKey, error) {

	if publicKey == "" {
		return nil, fmt.Errorf("public key string provided is empty")
	}

	publicKeyPem, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa public key from base64: %v", err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPem)
	GenericPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key block to generic public key: %v", err)
	}
	ecdsaPublicKey, ok := GenericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("value provide is not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}
