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
// Supports both PKCS#8 ("PRIVATE KEY") and SEC 1 ("EC PRIVATE KEY") PEM block types.
func ParsePrivateEcdsaCert(privateKey string) (*ecdsa.PrivateKey, error) {

	if privateKey == "" {
		return nil, fmt.Errorf("private key string provided is empty")
	}

	privateKeyPem, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa private key from base64: %w", err)
	}

	block, _ := pem.Decode(privateKeyPem)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not an ECDSA key")
		}
		return ecKey, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// ParsePublicEcdsaCert is a helper function that parses a public ecdsa cert in pem format from
// a base64 encoded string, for example, a kubernetes secret value.
func ParsePublicEcdsaCert(publicKey string) (*ecdsa.PublicKey, error) {

	if publicKey == "" {
		return nil, fmt.Errorf("public key string provided is empty")
	}

	publicKeyPem, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa public key from base64: %w", err)
	}

	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from public key")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key block to generic public key: %w", err)
	}

	ecdsaPublicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("value provided is not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}
