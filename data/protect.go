package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

type Cryptor interface {
	encyptServiceData(string) (string, error)
	decyptServiceData(string) (string, error)
}

func GenerateAesGcmKey() []byte {

	// AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

type ServiceAesGcmKey struct {
	Name string
	Env  string // Env Var
}

func (key *ServiceAesGcmKey) encyptServiceData(plaintext string) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(os.Getenv(key.Env))
	if err != nil {
		return "", err
	}
	if len(keyBytes) != 32 {
		panic("AES key must be exactly 32 bytes long")
	}

	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (key *ServiceAesGcmKey) decyptServiceData(ciphertext string) (string, error) {

	// get service key from env var
	keyEnv := os.Getenv(key.Env)

	keyBytes, err := base64.StdEncoding.DecodeString(keyEnv)
	if err != nil {
		return "", err
	}
	if len(keyBytes) != 32 {
		panic("AES key must be exactly 32 bytes long")
	}

	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	// decode ciphertext to bytes
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherBytes := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
