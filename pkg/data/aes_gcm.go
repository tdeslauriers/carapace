package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func GenerateAesGcmKey() []byte {

	// AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

type Cryptor interface {
	EncyptServiceData(string) (string, error)
	DecyptServiceData(string) (string, error)
}

func NewServiceAesGcmKey(secret []byte) Cryptor {
	return &serviceAesGcmKey{
		secret: secret,
	}
}

var _ Cryptor = (*serviceAesGcmKey)(nil)

type serviceAesGcmKey struct {
	secret []byte // Env Var
}

func (key *serviceAesGcmKey) EncyptServiceData(plaintext string) (string, error) {

	if len(key.secret) != 32 {
		panic("AES key must be exactly 32 bytes long")
	}

	c, err := aes.NewCipher(key.secret)
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

func (key *serviceAesGcmKey) DecyptServiceData(ciphertext string) (string, error) {

	if len(key.secret) != 32 {
		panic("AES key must be exactly 32 bytes long")
	}

	c, err := aes.NewCipher(key.secret)
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
