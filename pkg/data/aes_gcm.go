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

// Cryptor is an interface for encrypting and decrypting service data
type Cryptor interface {

	// EncryptServiceData encrypts data and returns encrypted value as a base64 encoded string
	EncryptServiceData([]byte) (string, error)

	// DecryptServiceData decrypts ciphertext (encrypted + encoded in base64) data to a clear byte array
	DecryptServiceData(string) ([]byte, error)
}

// NewServiceAesGcmKey returns a new Cryptor interface for encrypting and decrypting service data
func NewServiceAesGcmKey(secret []byte) Cryptor {
	return &serviceAesGcmKey{
		secret: secret,
	}
}

var _ Cryptor = (*serviceAesGcmKey)(nil)

type serviceAesGcmKey struct {
	secret []byte // Env Var
}

func (key *serviceAesGcmKey) EncryptServiceData(clear []byte) (string, error) {

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

	// nonce is prepended to the encrypted value so it can be extracted on decryption
	encrypted := gcm.Seal(nonce, nonce, clear, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (key *serviceAesGcmKey) DecryptServiceData(ciphertext string) ([]byte, error) {

	if len(key.secret) != 32 {
		panic("AES key must be exactly 32 bytes long")
	}

	c, err := aes.NewCipher(key.secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// decode ciphertext to bytes
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, cipherBytes := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
