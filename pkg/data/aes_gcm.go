package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
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

	// EncryptField encrypts a single field and sends the ciphertext or error to the ciphertext channel
	EncryptField(
		fieldname string,
		plaintext string,
		ciphertextCh chan string,
		errCh chan error,
		wg *sync.WaitGroup,
	)

	// EncryptServiceData encrypts data and returns encrypted value as a base64 encoded string
	EncryptServiceData([]byte) (string, error)

	// DecryptField decrypts a single field and sends the plaintext or error to the plaintext channel
	DecryptField(
		fieldname string,
		ciphertext string,
		plaintextCh chan string,
		errCh chan error,
		wg *sync.WaitGroup,
	)

	// DecryptServiceData decrypts ciphertext (encrypted + encoded in base64) data to a clear byte array
	DecryptServiceData(string) ([]byte, error)
}

// NewServiceAesGcm returns a new Cryptor for encrypting and decrypting service data.
// The secret must be exactly 32 bytes (AES-256).
func NewServiceAesGcm(secret []byte) (Cryptor, error) {

	if len(secret) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(secret))
	}

	gcm, err := NewGcm(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate aes gcm AEAD: %v", err)
	}

	return &serviceAesGcm{gcm: gcm}, nil
}

var _ Cryptor = (*serviceAesGcm)(nil)

type serviceAesGcm struct {
	gcm cipher.AEAD
}

// NewGCM constructs the AES-GCM AEAD from the stored key.
func NewGcm(secret []byte) (cipher.AEAD, error) {

	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm, nil
}

// EncryptField encrypts a single field and sends the ciphertext or error to the respective channel.
func (s *serviceAesGcm) EncryptField(
	fieldname string,
	plaintext string,
	ciphertextCh chan string,
	errCh chan error,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	if plaintext == "" {
		errCh <- fmt.Errorf("failed to encrypt '%s' field because it is empty", fieldname)
		return
	}

	ciphertext, err := s.encryptServiceData([]byte(plaintext))
	if err != nil {
		errCh <- fmt.Errorf("failed to encrypt field '%s': %w", fieldname, err)
		return
	}

	ciphertextCh <- ciphertext
}

// EncryptServiceData is the concrete implementation of the Cryptor interface method.
// It takes a byte slice for versatility and returns a base64-encoded ciphertext string.
func (s *serviceAesGcm) EncryptServiceData(clear []byte) (string, error) {

	return s.encryptServiceData(clear)
}

func (s *serviceAesGcm) encryptServiceData(clear []byte) (string, error) {

	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// nonce is prepended to the ciphertext so it can be extracted on decryption
	encrypted := s.gcm.Seal(nonce, nonce, clear, nil)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptField decrypts a single field and sends the plaintext or error to the respective channel.
func (s *serviceAesGcm) DecryptField(
	fieldname string,
	ciphertext string,
	plaintextCh chan string,
	errCh chan error,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	if ciphertext == "" {
		errCh <- fmt.Errorf("failed to decrypt '%s' field because it is empty", fieldname)
		return
	}

	plaintext, err := s.decryptServiceData(ciphertext)
	if err != nil {
		errCh <- fmt.Errorf("failed to decrypt field '%s': %w", fieldname, err)
		return
	}

	plaintextCh <- string(plaintext)
}

// DecryptServiceData is the concrete implementation of the Cryptor interface method.
func (s *serviceAesGcm) DecryptServiceData(ciphertext string) ([]byte, error) {

	return s.decryptServiceData(ciphertext)
}

func (s *serviceAesGcm) decryptServiceData(ciphertext string) ([]byte, error) {

	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode ciphertext: %w", err)
	}

	nonceSize := s.gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, cipherBytes := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := s.gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: ciphertext may be tampered or corrupted: %w", err)
	}

	return decrypted, nil
}
