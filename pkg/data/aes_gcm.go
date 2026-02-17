package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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

	// Encrypt encrypts a single field and sends the ciphertext or error to the ciphertext channel
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

// Encrypt is a helper function that encrypts a sensitive field.
func (key *serviceAesGcmKey) EncryptField(
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

	// encrypt the plaintext
	ciphertext, err := key.encryptServiceData([]byte(plaintext))
	if err != nil {
		errCh <- err
		return
	}

	// send the ciphertext to the channel
	ciphertextCh <- ciphertext
}

// EncryptServiceData is the concrete implementation of the Cryptor interface function
// Note: takes in a byte array (for versatility) and returns a base64 encoded string
func (key *serviceAesGcmKey) EncryptServiceData(clear []byte) (string, error) {

	return key.encryptServiceData(clear)
}

// EncryptServiceData is the concrete implementation of the Cryptor interface function
// Note: takes in a byte array (for versatility) and returns a base64 encoded string
func (key *serviceAesGcmKey) encryptServiceData(clear []byte) (string, error) {

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

// DecryptField decrypts a single field and sends the plaintext or error to the respective channel
func (key *serviceAesGcmKey) DecryptField(
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

	// decrypt the ciphertext
	plaintext, err := key.decryptServiceData(ciphertext)
	if err != nil {
		errCh <- err
		return
	}

	// send the plaintext to the channel
	plaintextCh <- string(plaintext)
}

// DecryptServiceData is the concrete implementation of the Cryptor interface function
func (key *serviceAesGcmKey) DecryptServiceData(ciphertext string) ([]byte, error) {

	return key.decryptServiceData(ciphertext)
}

// decryptServiceData is the concrete implementation of the Cryptor interface function
func (key *serviceAesGcmKey) decryptServiceData(ciphertext string) ([]byte, error) {

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
