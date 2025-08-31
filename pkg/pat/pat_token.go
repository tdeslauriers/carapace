package pat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PatToken is an interface that defines methods for working with Personal Access Tokens (PATs).
type PatTokener interface {

	// Generate generates a new 64 byte random secret byte-slice, a base64 url encoded string representation,
	// and an error if any.
	Generate() ([]byte, string, error)

	// ObtainIndex takes a PAT token byte slice and returns a hashed blind index of the token using HMAC SHA-256
	// with the interfaces provided secret/pepper.  It returns the blind index as a hex,
	// lowercase string and an error if any.
	ObtainIndex(token []byte) (string, error)
}

// newPatToken creates a new PatToken object with the provided secret/pepper byte-slice.
func NewPatTokener(secret []byte) PatTokener {
	return &patTokener{
		pepper: secret,
	}
}

var _ PatTokener = (*patTokener)(nil)

// patTokener is the concrete implementation of the PatToken interface.
type patTokener struct {
	// secret used for hashing, sometimes called the pepper, it is used to hash the token before
	// storing it in a persistent store.
	// It should be a securely generated random byte-slice of at least 32 bytes.
	pepper []byte
}

// Generate is the concerte implementation of the interface method which
// generates a new 64 byte random secret byte-slice, a base64 url encoded string representation,
// and an error if any.
func (p *patTokener) Generate() ([]byte, string, error) {

	// generate a new 64 byte random secret
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("failed to generate random bytes for PAT token: %v", err)
	}

	// encode the byte slice to a base64 string
	secretString := base64.StdEncoding.EncodeToString(raw)

	return raw, secretString, nil
}

// ObtainIndex is the concrete implementation of the interface method which
// takes a PAT token byte slice and returns a hashed blind index of the token using HMAC SHA-256
// with the interfaces provided secret/pepper.  It returns the blind index as a hex,
// lowercase string and an error if any.
func (p *patTokener) ObtainIndex(token []byte) (string, error) {

	// return the blind index of the token
	return p.obtainIndex(token)
}

// obtainIndex is a helper method that creates a blind index of the provided token using HMAC SHA-256
// with the patTokener's pepper/secret.  It returns the blind index as a hex,
// lowercase string and an error if any.
func (p *patTokener) obtainIndex(token []byte) (string, error) {

	// validate input is not empty
	if len(token) == 0 {
		return "", fmt.Errorf("cannot obtain blind index of empty token")
	}

	h := hmac.New(sha256.New, p.pepper)
	if _, err := h.Write(token); err != nil {
		return "", fmt.Errorf("failed to hmac/hash PAT token to blind index: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashAndCompare takes in a PAT token byte-slice and a hashed blind index string,
// hashes the token using HMAC SHA-256 with the provided secret/pepper,
// and compares the resulting blind index with the provided blind index.
// It returns true if they match, false otherwise, and an error if any.
func (p *patTokener) HashAndCompare(token []byte, blindIndex string) (bool, error) {

	// validate token is not empty
	if len(token) == 0 {
		return false, fmt.Errorf("cannot hash and compare empty token")
	}

	// validate blind index is not empty
	if blindIndex == "" {
		return false, fmt.Errorf("cannot hash and compare to empty blind index")
	}

	hashedIndex, err := p.obtainIndex(token)
	if err != nil {
		return false, fmt.Errorf("failed to hash provided PAT token for comparision: %v", err)
	}

	return hmac.Equal([]byte(hashedIndex), []byte(blindIndex)), nil
}
