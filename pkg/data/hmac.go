package data

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Indexer interface {
	ObtainBlindIndex(string) (string, error)
}

func NewIndexer(secret []byte) Indexer {
	return &hmacIndexer{
		secret: secret,
	}
}

var _ Indexer = (*hmacIndexer)(nil)

type hmacIndexer struct {
	secret []byte
}

func (i *hmacIndexer) ObtainBlindIndex(s string) (string, error) {

	h := hmac.New(sha256.New, i.secret)
	if _, err := h.Write([]byte(s)); err != nil {
		return "", fmt.Errorf("failed to hmac/hash text to blind index: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

