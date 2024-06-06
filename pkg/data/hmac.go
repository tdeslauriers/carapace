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
		Secret: secret,
	}
}

var _ Indexer = (*hmacIndexer)(nil)

type hmacIndexer struct {
	Secret []byte
}

func (i *hmacIndexer) ObtainBlindIndex(s string) (string, error) {

	h := hmac.New(sha256.New, i.Secret)
	if _, err := h.Write([]byte(s)); err != nil {
		return "", fmt.Errorf("unable to hmac/hash text to blind index: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
