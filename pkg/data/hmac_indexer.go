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

func NewIndexer(secret []byte) (Indexer, error) {

	if len(secret) < 32 {
		return nil, fmt.Errorf("hmac secret must be at least 32 bytes, got %d", len(secret))
	}

	return &hmacIndexer{secret: secret}, nil
}

var _ Indexer = (*hmacIndexer)(nil)

type hmacIndexer struct {
	secret []byte
}

func (i *hmacIndexer) ObtainBlindIndex(s string) (string, error) {

	h := hmac.New(sha256.New, i.secret)
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil)), nil
}
