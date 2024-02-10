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

type HmacIndexer struct {
	Secret []byte
}

func NewHmacIndexer(secret []byte) *HmacIndexer {
	return &HmacIndexer{
		Secret: secret,
	}
}

func (i *HmacIndexer) ObtainBlindIndex(s string) (string, error) {

	h := hmac.New(sha256.New, i.Secret)
	if _, err := h.Write([]byte(s)); err != nil {
		return "", fmt.Errorf("unable to hmac/hash text to blind index: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
