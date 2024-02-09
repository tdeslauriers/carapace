package data

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type Indexer interface {
	ObtainBlindIndex(string) (string, error)
}

type HmacIndexer struct {
	Secret string
}

func (i *HmacIndexer) ObtainBlindIndex(s string) (string, error) {

	key, err := base64.StdEncoding.DecodeString(i.Secret)
	if err != nil {
		return "", fmt.Errorf("unable to decode base 64 encoded hmac key for hmac: %v", err)
	}

	h := hmac.New(sha256.New, key)
	if _, err := h.Write([]byte(s)); err != nil {
		return "", fmt.Errorf("unable to hmac/hash text to blind index: %v", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
