package data

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// IndexBuilder is an interface for building HMAC blind indexes when needed
type IndexBuilder interface {

	// BuildHMACIndex builds a HMAC blind index for a given value and secret name (+ the vault where the secret is stored)
	BuildHmacIndex(toIndex, secretName, vault string) (string, error)
}

// New IndexBuilder is a factory function that returns a new IndexBuilder interface and
// an underlying concrete implementation.
func NewIndexBuilder() IndexBuilder {
	return &indexBuilder{
		op: onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentHmac)).
			With(slog.String(util.PackageKey, util.PackageStorage)).
			With(slog.String(util.ServiceKey, util.ServiceCarapace)),
	}
}

var _ IndexBuilder = (*indexBuilder)(nil)

// hmacIndexBuilder is the concrete implementation of the IndexBuilder interface
type indexBuilder struct {
	op onepassword.Service

	logger *slog.Logger
}

// BuildHmacIndex is the concrete implementaiton of the interface method which
//
//	builds a HMAC blind index for a given secret name.
func (ib *indexBuilder) BuildHmacIndex(toIndex, secretName, vault string) (string, error) {

	// make sure the secret name is not empty
	if secretName == "" {
		return "", fmt.Errorf("secret name cannot be empty")
	}

	// retrieve the secret from 1password
	opItem, err := ib.op.GetItem(secretName, vault)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve item %s from 1password vault %s: %v", secretName, vault, err)
	}

	// loop through the item's fields to find the hmac secret
	// fields name actually is "secret"
	var itemSecret string
	for _, field := range opItem.Fields {
		if field.Label == "secret" {
			itemSecret = field.Value
			break
		}
	}

	// make sure found the secret --> should never fail here
	if itemSecret == "" {
		return "", fmt.Errorf("failed to find field 'secret' in 1password item %s in vault %s", secretName, vault)
	}

	// indexer
	hmacSecret, err := base64.StdEncoding.DecodeString(itemSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decode hmac secret: %v", err)
	}

	// this is the indexer used by app services, of which this function is effectively a wrapper
	indexer := NewIndexer(hmacSecret)
	blindIndex, err := indexer.ObtainBlindIndex(toIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build hmac blind index: %v", err)
	}

	return blindIndex, nil
}
