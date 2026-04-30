package data

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// hmacSecretLabel is the 1Password field label that holds the HMAC secret.
const hmacSecretLabel = "secret"

// IndexBuilder is an interface for building HMAC blind indexes when needed
type IndexBuilder interface {

	// BuildHmacIndex builds a HMAC blind index for a given value and secret name (+ the vault where the secret is stored)
	BuildHmacIndex(toIndex, secretName, vault string) (string, error)
}

// NewIndexBuilder is a factory function that returns a new IndexBuilder interface and
// an underlying concrete implementation.
func NewIndexBuilder() IndexBuilder {
	return &indexBuilder{
		op: onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentHmac)).
			With(slog.String(util.PackageKey, util.PackageStorage)).
			With(slog.String(util.FrameworkKey, util.FrameworkCarapace)),
	}
}

var _ IndexBuilder = (*indexBuilder)(nil)

// hmacIndexBuilder is the concrete implementation of the IndexBuilder interface
type indexBuilder struct {
	op onepassword.Service

	logger *slog.Logger
}

// BuildHmacIndex is the concrete implementation of the interface method which
// builds a HMAC blind index for a given secret name.
func (ib *indexBuilder) BuildHmacIndex(toIndex, secretName, vault string) (string, error) {

	if toIndex == "" {
		return "", fmt.Errorf("value to index cannot be empty")
	}

	if secretName == "" {
		return "", fmt.Errorf("secret name cannot be empty")
	}

	// get secret item record from 1password
	opItem, err := ib.op.GetItem(secretName, vault)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve item %s from 1password vault %s: %w", secretName, vault, err)
	}

	// get the secret from the item fields
	var itemSecret string
	for _, field := range opItem.Fields {
		if field.Label == hmacSecretLabel {
			itemSecret = field.Value
			break
		}
	}

	if itemSecret == "" {
		return "", fmt.Errorf("failed to find field %q in 1password item %s in vault %s", hmacSecretLabel, secretName, vault)
	}

	// decode
	hmacSecret, err := base64.StdEncoding.DecodeString(itemSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decode hmac secret: %w", err)
	}
	defer clear(hmacSecret)

	// instantiate the indexer
	indexer, err := NewIndexer(hmacSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create hmac indexer: %w", err)
	}

	// get index value
	blindIndex, err := indexer.ObtainBlindIndex(toIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build hmac blind index: %w", err)
	}

	return blindIndex, nil
}
