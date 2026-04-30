package data

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// SecretGenerator is an interface for generating a 32 byte keys for data operations like AES GCM encryption or blind index hashing
type SecretGenerator interface {

	// GenerateKey generates a random key of specificed byte length, encodes it to base64, and uploads it to 1password with tne name provided
	GenerateKey(name string, length int) error
}

func NewSecretGenerator(op onepassword.Service) SecretGenerator {
	return &secretGenerator{
		op: op,

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentSecretGen)),
	}
}

var _ SecretGenerator = (*secretGenerator)(nil)

type secretGenerator struct {
	op onepassword.Service

	logger *slog.Logger
}

// GenerateKey creates a cryptographcially random secretkey,
// encodes it to base 64 and upserts it into 1password
func (sg *secretGenerator) GenerateKey(name string, length int) error {

	// only allow key sizes that map to real cryptographic use cases:
	// 16 = AES-128, 32 = AES-256 / HMAC-SHA256, 64 = HMAC-SHA512
	switch length {
	case 16, 32, 64:
	default:
		return fmt.Errorf("length must be 16, 32, or 64 bytes, got %d", length)
	}

	// generate cryptographically random secret key of specified length
	secret := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return fmt.Errorf("failed to generate random secret: %w", err)
	}

	// encode key to base64
	encodedSecret := base64.StdEncoding.EncodeToString(secret)

	// upsert key to 1password
	item := &onepassword.Item{
		Title: name,
		Vault: onepassword.Vault{
			Name: util.OpVaultName,
		},
		Tags:     []string{util.OpTag0},
		Category: util.OpCategory,
		Fields: []onepassword.Field{
			{Label: "secret", Value: encodedSecret, Type: "CONCEALED"},
			{Label: "notesPlain", Value: "This secret is base64 encoded for use by service config", Type: "STRING", Purpose: "NOTES"},
		},
	}
	if err := sg.op.UpsertItem(item); err != nil {
		return err
	}

	sg.logger.Info("successfully generated, base64 encoded, and upserted secret to 1password",
		slog.String("secret_name", name),
		slog.Int("length_bytes", length),
	)

	return nil
}
