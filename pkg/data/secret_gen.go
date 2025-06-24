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

func NewSecretGenerator() SecretGenerator {
	return &secretGenerator{
		op: onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentSecretGen)),
	}
}

var _ SecretGenerator = (*secretGenerator)(nil)

type secretGenerator struct {
	op onepassword.Service

	logger *slog.Logger
}

func (sg *secretGenerator) GenerateKey(name string, length int) error {

	// length must be at least 32 bytes for secure algorithms such as AES GCM and hmac hashing
	if length < 32 {
		sg.logger.Warn(fmt.Sprintf("length is less than 32 bytes, which is the minimum for several secure algorithms, got %d", length))
	}

	// check if it is a power of 2 so we can use it for AES GCM or blind index hashing
	if length&(length-1) != 0 {
		return fmt.Errorf("length must be a power of 2, got %d", length)
	}

	// generete cryptographically random secret key of specified length
	secret := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		panic(err.Error())
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

	sg.logger.Info(fmt.Sprintf("successfully generated, base64 encoded, and upserted 32 byte secret '%s' to 1password", name))

	return nil
}
