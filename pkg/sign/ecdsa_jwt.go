package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

type KeyGenerator interface {
	GenerateEcdsaSigningKey(service, env string) error
}

var _ KeyGenerator = (*keyGenerator)(nil)

func NewKeyGenerator(op onepassword.Service) KeyGenerator {
	return &keyGenerator{
		op: op,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentKeyGen)).
			With(slog.String(util.PackageKey, util.PackageSign)),
	}
}

type keyGenerator struct {
	op onepassword.Service

	logger *slog.Logger
}

func (kg *keyGenerator) GenerateEcdsaSigningKey(service, env string) error {

	if service == "" || env == "" {
		return fmt.Errorf("service name and env are required to generate ecdsa key pair")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ecdsa key: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EC (ecdsa) private key: %w", err)
	}

	privPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal PKIX (ecdsa) public key: %w", err)
	}

	pubPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

	privBase64 := base64.StdEncoding.EncodeToString(privPem)
	pubBase64 := base64.StdEncoding.EncodeToString(pubPem)

	kg.logger.Info(
		"successfully generated jwt ecdsa key pair",
		slog.String("env", env),
		slog.String("service", service),
	)

	item := &onepassword.Item{
		Title: fmt.Sprintf("%s_%s_%s", service, util.OpSigningKeyPairTitle, env),
		Vault: onepassword.Vault{
			Name: util.OpVaultName,
		},
		Category: util.OpCategory,
		Tags:     []string{util.OpTag0},
		Fields: []onepassword.Field{
			{Label: util.OpEcdsaPrivateKeyLabel, Value: privBase64, Type: "concealed"},
			{Label: util.OpEcdsaPublicKeyLabel, Value: pubBase64, Type: "concealed"},
		},
	}

	if err := kg.op.UpsertItem(item); err != nil {
		return fmt.Errorf("failed to upsert ecdsa key pair to 1password: %w", err)
	}

	kg.logger.Info(
		"successfully upserted jwt signing ecdsa key pair in 1password",
		slog.String("item_title", item.Title),
	)

	return nil
}
