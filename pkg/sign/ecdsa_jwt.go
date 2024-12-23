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

func NewKeyGenerator() KeyGenerator {
	return &keyGenerator{
		op: onepassword.NewService(onepassword.NewCli()),

		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentKeyGen)),
	}
}

type keyGenerator struct {
	op onepassword.Service

	logger *slog.Logger
}

func (kg *keyGenerator) GenerateEcdsaSigningKey(service, env string) error {

	if len(service) < 1 || len(env) < 1 {
		return fmt.Errorf("service name and env are required to generate ecdsa key pair")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to generate ecdsa key: %v", err))
	}
	pulicKey := &privateKey.PublicKey

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to marshal EC (ecdsa) private key: %v", err))
	}
	privPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		})

	pubBytes, err := x509.MarshalPKIXPublicKey(pulicKey)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to marshal PKIX (ecdsa) public key: %v", err))
	}
	pubPem :=
		pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

	privBase64 := base64.StdEncoding.EncodeToString(privPem)
	pubBase64 := base64.StdEncoding.EncodeToString(pubPem)

	kg.logger.Info(fmt.Sprintf("successfully generated jwt ecdsa key pair for %s %s", env, service))

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
		return fmt.Errorf(fmt.Sprintf("failed to upsert ecdsa key pair to 1password: %v", err))
	}

	kg.logger.Info(fmt.Sprintf("successfully upserted jwt signing ecdsa key pair %s in 1password", item.Title))

	return nil
}
