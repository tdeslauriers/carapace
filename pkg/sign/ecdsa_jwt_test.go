package sign

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/internal/util"
	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

func TestGenSigningKey(t *testing.T) {
	tests := []struct {
		name      string
		service   string
		env       string
		upsertErr error
		wantErr   bool
		errSubstr string
		checkItem func(t *testing.T, item *onepassword.Item)
	}{
		{
			name:      "empty_service",
			service:   "",
			env:       "prod",
			wantErr:   true,
			errSubstr: "service name and env are required",
		},
		{
			name:      "empty_env",
			service:   "my-service",
			env:       "",
			wantErr:   true,
			errSubstr: "service name and env are required",
		},
		{
			name:      "both_empty",
			service:   "",
			env:       "",
			wantErr:   true,
			errSubstr: "service name and env are required",
		},
		{
			name:      "upsert_failure",
			service:   "my-service",
			env:       "prod",
			upsertErr: errors.New("1password unavailable"),
			wantErr:   true,
			errSubstr: "failed to upsert ecdsa key pair to 1password",
		},
		{
			name:    "item_title_format",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				want := fmt.Sprintf("my-service_%s_prod", util.OpSigningKeyPairTitle)
				if item.Title != want {
					t.Errorf("title: want %q, got %q", want, item.Title)
				}
			},
		},
		{
			name:    "item_vault_category_and_tags",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				if item.Vault.Name != util.OpVaultName {
					t.Errorf("vault: want %q, got %q", util.OpVaultName, item.Vault.Name)
				}
				if item.Category != util.OpCategory {
					t.Errorf("category: want %q, got %q", util.OpCategory, item.Category)
				}
				if len(item.Tags) != 1 || item.Tags[0] != util.OpTag0 {
					t.Errorf("tags: want [%q], got %v", util.OpTag0, item.Tags)
				}
			},
		},
		{
			name:    "item_has_two_concealed_fields",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				if len(item.Fields) != 2 {
					t.Fatalf("fields: want 2, got %d", len(item.Fields))
				}
				fieldMap := make(map[string]onepassword.Field)
				for _, f := range item.Fields {
					fieldMap[f.Label] = f
				}
				for _, label := range []string{util.OpEcdsaPrivateKeyLabel, util.OpEcdsaPublicKeyLabel} {
					f, ok := fieldMap[label]
					if !ok {
						t.Errorf("missing field: %q", label)
						continue
					}
					if f.Type != "concealed" {
						t.Errorf("field %q type: want %q, got %q", label, "concealed", f.Type)
					}
				}
			},
		},
		{
			name:    "private_key_field_is_pkcs8_ecdsa_pem",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				var privValue string
				for _, f := range item.Fields {
					if f.Label == util.OpEcdsaPrivateKeyLabel {
						privValue = f.Value
					}
				}
				if privValue == "" {
					t.Fatal("private key field value is empty")
				}
				pemBytes, err := base64.StdEncoding.DecodeString(privValue)
				if err != nil {
					t.Fatalf("private key value is not valid base64: %v", err)
				}
				block, _ := pem.Decode(pemBytes)
				if block == nil {
					t.Fatal("private key value does not contain a valid PEM block")
				}
				if block.Type != "PRIVATE KEY" {
					t.Errorf("private key PEM type: want %q, got %q", "PRIVATE KEY", block.Type)
				}
				parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					t.Fatalf("private key is not valid PKCS8: %v", err)
				}
				if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
					t.Error("PKCS8 key is not an ECDSA key")
				}
			},
		},
		{
			name:    "public_key_field_is_pkix_ecdsa_pem",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				var pubValue string
				for _, f := range item.Fields {
					if f.Label == util.OpEcdsaPublicKeyLabel {
						pubValue = f.Value
					}
				}
				if pubValue == "" {
					t.Fatal("public key field value is empty")
				}
				pemBytes, err := base64.StdEncoding.DecodeString(pubValue)
				if err != nil {
					t.Fatalf("public key value is not valid base64: %v", err)
				}
				block, _ := pem.Decode(pemBytes)
				if block == nil {
					t.Fatal("public key value does not contain a valid PEM block")
				}
				if block.Type != "PUBLIC KEY" {
					t.Errorf("public key PEM type: want %q, got %q", "PUBLIC KEY", block.Type)
				}
				generic, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					t.Fatalf("public key is not valid PKIX: %v", err)
				}
				if _, ok := generic.(*ecdsa.PublicKey); !ok {
					t.Error("PKIX key is not an ECDSA public key")
				}
			},
		},
		{
			// Keys are generated fresh each call; successive calls must produce
			// different key material even for the same service/env inputs.
			name:    "successive_calls_produce_different_keys",
			service: "my-service",
			env:     "prod",
			wantErr: false,
			checkItem: func(t *testing.T, item *onepassword.Item) {
				t.Helper()
				firstValue := ""
				for _, f := range item.Fields {
					if f.Label == util.OpEcdsaPrivateKeyLabel {
						firstValue = f.Value
					}
				}

				var secondValue string
				mock2 := &mockOpService{}
				kg2 := NewKeyGenerator(mock2)
				if err := kg2.GenerateEcdsaSigningKey("my-service", "prod"); err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				for _, f := range mock2.capturedItem.Fields {
					if f.Label == util.OpEcdsaPrivateKeyLabel {
						secondValue = f.Value
					}
				}
				if firstValue == secondValue {
					t.Error("two successive calls produced identical private key material")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upsertErr := tt.upsertErr
			mock := &mockOpService{
				upsertItemFn: func(item *onepassword.Item) error {
					return upsertErr
				},
			}

			kg := NewKeyGenerator(mock)
			err := kg.GenerateEcdsaSigningKey(tt.service, tt.env)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkItem != nil && mock.capturedItem != nil {
				tt.checkItem(t, mock.capturedItem)
			}
		})
	}
}
