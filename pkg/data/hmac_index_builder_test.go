package data

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// mockOp satisfies onepassword.Service. Only GetItem is called by BuildHmacIndex;
// the remaining methods panic if reached so any unexpected call is immediately visible.
type mockOp struct {
	getItem func(title, vault string) (*onepassword.Item, error)
}

func (m *mockOp) GetItem(title, vault string) (*onepassword.Item, error) {
	return m.getItem(title, vault)
}
func (m *mockOp) GetDocument(_, _ string) ([]byte, error)          { panic("unexpected GetDocument") }
func (m *mockOp) UpsertDocument(_, _, _ string, _ []string) error  { panic("unexpected UpsertDocument") }
func (m *mockOp) UpsertItem(_ *onepassword.Item) error             { panic("unexpected UpsertItem") }

// Star Wars themed secrets — raw bytes and their base64 equivalents.
var (
	deathStarKeyRaw = []byte("DeathStarPlans_MayTheForceBe1234") // 32 bytes
	rebelKeyRaw     = []byte("RebelAlliancePls_MayForceBe1234X") // 32 bytes

	deathStarKeyB64 = base64.StdEncoding.EncodeToString(deathStarKeyRaw)
	rebelKeyB64     = base64.StdEncoding.EncodeToString(rebelKeyRaw)
	shortKeyB64     = base64.StdEncoding.EncodeToString([]byte("TooShort")) // decodes to < 32 bytes
)

// makeSecretItem returns an Item with a single "secret" field.
func makeSecretItem(value string) *onepassword.Item {
	return &onepassword.Item{
		Fields: []onepassword.Field{
			{Label: hmacSecretLabel, Value: value},
		},
	}
}

func newIndexBuilderWithMock(fn func(string, string) (*onepassword.Item, error)) *indexBuilder {
	return &indexBuilder{op: &mockOp{getItem: fn}}
}

func TestBuildHmacIndex(t *testing.T) {
	const (
		galacticVault = "GalacticVault"
		secretItem    = "death-star-plans-hmac-key"
	)

	// sentinel is used to verify that GetItem errors are wrapped with %w.
	sentinel := errors.New("1password unavailable")

	tests := []struct {
		name      string
		toIndex   string
		secretNm  string
		vault     string
		opFunc    func(string, string) (*onepassword.Item, error)
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, result string)
	}{
		// ---- input validation (no 1Password call) --------------------------------
		{
			name:      "empty_toIndex",
			toIndex:   "",
			secretNm:  secretItem,
			vault:     galacticVault,
			wantErr:   true,
			errSubstr: "value to index cannot be empty",
		},
		{
			name:      "empty_secretName",
			toIndex:   "luke.skywalker@rebels.com",
			secretNm:  "",
			vault:     galacticVault,
			wantErr:   true,
			errSubstr: "secret name cannot be empty",
		},

		// ---- 1Password retrieval failures ----------------------------------------
		{
			name:     "getitem_returns_error",
			toIndex:  "han.solo@millenniumfalcon.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return nil, fmt.Errorf("vault not found")
			},
			wantErr:   true,
			errSubstr: "failed to retrieve item",
		},
		{
			name:     "getitem_error_is_wrapped_with_w",
			toIndex:  "leia.organa@alderaan.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return nil, sentinel
			},
			wantErr:   true,
			errSubstr: "failed to retrieve item",
			check: func(t *testing.T, _ string) {
				// verified in the loop body below using errors.Is
			},
		},

		// ---- secret field resolution failures ------------------------------------
		{
			name:     "item_has_no_fields",
			toIndex:  "darth.vader@empire.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return &onepassword.Item{}, nil
			},
			wantErr:   true,
			errSubstr: "failed to find field",
		},
		{
			name:     "item_fields_have_no_matching_label",
			toIndex:  "darth.vader@empire.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return &onepassword.Item{Fields: []onepassword.Field{
					{Label: "username", Value: "lord.vader"},
					{Label: "password", Value: "UseTheForce123!"},
				}}, nil
			},
			wantErr:   true,
			errSubstr: "failed to find field",
		},
		{
			name:     "secret_field_has_empty_value",
			toIndex:  "darth.vader@empire.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(""), nil
			},
			wantErr:   true,
			errSubstr: "failed to find field",
		},

		// ---- base64 / key failures -----------------------------------------------
		{
			name:     "secret_field_not_valid_base64",
			toIndex:  "yoda@dagobah.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem("not-valid-base64===!!!"), nil
			},
			wantErr:   true,
			errSubstr: "failed to decode hmac secret",
		},
		{
			name:     "decoded_key_shorter_than_32_bytes",
			toIndex:  "obi-wan.kenobi@jedi.order",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(shortKeyB64), nil
			},
			wantErr:   true,
			errSubstr: "failed to create hmac indexer",
		},

		// ---- success cases -------------------------------------------------------
		{
			name:     "valid_index_is_64_char_lowercase_hex",
			toIndex:  "luke.skywalker@rebels.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(deathStarKeyB64), nil
			},
			check: func(t *testing.T, result string) {
				if len(result) != 64 {
					t.Errorf("want 64-char hex, got %d chars: %q", len(result), result)
				}
				for _, c := range result {
					if !strings.ContainsRune("0123456789abcdef", c) {
						t.Errorf("non-hex character in output: %q", c)
					}
				}
			},
		},
		{
			name:     "deterministic_same_input_and_key",
			toIndex:  "leia.organa@alderaan.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(deathStarKeyB64), nil
			},
			check: func(t *testing.T, result string) {
				again, err := newIndexBuilderWithMock(func(_, _ string) (*onepassword.Item, error) {
					return makeSecretItem(deathStarKeyB64), nil
				}).BuildHmacIndex("leia.organa@alderaan.com", secretItem, galacticVault)
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result != again {
					t.Errorf("same input/key produced different outputs: %q vs %q", result, again)
				}
			},
		},
		{
			name:     "different_inputs_produce_different_indexes",
			toIndex:  "han.solo@millenniumfalcon.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(deathStarKeyB64), nil
			},
			check: func(t *testing.T, result string) {
				other, err := newIndexBuilderWithMock(func(_, _ string) (*onepassword.Item, error) {
					return makeSecretItem(deathStarKeyB64), nil
				}).BuildHmacIndex("chewbacca@kashyyyk.com", secretItem, galacticVault)
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result == other {
					t.Errorf("different inputs produced the same index: %q", result)
				}
			},
		},
		{
			name:     "different_keys_produce_different_indexes",
			toIndex:  "r2d2@republic.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return makeSecretItem(deathStarKeyB64), nil
			},
			check: func(t *testing.T, result string) {
				other, err := newIndexBuilderWithMock(func(_, _ string) (*onepassword.Item, error) {
					return makeSecretItem(rebelKeyB64), nil
				}).BuildHmacIndex("r2d2@republic.com", secretItem, galacticVault)
				if err != nil {
					t.Fatalf("alt-key call failed: %v", err)
				}
				if result == other {
					t.Errorf("different keys produced the same index for the same input: %q", result)
				}
			},
		},
		{
			name:     "correct_field_selected_among_many",
			toIndex:  "c3po@protocol-droids.com",
			secretNm: secretItem,
			vault:    galacticVault,
			opFunc: func(_, _ string) (*onepassword.Item, error) {
				return &onepassword.Item{Fields: []onepassword.Field{
					{Label: "username", Value: "deathstar-admin"},
					{Label: "password", Value: "PalpatiNe4Ever!"},
					{Label: hmacSecretLabel, Value: deathStarKeyB64},
					{Label: "notes", Value: "Do not let rebels find this"},
				}}, nil
			},
			check: func(t *testing.T, result string) {
				if len(result) != 64 {
					t.Errorf("want 64-char hex, got %d chars: %q", len(result), result)
				}
			},
		},
		{
			name:     "correct_title_and_vault_forwarded_to_getitem",
			toIndex:  "mace.windu@jedi.council",
			secretNm: "jedi-council-hmac-key",
			vault:    "JediVault",
			opFunc: func(title, vault string) (*onepassword.Item, error) {
				if title != "jedi-council-hmac-key" {
					t.Errorf("GetItem: unexpected title %q", title)
				}
				if vault != "JediVault" {
					t.Errorf("GetItem: unexpected vault %q", vault)
				}
				return makeSecretItem(deathStarKeyB64), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc := tt.opFunc
			if opFunc == nil {
				// input-validation cases must never reach 1Password
				opFunc = func(_, _ string) (*onepassword.Item, error) {
					t.Fatal("GetItem should not be called for input-validation failures")
					return nil, nil
				}
			}

			ib := newIndexBuilderWithMock(opFunc)
			result, err := ib.BuildHmacIndex(tt.toIndex, tt.secretNm, tt.vault)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", result)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				// verify sentinel wrapping for the specific case
				if tt.name == "getitem_error_is_wrapped_with_w" && !errors.Is(err, sentinel) {
					t.Fatalf("expected errors.Is to find sentinel in error chain, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}
