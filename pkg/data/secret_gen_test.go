package data

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	onepassword "github.com/tdeslauriers/carapace/pkg/one_password"
)

// mockOpService is a test double for onepassword.Service.
// It captures the last item passed to UpsertItem so tests can assert on it.
type mockOpService struct {
	upsertErr    error
	lastUpserted *onepassword.Item
}

func (m *mockOpService) GetDocument(title, vault string) ([]byte, error) { return nil, nil }
func (m *mockOpService) UpsertDocument(path, title, vault string, tags []string) error {
	return nil
}
func (m *mockOpService) GetItem(title, vault string) (*onepassword.Item, error) { return nil, nil }
func (m *mockOpService) UpsertItem(item *onepassword.Item) error {
	m.lastUpserted = item
	return m.upsertErr
}

// findField returns the first Field with the matching label, or nil.
func findField(fields []onepassword.Field, label string) *onepassword.Field {
	for i := range fields {
		if fields[i].Label == label {
			return &fields[i]
		}
	}
	return nil
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name      string
		keyName   string
		length    int
		upsertErr error
		wantErr   bool
		errSubstr string
		checkFunc func(t *testing.T, mock *mockOpService)
	}{
		// --- invalid lengths: boundaries and representative rejections ---
		{
			name:      "length_negative_32",
			keyName:   "darth_vader_key",
			length:    -32,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_negative_1",
			keyName:   "darth_vader_key",
			length:    -1,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_zero",
			keyName:   "darth_vader_key",
			length:    0,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_1",
			keyName:   "darth_vader_key",
			length:    1,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_8",
			keyName:   "darth_vader_key",
			length:    8,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_15_boundary_below_16",
			keyName:   "darth_vader_key",
			length:    15,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_17_boundary_above_16",
			keyName:   "darth_vader_key",
			length:    17,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_24_aes192_not_supported",
			keyName:   "darth_vader_key",
			length:    24,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_31_boundary_below_32",
			keyName:   "darth_vader_key",
			length:    31,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_33_boundary_above_32",
			keyName:   "darth_vader_key",
			length:    33,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_48",
			keyName:   "darth_vader_key",
			length:    48,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_63_boundary_below_64",
			keyName:   "darth_vader_key",
			length:    63,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_65_boundary_above_64",
			keyName:   "darth_vader_key",
			length:    65,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_128_power_of_two_not_in_whitelist",
			keyName:   "darth_vader_key",
			length:    128,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		{
			name:      "length_256",
			keyName:   "darth_vader_key",
			length:    256,
			wantErr:   true,
			errSubstr: "16, 32, or 64",
		},
		// --- validation errors must not reach UpsertItem ---
		{
			name:    "upsert_not_called_on_invalid_length",
			keyName: "emperor_palpatine_key",
			length:  48,
			wantErr: true,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted != nil {
					t.Error("UpsertItem was called despite invalid length; early return did not fire")
				}
			},
		},
		// --- UpsertItem error propagation ---
		{
			name:      "upsert_error_propagated",
			keyName:   "rebel_alliance_key",
			length:    32,
			upsertErr: fmt.Errorf("1password: vault unreachable"),
			wantErr:   true,
			errSubstr: "vault unreachable",
		},
		// --- valid lengths: 16 (AES-128) ---
		{
			name:    "valid_length_16_aes128_key_decoded_length",
			keyName: "luke_skywalker_key",
			length:  16,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				secret := findField(mock.lastUpserted.Fields, "secret")
				if secret == nil {
					t.Fatal("item missing 'secret' field")
				}
				raw, err := base64.StdEncoding.DecodeString(secret.Value)
				if err != nil {
					t.Fatalf("secret value is not valid base64: %v", err)
				}
				if len(raw) != 16 {
					t.Errorf("decoded key length: want 16, got %d", len(raw))
				}
			},
		},
		// --- valid lengths: 32 (AES-256 / HMAC-SHA256) ---
		{
			name:    "valid_length_32_aes256_key_decoded_length",
			keyName: "obi_wan_kenobi_key",
			length:  32,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				secret := findField(mock.lastUpserted.Fields, "secret")
				if secret == nil {
					t.Fatal("item missing 'secret' field")
				}
				raw, err := base64.StdEncoding.DecodeString(secret.Value)
				if err != nil {
					t.Fatalf("secret value is not valid base64: %v", err)
				}
				if len(raw) != 32 {
					t.Errorf("decoded key length: want 32, got %d", len(raw))
				}
			},
		},
		// --- valid lengths: 64 (HMAC-SHA512) ---
		{
			name:    "valid_length_64_hmac_sha512_key_decoded_length",
			keyName: "yoda_key",
			length:  64,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				secret := findField(mock.lastUpserted.Fields, "secret")
				if secret == nil {
					t.Fatal("item missing 'secret' field")
				}
				raw, err := base64.StdEncoding.DecodeString(secret.Value)
				if err != nil {
					t.Fatalf("secret value is not valid base64: %v", err)
				}
				if len(raw) != 64 {
					t.Errorf("decoded key length: want 64, got %d", len(raw))
				}
			},
		},
		// --- item title matches the name argument ---
		{
			name:    "item_title_matches_name_arg",
			keyName: "millennium_falcon_key",
			length:  32,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				if mock.lastUpserted.Title != "millennium_falcon_key" {
					t.Errorf("item.Title: want %q, got %q", "millennium_falcon_key", mock.lastUpserted.Title)
				}
			},
		},
		// --- secret field type must be CONCEALED ---
		{
			name:    "secret_field_type_is_concealed",
			keyName: "princess_leia_key",
			length:  32,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				secret := findField(mock.lastUpserted.Fields, "secret")
				if secret == nil {
					t.Fatal("item missing 'secret' field")
				}
				if secret.Type != "CONCEALED" {
					t.Errorf("secret field type: want CONCEALED, got %q", secret.Type)
				}
			},
		},
		// --- notes field present with correct purpose ---
		{
			name:    "notes_field_present_with_notes_purpose",
			keyName: "han_solo_key",
			length:  32,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				notes := findField(mock.lastUpserted.Fields, "notesPlain")
				if notes == nil {
					t.Fatal("item missing 'notesPlain' field")
				}
				if notes.Purpose != "NOTES" {
					t.Errorf("notesPlain purpose: want NOTES, got %q", notes.Purpose)
				}
				if notes.Value == "" {
					t.Error("notesPlain value is empty")
				}
			},
		},
		// --- item metadata: vault, tags, category must be set ---
		{
			name:    "item_metadata_vault_tags_category_populated",
			keyName: "chewbacca_key",
			length:  32,
			checkFunc: func(t *testing.T, mock *mockOpService) {
				if mock.lastUpserted == nil {
					t.Fatal("UpsertItem was not called")
				}
				item := mock.lastUpserted
				if item.Vault.Name == "" {
					t.Error("item.Vault.Name is empty")
				}
				if len(item.Tags) == 0 {
					t.Error("item.Tags is empty")
				}
				if item.Category == "" {
					t.Error("item.Category is empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockOpService{upsertErr: tt.upsertErr}
			sg := NewSecretGenerator(mock)

			err := sg.GenerateKey(tt.keyName, tt.length)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				if tt.checkFunc != nil {
					tt.checkFunc(t, mock)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, mock)
			}
		})
	}
}

// TestGenerateKey_Uniqueness verifies that successive calls produce distinct keys,
// guarding against RNG reuse or a broken rand.Reader.
func TestGenerateKey_Uniqueness(t *testing.T) {
	lengths := []int{16, 32, 64}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			mock1 := &mockOpService{}
			mock2 := &mockOpService{}

			if err := NewSecretGenerator(mock1).GenerateKey("jedi_key_alpha", length); err != nil {
				t.Fatalf("first GenerateKey(%d) failed: %v", length, err)
			}
			if err := NewSecretGenerator(mock2).GenerateKey("jedi_key_beta", length); err != nil {
				t.Fatalf("second GenerateKey(%d) failed: %v", length, err)
			}

			f1 := findField(mock1.lastUpserted.Fields, "secret")
			f2 := findField(mock2.lastUpserted.Fields, "secret")
			if f1 == nil || f2 == nil {
				t.Fatal("'secret' field missing from one or both generated items")
			}
			if f1.Value == f2.Value {
				t.Errorf("two independent GenerateKey(%d) calls produced the same secret value: possible RNG failure", length)
			}
		})
	}
}
