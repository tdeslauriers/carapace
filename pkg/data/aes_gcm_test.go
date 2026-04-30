package data

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
)

// Star Wars themed 32-byte AES-256 test keys.
var (
	sithAesKey = []byte("SithOrder_Key_Palpatine_AES256__") // 32 bytes
	jediAesKey = []byte("JediOrder_Key_Yoda_ForceAES256__") // 32 bytes
)

// mustNewCryptor creates a Cryptor or immediately fails the test.
func mustNewCryptor(t *testing.T, key []byte) Cryptor {
	t.Helper()
	c, err := NewServiceAesGcmKey(key)
	if err != nil {
		t.Fatalf("setup: NewServiceAesGcmKey failed: %v", err)
	}
	return c
}

// mustEncrypt encrypts plaintext or immediately fails the test.
func mustEncrypt(t *testing.T, c Cryptor, plaintext []byte) string {
	t.Helper()
	ct, err := c.EncryptServiceData(plaintext)
	if err != nil {
		t.Fatalf("setup: EncryptServiceData failed: %v", err)
	}
	return ct
}

// tamperCiphertext flips all bits of the first payload byte (after the nonce).
func tamperCiphertext(t *testing.T, ciphertext string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("tamperCiphertext: base64 decode failed: %v", err)
	}
	const nonceSize = 12
	if len(raw) <= nonceSize {
		t.Fatal("tamperCiphertext: ciphertext too short to tamper payload")
	}
	raw[nonceSize] ^= 0xFF
	return base64.StdEncoding.EncodeToString(raw)
}

// runEncryptField launches EncryptField as a goroutine and collects the result.
func runEncryptField(t *testing.T, c Cryptor, fieldname, plaintext string) (string, error) {
	t.Helper()
	var wg sync.WaitGroup
	ciphertextCh := make(chan string, 1)
	errCh := make(chan error, 1)
	wg.Add(1)
	go c.EncryptField(fieldname, plaintext, ciphertextCh, errCh, &wg)
	wg.Wait()
	select {
	case ct := <-ciphertextCh:
		return ct, nil
	case err := <-errCh:
		return "", err
	default:
		t.Fatal("EncryptField: nothing sent to either channel")
		return "", nil
	}
}

// runDecryptField launches DecryptField as a goroutine and collects the result.
func runDecryptField(t *testing.T, c Cryptor, fieldname, ciphertext string) (string, error) {
	t.Helper()
	var wg sync.WaitGroup
	plaintextCh := make(chan string, 1)
	errCh := make(chan error, 1)
	wg.Add(1)
	go c.DecryptField(fieldname, ciphertext, plaintextCh, errCh, &wg)
	wg.Wait()
	select {
	case pt := <-plaintextCh:
		return pt, nil
	case err := <-errCh:
		return "", err
	default:
		t.Fatal("DecryptField: nothing sent to either channel")
		return "", nil
	}
}

func TestGenerateAesGcmKey(t *testing.T) {

	k := GenerateAesGcmKey()
	if len(k) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(k))
	}

	k2 := GenerateAesGcmKey()
	if string(k) == string(k2) {
		t.Error("two consecutive calls produced the same key: possible RNG failure")
	}

	if _, err := NewServiceAesGcmKey(k); err != nil {
		t.Errorf("generated key rejected by NewServiceAesGcmKey: %v", err)
	}

	t.Logf("sample AES-256 key (base64): %s", base64.StdEncoding.EncodeToString(k))
}

func TestNewServiceAesGcmKey(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "nil_key",
			key:       nil,
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "empty_key",
			key:       []byte{},
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "15_byte_key",
			key:       []byte("MayTheForceBe15"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "16_byte_key_aes128_rejected",
			key:       []byte("MayTheForceBe_16"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "24_byte_key_aes192_rejected",
			key:       []byte("MayTheForce24BytesWow!__"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "31_byte_key",
			key:       []byte("SithOrder_Key_Palpatine_AES256_"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:    "valid_32_byte_key",
			key:     sithAesKey,
			wantErr: false,
		},
		{
			name:      "33_byte_key",
			key:       []byte("SithOrder_Key_Palpatine_AES256___"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "64_byte_key",
			key:       append(append([]byte(nil), sithAesKey...), jediAesKey...),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewServiceAesGcmKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				if c != nil {
					t.Fatal("expected nil Cryptor on error, got non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c == nil {
				t.Fatal("expected non-nil Cryptor, got nil")
			}
		})
	}
}

func TestEncryptServiceData(t *testing.T) {
	sith := mustNewCryptor(t, sithAesKey)

	tests := []struct {
		name      string
		plaintext []byte
		check     func(t *testing.T, result string)
	}{
		{
			name:      "email_luke_skywalker",
			plaintext: []byte("luke.skywalker@rebels.com"),
			check: func(t *testing.T, result string) {
				if result == "" {
					t.Error("expected non-empty ciphertext")
				}
				if _, err := base64.StdEncoding.DecodeString(result); err != nil {
					t.Errorf("result is not valid base64: %v", err)
				}
			},
		},
		{
			name:      "email_darth_vader",
			plaintext: []byte("darth.vader@empire.com"),
		},
		{
			name:      "email_princess_leia",
			plaintext: []byte("leia.organa@alderaan.com"),
		},
		{
			name:      "long_plaintext_yoda_quote",
			plaintext: []byte("Fear is the path to the dark side. Fear leads to anger. Anger leads to hate. Hate leads to suffering."),
		},
		{
			name:      "empty_byte_slice",
			plaintext: []byte{},
			check: func(t *testing.T, result string) {
				// nonce(12) + auth_tag(16) = 28 bytes for 0-byte plaintext
				raw, err := base64.StdEncoding.DecodeString(result)
				if err != nil {
					t.Fatalf("result is not valid base64: %v", err)
				}
				if len(raw) != 28 {
					t.Errorf("expected 28 decoded bytes for empty plaintext, got %d", len(raw))
				}
			},
		},
		{
			name:      "output_length_is_nonce_plus_plaintext_plus_tag",
			plaintext: []byte("obi-wan.kenobi@jedi.order"),
			check: func(t *testing.T, result string) {
				raw, err := base64.StdEncoding.DecodeString(result)
				if err != nil {
					t.Fatalf("not valid base64: %v", err)
				}
				want := 12 + len("obi-wan.kenobi@jedi.order") + 16
				if len(raw) != want {
					t.Errorf("decoded length: want %d, got %d", want, len(raw))
				}
			},
		},
		{
			name:      "nonce_randomness_same_input_produces_different_ciphertext",
			plaintext: []byte("han.solo@millenniumfalcon.com"),
			check: func(t *testing.T, result string) {
				second := mustEncrypt(t, sith, []byte("han.solo@millenniumfalcon.com"))
				if result == second {
					t.Error("encrypting the same plaintext twice produced identical ciphertext: nonce reuse")
				}
			},
		},
		{
			name:      "binary_data",
			plaintext: []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sith.EncryptServiceData(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptServiceData failed: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestDecryptServiceData(t *testing.T) {
	sith := mustNewCryptor(t, sithAesKey)
	jedi := mustNewCryptor(t, jediAesKey)

	lukeCipher := mustEncrypt(t, sith, []byte("luke.skywalker@rebels.com"))
	vaderCipher := mustEncrypt(t, sith, []byte("darth.vader@empire.com"))
	yodaCipher := mustEncrypt(t, sith, []byte("yoda@dagobah.com"))
	emptyCipher := mustEncrypt(t, sith, []byte{})

	// 11 bytes decodes to < 12 (GCM nonce size) → "ciphertext too short"
	tooShortB64 := base64.StdEncoding.EncodeToString(make([]byte, 11))

	tests := []struct {
		name       string
		cryptor    Cryptor
		ciphertext string
		wantErr    bool
		errSubstr  string
		wantPlain  string
	}{
		// --- roundtrip success ---
		{
			name:       "roundtrip_luke_skywalker",
			cryptor:    sith,
			ciphertext: lukeCipher,
			wantPlain:  "luke.skywalker@rebels.com",
		},
		{
			name:       "roundtrip_darth_vader",
			cryptor:    sith,
			ciphertext: vaderCipher,
			wantPlain:  "darth.vader@empire.com",
		},
		{
			name:       "roundtrip_yoda",
			cryptor:    sith,
			ciphertext: yodaCipher,
			wantPlain:  "yoda@dagobah.com",
		},
		{
			name:       "roundtrip_empty_plaintext",
			cryptor:    sith,
			ciphertext: emptyCipher,
			wantPlain:  "",
		},
		// --- format errors ---
		{
			name:       "empty_string_too_short",
			cryptor:    sith,
			ciphertext: "",
			wantErr:    true,
			errSubstr:  "ciphertext too short",
		},
		{
			name:       "not_valid_base64",
			cryptor:    sith,
			ciphertext: "not!valid!base64!!!",
			wantErr:    true,
			errSubstr:  "failed to base64-decode",
		},
		{
			name:       "decoded_length_less_than_nonce_size",
			cryptor:    sith,
			ciphertext: tooShortB64,
			wantErr:    true,
			errSubstr:  "ciphertext too short",
		},
		// --- authentication failures ---
		{
			name:       "tampered_ciphertext_bit_flip",
			cryptor:    sith,
			ciphertext: tamperCiphertext(t, lukeCipher),
			wantErr:    true,
			errSubstr:  "authentication failed",
		},
		{
			name:       "wrong_key_jedi_key_on_sith_ciphertext",
			cryptor:    jedi,
			ciphertext: vaderCipher,
			wantErr:    true,
			errSubstr:  "authentication failed",
		},
		{
			name:       "wrong_key_sith_key_on_jedi_ciphertext",
			cryptor:    sith,
			ciphertext: mustEncrypt(t, jedi, []byte("mace.windu@jedi.council")),
			wantErr:    true,
			errSubstr:  "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cryptor.DecryptServiceData(tt.ciphertext)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", string(got))
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.wantPlain {
				t.Errorf("decrypted: want %q, got %q", tt.wantPlain, string(got))
			}
		})
	}
}

func TestEncryptField(t *testing.T) {
	sith := mustNewCryptor(t, sithAesKey)

	tests := []struct {
		name      string
		fieldname string
		plaintext string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, result string)
	}{
		{
			name:      "empty_plaintext_error_contains_fieldname",
			fieldname: "email",
			plaintext: "",
			wantErr:   true,
			errSubstr: "email",
		},
		{
			name:      "empty_plaintext_different_fieldname",
			fieldname: "homeworld",
			plaintext: "",
			wantErr:   true,
			errSubstr: "homeworld",
		},
		{
			name:      "valid_email_field",
			fieldname: "email",
			plaintext: "luke.skywalker@rebels.com",
			check: func(t *testing.T, result string) {
				if result == "" {
					t.Error("expected non-empty ciphertext")
				}
				if _, err := base64.StdEncoding.DecodeString(result); err != nil {
					t.Errorf("result is not valid base64: %v", err)
				}
			},
		},
		{
			name:      "valid_username_field_darth_vader",
			fieldname: "username",
			plaintext: "darth.vader",
		},
		{
			name:      "valid_field_roundtrip",
			fieldname: "title",
			plaintext: "Dark Lord of the Sith",
			check: func(t *testing.T, result string) {
				got, err := runDecryptField(t, sith, "title", result)
				if err != nil {
					t.Fatalf("roundtrip decrypt failed: %v", err)
				}
				if got != "Dark Lord of the Sith" {
					t.Errorf("roundtrip: want %q, got %q", "Dark Lord of the Sith", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := runEncryptField(t, sith, tt.fieldname, tt.plaintext)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", result)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
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

func TestDecryptField(t *testing.T) {
	sith := mustNewCryptor(t, sithAesKey)

	lukeCipher := mustEncrypt(t, sith, []byte("luke.skywalker@rebels.com"))
	vaderCipher := mustEncrypt(t, sith, []byte("darth.vader@empire.com"))
	leiaCipher := mustEncrypt(t, sith, []byte("leia.organa@alderaan.com"))

	tests := []struct {
		name       string
		fieldname  string
		ciphertext string
		wantErr    bool
		errSubstr  string
		wantPlain  string
	}{
		{
			name:       "empty_ciphertext_error_contains_fieldname",
			fieldname:  "email",
			ciphertext: "",
			wantErr:    true,
			errSubstr:  "email",
		},
		{
			name:       "empty_ciphertext_different_fieldname",
			fieldname:  "homeworld",
			ciphertext: "",
			wantErr:    true,
			errSubstr:  "homeworld",
		},
		{
			name:       "roundtrip_luke_skywalker",
			fieldname:  "email",
			ciphertext: lukeCipher,
			wantPlain:  "luke.skywalker@rebels.com",
		},
		{
			name:       "roundtrip_darth_vader",
			fieldname:  "username",
			ciphertext: vaderCipher,
			wantPlain:  "darth.vader@empire.com",
		},
		{
			name:       "roundtrip_princess_leia",
			fieldname:  "email",
			ciphertext: leiaCipher,
			wantPlain:  "leia.organa@alderaan.com",
		},
		{
			name:       "tampered_ciphertext_error_contains_fieldname",
			fieldname:  "homeworld",
			ciphertext: tamperCiphertext(t, lukeCipher),
			wantErr:    true,
			errSubstr:  "homeworld",
		},
		{
			name:       "invalid_base64_error_contains_fieldname",
			fieldname:  "planet",
			ciphertext: "not!valid!base64!!!",
			wantErr:    true,
			errSubstr:  "planet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := runDecryptField(t, sith, tt.fieldname, tt.ciphertext)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", result)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.wantPlain {
				t.Errorf("decrypted: want %q, got %q", tt.wantPlain, result)
			}
		})
	}
}
