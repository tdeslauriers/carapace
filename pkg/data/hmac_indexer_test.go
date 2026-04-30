package data

import (
	"strings"
	"testing"
)

var (
	key32 = []byte("DeathStarPlans_MayTheForceBe1234")                                   // exactly 32 bytes
	key64 = []byte("DeathStarPlans_MayTheForceBe1234_RebelAllianceSecretKey_LukeSkywal") // 64 bytes
)

func TestNewIndexer(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_32_byte_key",
			key:     key32,
			wantErr: false,
		},
		{
			name:    "valid_64_byte_key",
			key:     key64,
			wantErr: false,
		},
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
			name:      "short_key_31_bytes",
			key:       []byte("DeathStarPlans_MayTheForceBe123"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
		{
			name:      "short_key_1_byte",
			key:       []byte("x"),
			wantErr:   true,
			errSubstr: "32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer, err := NewIndexer(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				if indexer != nil {
					t.Fatal("expected nil indexer on error, got non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if indexer == nil {
				t.Fatal("expected non-nil indexer, got nil")
			}
		})
	}
}

func TestObtainBlindIndex(t *testing.T) {
	indexer32, err := NewIndexer(key32)
	if err != nil {
		t.Fatalf("setup: NewIndexer(key32) failed: %v", err)
	}

	altKey := []byte("RebelAlliancePlans_MayForce1234X")
	indexerAlt, err := NewIndexer(altKey)
	if err != nil {
		t.Fatalf("setup: NewIndexer(altKey) failed: %v", err)
	}

	tests := []struct {
		name      string
		indexer   Indexer
		input     string
		wantLen   int // 0 means skip length check
		checkFunc func(t *testing.T, result string)
	}{
		{
			name:    "output_is_64_char_hex",
			indexer: indexer32,
			input:   "darth.vader@empire.com",
			wantLen: 64,
			checkFunc: func(t *testing.T, result string) {
				for _, c := range result {
					if !strings.ContainsRune("0123456789abcdef", c) {
						t.Errorf("output contains non-hex character: %q", c)
					}
				}
			},
		},
		{
			name:    "deterministic_same_input",
			indexer: indexer32,
			input:   "darth.vader@empire.com",
			wantLen: 64,
			checkFunc: func(t *testing.T, result string) {
				again, err := indexer32.ObtainBlindIndex("darth.vader@empire.com")
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result != again {
					t.Errorf("same input produced different outputs: %q vs %q", result, again)
				}
			},
		},
		{
			name:    "empty_string_input_is_deterministic",
			indexer: indexer32,
			input:   "",
			wantLen: 64,
			checkFunc: func(t *testing.T, result string) {
				again, err := indexer32.ObtainBlindIndex("")
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result != again {
					t.Errorf("empty input produced different outputs: %q vs %q", result, again)
				}
			},
		},
		{
			name:    "different_inputs_produce_different_outputs",
			indexer: indexer32,
			input:   "luke.skywalker@rebels.com",
			wantLen: 64,
			checkFunc: func(t *testing.T, result string) {
				other, err := indexer32.ObtainBlindIndex("darth.vader@empire.com")
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result == other {
					t.Errorf("different inputs produced the same output: %q", result)
				}
			},
		},
		{
			name:    "different_keys_produce_different_outputs",
			indexer: indexer32,
			input:   "darth.vader@empire.com",
			wantLen: 64,
			checkFunc: func(t *testing.T, result string) {
				altResult, err := indexerAlt.ObtainBlindIndex("darth.vader@empire.com")
				if err != nil {
					t.Fatalf("alt indexer call failed: %v", err)
				}
				if result == altResult {
					t.Errorf("different keys produced the same output for the same input: %q", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.indexer.ObtainBlindIndex(tt.input)
			if err != nil {
				t.Fatalf("ObtainBlindIndex(%q) failed: %v", tt.input, err)
			}
			if tt.wantLen > 0 && len(result) != tt.wantLen {
				t.Errorf("output length: want %d, got %d (value: %q)", tt.wantLen, len(result), result)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}
