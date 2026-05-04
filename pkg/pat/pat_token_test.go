package pat

import (
	"encoding/base64"
	"strings"
	"testing"
)

var (
	testPepper    = []byte("test-pepper-exactly-32-bytes-pad")
	testAltPepper = []byte("alt-pepper-exactly-32-bytes-padd")
	testToken     = []byte(strings.Repeat("a", 64))
	testAltToken  = []byte(strings.Repeat("b", 64))
)

func TestNewPatTokener(t *testing.T) {
	if p := NewPatTokener(testPepper); p == nil {
		t.Fatal("expected non-nil PatTokener, got nil")
	}
}

func TestGenerate(t *testing.T) {
	p := NewPatTokener(testPepper)

	tests := []struct {
		name      string
		checkFunc func(t *testing.T, raw []byte, encoded string)
	}{
		{
			name: "raw_is_64_bytes",
			checkFunc: func(t *testing.T, raw []byte, _ string) {
				if len(raw) != 64 {
					t.Errorf("raw length: want 64, got %d", len(raw))
				}
			},
		},
		{
			name: "encoded_is_valid_standard_base64",
			checkFunc: func(t *testing.T, _ []byte, encoded string) {
				if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
					t.Errorf("encoded string is not valid standard base64: %v", err)
				}
			},
		},
		{
			name: "raw_and_encoded_are_consistent",
			checkFunc: func(t *testing.T, raw []byte, encoded string) {
				if want := base64.StdEncoding.EncodeToString(raw); encoded != want {
					t.Error("encoded does not match re-encoding of raw bytes")
				}
			},
		},
		{
			name: "successive_calls_produce_unique_tokens",
			checkFunc: func(t *testing.T, raw []byte, encoded string) {
				raw2, encoded2, err := p.Generate()
				if err != nil {
					t.Fatalf("second Generate() failed: %v", err)
				}
				if string(raw) == string(raw2) {
					t.Error("successive calls returned identical raw bytes")
				}
				if encoded == encoded2 {
					t.Error("successive calls returned identical encoded strings")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, encoded, err := p.Generate()
			if err != nil {
				t.Fatalf("Generate() returned unexpected error: %v", err)
			}
			tt.checkFunc(t, raw, encoded)
		})
	}
}

func TestObtainIndex(t *testing.T) {
	p := NewPatTokener(testPepper)
	pAlt := NewPatTokener(testAltPepper)

	tests := []struct {
		name      string
		tokener   PatTokener
		token     []byte
		wantErr   bool
		errSubstr string
		checkFunc func(t *testing.T, result string)
	}{
		{
			name:      "nil_token_returns_error",
			tokener:   p,
			token:     nil,
			wantErr:   true,
			errSubstr: "empty token",
		},
		{
			name:      "empty_token_returns_error",
			tokener:   p,
			token:     []byte{},
			wantErr:   true,
			errSubstr: "empty token",
		},
		{
			name:    "output_is_64_char_lowercase_hex",
			tokener: p,
			token:   testToken,
			checkFunc: func(t *testing.T, result string) {
				if len(result) != 64 {
					t.Errorf("index length: want 64, got %d", len(result))
				}
				for _, c := range result {
					if !strings.ContainsRune("0123456789abcdef", c) {
						t.Errorf("non-hex character in output: %q", c)
					}
				}
			},
		},
		{
			name:    "deterministic_for_same_input_and_pepper",
			tokener: p,
			token:   testToken,
			checkFunc: func(t *testing.T, result string) {
				again, err := p.ObtainIndex(testToken)
				if err != nil {
					t.Fatalf("second ObtainIndex() call failed: %v", err)
				}
				if result != again {
					t.Errorf("same token/pepper produced different outputs: %q vs %q", result, again)
				}
			},
		},
		{
			name:    "different_tokens_produce_different_indexes",
			tokener: p,
			token:   testToken,
			checkFunc: func(t *testing.T, result string) {
				other, err := p.ObtainIndex(testAltToken)
				if err != nil {
					t.Fatalf("alt-token ObtainIndex() call failed: %v", err)
				}
				if result == other {
					t.Error("different tokens produced the same blind index")
				}
			},
		},
		{
			name:    "different_peppers_produce_different_indexes",
			tokener: pAlt,
			token:   testToken,
			checkFunc: func(t *testing.T, result string) {
				base, err := p.ObtainIndex(testToken)
				if err != nil {
					t.Fatalf("base-pepper ObtainIndex() call failed: %v", err)
				}
				if result == base {
					t.Error("different peppers produced the same blind index for the same token")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.tokener.ObtainIndex(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestHashAndCompare(t *testing.T) {
	p := NewPatTokener(testPepper)
	pAlt := NewPatTokener(testAltPepper)

	validIndex, err := p.ObtainIndex(testToken)
	if err != nil {
		t.Fatalf("test setup: ObtainIndex() failed: %v", err)
	}

	const allZeroIndex = "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name       string
		tokener    PatTokener
		token      []byte
		blindIndex string
		wantMatch  bool
		wantErr    bool
		errSubstr  string
	}{
		{
			name:       "nil_token_returns_error",
			tokener:    p,
			token:      nil,
			blindIndex: validIndex,
			wantErr:    true,
			errSubstr:  "empty token",
		},
		{
			name:       "empty_token_returns_error",
			tokener:    p,
			token:      []byte{},
			blindIndex: validIndex,
			wantErr:    true,
			errSubstr:  "empty token",
		},
		{
			name:       "empty_blind_index_returns_error",
			tokener:    p,
			token:      testToken,
			blindIndex: "",
			wantErr:    true,
			errSubstr:  "empty blind index",
		},
		{
			name:       "matching_token_and_index_returns_true",
			tokener:    p,
			token:      testToken,
			blindIndex: validIndex,
			wantMatch:  true,
		},
		{
			name:       "different_token_returns_false",
			tokener:    p,
			token:      testAltToken,
			blindIndex: validIndex,
			wantMatch:  false,
		},
		{
			name:       "different_pepper_returns_false",
			tokener:    pAlt,
			token:      testToken,
			blindIndex: validIndex,
			wantMatch:  false,
		},
		{
			name:       "tampered_index_returns_false",
			tokener:    p,
			token:      testToken,
			blindIndex: allZeroIndex,
			wantMatch:  false,
		},
		{
			name:       "wrong_length_index_returns_false",
			tokener:    p,
			token:      testToken,
			blindIndex: "abc",
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := tt.tokener.HashAndCompare(tt.token, tt.blindIndex)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match != tt.wantMatch {
				t.Errorf("HashAndCompare: want %v, got %v", tt.wantMatch, match)
			}
		})
	}
}
