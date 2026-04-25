package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestMint(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	s := NewSigner(privKey)
	v := NewVerifier("service-a", &privKey.PublicKey)

	now := time.Now().UTC()

	baseClaims := Claims{
		Jti:      "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		Issuer:   "https://auth.example.com",
		Subject:  "user@example.com",
		Audience: []string{"service-a"},
		IssuedAt: now.Unix(),
		Expires:  now.Add(time.Hour).Unix(),
		Scopes:   "r:service-a:*",
	}

	newToken := func() *Token {
		return &Token{
			Header: Header{Alg: ES512, Typ: TokenType},
			Claims: baseClaims,
		}
	}

	tests := []struct {
		name      string
		token     *Token
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, tok *Token)
	}{
		{
			name:    "all_output_fields_populated",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if tok.BaseString == "" {
					t.Error("BaseString is empty after Mint")
				}
				if len(tok.Signature) == 0 {
					t.Error("Signature is empty after Mint")
				}
				if tok.Raw == "" {
					t.Error("Raw is empty after Mint")
				}
			},
		},
		{
			// ES512 raw r‖s serialization: exactly 2 × Keysize bytes.
			name:    "signature_length_is_two_keysize_bytes",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if len(tok.Signature) != 2*Keysize {
					t.Errorf("signature length: want %d, got %d", 2*Keysize, len(tok.Signature))
				}
			},
		},
		{
			name:    "raw_has_three_dot_separated_segments",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				parts := strings.Split(tok.Raw, ".")
				if len(parts) != 3 {
					t.Errorf("expected 3 Raw segments, got %d: %q", len(parts), tok.Raw)
				}
			},
		},
		{
			name:    "base_string_matches_first_two_segments_of_raw",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				parts := strings.Split(tok.Raw, ".")
				want := parts[0] + "." + parts[1]
				if tok.BaseString != want {
					t.Errorf("BaseString %q does not match first two Raw segments %q", tok.BaseString, want)
				}
			},
		},
		{
			// JWT spec (RFC 7515) requires RawURL base64 — no padding or standard chars.
			name:    "raw_uses_rawurl_encoding_no_padding",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if strings.ContainsAny(tok.Raw, "=+/") {
					t.Errorf("Raw contains non-URL-safe or padding characters: %q", tok.Raw)
				}
			},
		},
		{
			name:    "signature_verifies_against_public_key",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if err := v.VerifySignature(tok.BaseString, tok.Signature); err != nil {
					t.Errorf("minted signature failed verification: %v", err)
				}
			},
		},
		{
			name:    "raw_round_trips_through_build_token_from_raw",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				parsed, err := BuildTokenFromRaw(tok.Raw)
				if err != nil {
					t.Fatalf("BuildTokenFromRaw failed on minted token: %v", err)
				}
				if parsed.Header.Alg != ES512 || parsed.Header.Typ != TokenType {
					t.Errorf("parsed header mismatch: got %+v", parsed.Header)
				}
				if parsed.Claims.Subject != baseClaims.Subject {
					t.Errorf("parsed subject: want %q, got %q", baseClaims.Subject, parsed.Claims.Subject)
				}
				if parsed.Claims.Issuer != baseClaims.Issuer {
					t.Errorf("parsed issuer: want %q, got %q", baseClaims.Issuer, parsed.Claims.Issuer)
				}
			},
		},
		{
			// ECDSA signing uses a random nonce; identical inputs must produce
			// different signatures on each call.
			name:    "ecdsa_is_randomized_different_signatures_per_call",
			token:   newToken(),
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				tok2 := newToken()
				if err := s.Mint(tok2); err != nil {
					t.Fatalf("second Mint failed: %v", err)
				}
				if bytes.Equal(tok.Signature, tok2.Signature) {
					t.Error("expected different signatures for same input (ECDSA must be randomized)")
				}
			},
		},
		{
			name: "invalid_header_alg_rejected",
			token: &Token{
				Header: Header{Alg: "RS256", Typ: TokenType},
				Claims: baseClaims,
			},
			wantErr:   true,
			errSubstr: "invalid token header",
		},
		{
			name: "invalid_header_alg_none_rejected",
			token: &Token{
				Header: Header{Alg: "none", Typ: TokenType},
				Claims: baseClaims,
			},
			wantErr:   true,
			errSubstr: "invalid token header",
		},
		{
			name: "missing_issuer_rejected",
			token: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := baseClaims
					c.Issuer = ""
					return c
				}(),
			},
			wantErr:   true,
			errSubstr: "invalid token claims",
		},
		{
			name: "missing_subject_rejected",
			token: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := baseClaims
					c.Subject = ""
					return c
				}(),
			},
			wantErr:   true,
			errSubstr: "invalid token claims",
		},
		{
			name: "missing_expiry_rejected",
			token: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := baseClaims
					c.Expires = 0
					return c
				}(),
			},
			wantErr:   true,
			errSubstr: "invalid token claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Mint(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
			if tt.check != nil {
				tt.check(t, tt.token)
			}
		})
	}
}
