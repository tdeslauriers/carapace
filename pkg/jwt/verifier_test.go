package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// testVerifierSetup generates a key pair and returns a signer and a verifier
// scoped to svcName. Fails the test immediately if key generation fails.
func testVerifierSetup(t *testing.T, svcName string) (Signer, Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return NewSigner(privKey), NewVerifier(svcName, &privKey.PublicKey), privKey
}

// mintRaw signs a Token and returns its Raw string, failing the test on error.
func mintRaw(t *testing.T, s Signer, tok *Token) string {
	t.Helper()
	if err := s.Mint(tok); err != nil {
		t.Fatalf("test setup: Mint failed: %v", err)
	}
	return tok.Raw
}

// ---- VerifySignature -------------------------------------------------------

func TestVerifySignature(t *testing.T) {
	s, v, _ := testVerifierSetup(t, "service-a")

	// wrongV uses a different public key so valid signatures will fail.
	_, wrongV, _ := testVerifierSetup(t, "service-a")

	tok := &Token{
		Header: Header{Alg: ES512, Typ: TokenType},
		Claims: Claims{
			Issuer:   "https://auth.example.com",
			Subject:  "user@example.com",
			Audience: []string{"service-a"},
			IssuedAt: time.Now().Unix(),
			Expires:  time.Now().Add(time.Hour).Unix(),
		},
	}
	mintRaw(t, s, tok)

	tests := []struct {
		name      string
		v         Verifier
		msg       string
		sig       []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_signature",
			v:       v,
			msg:     tok.BaseString,
			sig:     tok.Signature,
			wantErr: false,
		},
		{
			name:      "empty_message",
			v:         v,
			msg:       "",
			sig:       tok.Signature,
			wantErr:   true,
			errSubstr: "missing message",
		},
		{
			name:      "nil_signature",
			v:         v,
			msg:       tok.BaseString,
			sig:       nil,
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			name:      "empty_signature",
			v:         v,
			msg:       tok.BaseString,
			sig:       []byte{},
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			// One byte short of the r component alone — should panic without the guard.
			name:      "short_signature_keysize_minus_one",
			v:         v,
			msg:       tok.BaseString,
			sig:       tok.Signature[:Keysize-1],
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			// Exactly one component (r only, missing s) — half the required length.
			name:      "short_signature_exactly_one_keysize",
			v:         v,
			msg:       tok.BaseString,
			sig:       tok.Signature[:Keysize],
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			name:      "long_signature_one_extra_byte",
			v:         v,
			msg:       tok.BaseString,
			sig:       append(append([]byte{}, tok.Signature...), 0x00),
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			name:      "tampered_message",
			v:         v,
			msg:       tok.BaseString + "X",
			sig:       tok.Signature,
			wantErr:   true,
			errSubstr: "failed to verify jwt signature",
		},
		{
			name:      "wrong_signing_key",
			v:         wrongV,
			msg:       tok.BaseString,
			sig:       tok.Signature,
			wantErr:   true,
			errSubstr: "failed to verify jwt signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.v.VerifySignature(tt.msg, tt.sig)
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
		})
	}
}

// ---- BuildAuthorized -------------------------------------------------------

func TestBuildAuthorized(t *testing.T) {
	const svcName = "service-a"

	s, v, _ := testVerifierSetup(t, svcName)

	allowedScopes := []string{"r:service-a:*", "w:service-a:*"}

	now := time.Now().UTC()

	validClaims := Claims{
		Jti:      "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		Issuer:   "https://auth.example.com",
		Subject:  "user@example.com",
		Audience: []string{svcName},
		IssuedAt: now.Unix(),
		Expires:  now.Add(time.Hour).Unix(),
		Scopes:   "r:service-a:* w:service-a:*",
	}

	validRaw := mintRaw(t, s, &Token{
		Header: Header{Alg: ES512, Typ: TokenType},
		Claims: validClaims,
	})

	// tamperedRaw: valid signature from token A paired with different claims from
	// token B, simulating an attacker swapping the payload while keeping a stolen sig.
	altClaims := validClaims
	altClaims.Subject = "attacker@evil.com"
	tokB := &Token{Header: Header{Alg: ES512, Typ: TokenType}, Claims: altClaims}
	mintRaw(t, s, tokB)
	validParts := strings.Split(validRaw, ".")
	tamperedRaw := tokB.BaseString + "." + validParts[2]

	// wrongAlgRaw: manually constructed token with RS256 in the header.
	wrongAlgRaw := makeRawToken(
		encodeSegment(Header{Alg: "RS256", Typ: TokenType}),
		encodeSegment(validClaims),
		base64.RawURLEncoding.EncodeToString(fakeSig),
	)

	// noIssuerRaw: constructed manually because Mint now validates and would
	// reject an empty Issuer. ValidateClaims fires in BuildAuthorized before
	// signature verification, so the fake signature is never reached.
	noIssuerClaims := validClaims
	noIssuerClaims.Issuer = ""
	noIssuerRaw := makeRawToken(
		encodeSegment(Header{Alg: ES512, Typ: TokenType}),
		encodeSegment(noIssuerClaims),
		base64.RawURLEncoding.EncodeToString(fakeSig),
	)

	tests := []struct {
		name      string
		token     string
		scopes    []string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, tok *Token)
	}{
		{
			name:    "valid_token",
			token:   validRaw,
			scopes:  allowedScopes,
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if tok.Claims.Subject != validClaims.Subject {
					t.Errorf("subject: want %q, got %q", validClaims.Subject, tok.Claims.Subject)
				}
			},
		},
		{
			// "Bearer " prefix must be stripped before parsing.
			name:    "bearer_prefix_stripped",
			token:   "Bearer " + validRaw,
			scopes:  allowedScopes,
			wantErr: false,
		},
		{
			// Leading/trailing whitespace plus Bearer prefix both stripped.
			name:    "whitespace_and_bearer_prefix_stripped",
			token:   "  Bearer " + validRaw + "  ",
			scopes:  allowedScopes,
			wantErr: false,
		},
		{
			name:      "empty_token",
			token:     "",
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "missing token",
		},
		{
			name:      "whitespace_only_token",
			token:     "   ",
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "missing token",
		},
		{
			// Two segments — long enough to pass the length guard but wrong structure.
			name:      "malformed_token_two_segments",
			token:     strings.Repeat("a", 9) + "." + strings.Repeat("b", 9),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "3 segments",
		},
		{
			// Four segments — ditto.
			name:      "malformed_token_four_segments",
			token:     strings.Repeat("a", 5) + "." + strings.Repeat("b", 5) + "." + strings.Repeat("c", 5) + "." + strings.Repeat("d", 5),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "3 segments",
		},
		{
			// alg:none and other non-ES512 algorithms must be rejected before
			// any cryptographic operations are attempted.
			name:      "wrong_alg_in_header",
			token:     wrongAlgRaw,
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "invalid token header",
		},
		{
			// Claims structural validation fires before signature verification.
			name:      "missing_required_claim_issuer",
			token:     noIssuerRaw,
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "invalid token claims",
		},
		{
			name:      "expired_token",
			token: mintRaw(t, s, &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := validClaims
					c.IssuedAt = now.Add(-2 * time.Hour).Unix()
					c.Expires = now.Add(-1 * time.Hour).Unix()
					return c
				}(),
			}),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "token expired",
		},
		{
			name: "issued_at_in_future",
			token: mintRaw(t, s, &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := validClaims
					c.IssuedAt = now.Add(10 * time.Minute).Unix()
					c.Expires = now.Add(70 * time.Minute).Unix()
					return c
				}(),
			}),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "issued at is in the future",
		},
		{
			name: "wrong_audience",
			token: mintRaw(t, s, &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := validClaims
					c.Audience = []string{"different-service"}
					return c
				}(),
			}),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "incorrect audience",
		},
		{
			name: "no_matching_scopes",
			token: mintRaw(t, s, &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := validClaims
					c.Scopes = "r:other-service:*"
					return c
				}(),
			}),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "incorrect or missing scopes",
		},
		{
			name: "empty_scopes_in_token",
			token: mintRaw(t, s, &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: func() Claims {
					c := validClaims
					c.Scopes = ""
					return c
				}(),
			}),
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "incorrect or missing scopes",
		},
		{
			// Token B's claims paired with token A's signature must fail
			// signature verification, demonstrating tamper detection.
			name:      "tampered_claims_with_stolen_signature",
			token:     tamperedRaw,
			scopes:    allowedScopes,
			wantErr:   true,
			errSubstr: "failed to verify jwt signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := v.BuildAuthorized(tt.scopes, tt.token)
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
				tt.check(t, tok)
			}
		})
	}
}
