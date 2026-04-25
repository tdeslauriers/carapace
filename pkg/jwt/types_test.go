package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// encodeSegment marshals v to JSON and base64-encodes it using RawURLEncoding,
// matching the encoding used by BuildBaseString and BuildTokenFromRaw.
func encodeSegment(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// makeRawToken joins three pre-encoded segments into a dot-separated JWT string.
func makeRawToken(headerSeg, claimsSeg, sigSeg string) string {
	return headerSeg + "." + claimsSeg + "." + sigSeg
}

// fixedClaims returns a Claims value with all required fields populated and
// fixed timestamps so tests that don't care about time are deterministic.
func fixedClaims() Claims {
	return Claims{
		Jti:      "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		Issuer:   "https://auth.example.com",
		Subject:  "user@example.com",
		Audience: []string{"service-a"},
		IssuedAt: 1_700_000_000,
		Expires:  1_700_003_600,
	}
}

// fakeSig is a 132-byte slice (2 × Keysize) used as a plausible but
// non-cryptographic signature in parse-only tests.
var fakeSig = func() []byte {
	b := make([]byte, 2*Keysize)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// ---- ValidateHeader --------------------------------------------------------

func TestValidateHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    Header
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid",
			header:  Header{Alg: ES512, Typ: TokenType},
			wantErr: false,
		},
		{
			name:      "alg_empty",
			header:    Header{Alg: "", Typ: TokenType},
			wantErr:   true,
			errSubstr: "alg",
		},
		{
			name:      "alg_rs256",
			header:    Header{Alg: "RS256", Typ: TokenType},
			wantErr:   true,
			errSubstr: "alg",
		},
		{
			name:      "alg_hs256",
			header:    Header{Alg: "HS256", Typ: TokenType},
			wantErr:   true,
			errSubstr: "alg",
		},
		{
			// alg:none is a well-known attack vector that must be rejected explicitly.
			name:      "alg_none",
			header:    Header{Alg: "none", Typ: TokenType},
			wantErr:   true,
			errSubstr: "alg",
		},
		{
			name:      "typ_empty",
			header:    Header{Alg: ES512, Typ: ""},
			wantErr:   true,
			errSubstr: "typ",
		},
		{
			name:      "typ_wrong_value",
			header:    Header{Alg: ES512, Typ: "JWE"},
			wantErr:   true,
			errSubstr: "typ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.header.ValidateHeader()
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

// ---- ValidateClaims --------------------------------------------------------

func TestValidateClaims(t *testing.T) {
	tests := []struct {
		name      string
		claims    Claims
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_all_required_fields",
			claims:  fixedClaims(),
			wantErr: false,
		},
		{
			// jti is optional; a valid UUID is accepted.
			name: "valid_jti_present",
			claims: func() Claims {
				c := fixedClaims()
				c.Jti = "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09"
				return c
			}(),
			wantErr: false,
		},
		{
			// jti omitempty: absent jti skips UUID validation entirely.
			name: "valid_jti_absent",
			claims: func() Claims {
				c := fixedClaims()
				c.Jti = ""
				return c
			}(),
			wantErr: false,
		},
		{
			// jti present but not a UUID must be rejected.
			name: "invalid_jti_not_uuid",
			claims: func() Claims {
				c := fixedClaims()
				c.Jti = "not-a-uuid"
				return c
			}(),
			wantErr:   true,
			errSubstr: "jti",
		},
		{
			name: "missing_issuer",
			claims: func() Claims {
				c := fixedClaims()
				c.Issuer = ""
				return c
			}(),
			wantErr:   true,
			errSubstr: "issuer",
		},
		{
			name: "missing_subject",
			claims: func() Claims {
				c := fixedClaims()
				c.Subject = ""
				return c
			}(),
			wantErr:   true,
			errSubstr: "subject",
		},
		{
			name: "missing_audience_nil",
			claims: func() Claims {
				c := fixedClaims()
				c.Audience = nil
				return c
			}(),
			wantErr:   true,
			errSubstr: "audience",
		},
		{
			name: "missing_audience_empty_slice",
			claims: func() Claims {
				c := fixedClaims()
				c.Audience = []string{}
				return c
			}(),
			wantErr:   true,
			errSubstr: "audience",
		},
		{
			name: "missing_iat",
			claims: func() Claims {
				c := fixedClaims()
				c.IssuedAt = 0
				return c
			}(),
			wantErr:   true,
			errSubstr: "issued at",
		},
		{
			name: "missing_exp",
			claims: func() Claims {
				c := fixedClaims()
				c.Expires = 0
				return c
			}(),
			wantErr:   true,
			errSubstr: "expiration",
		},
		{
			// Optional ID token fields do not affect structural validation.
			name: "valid_with_id_token_fields",
			claims: func() Claims {
				c := fixedClaims()
				c.Nonce = "abc123"
				c.Email = "user@example.com"
				c.Name = "Test User"
				c.GivenName = "Test"
				c.FamilyName = "User"
				c.Birthdate = "1990-01-01"
				return c
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.ValidateClaims()
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

// ---- MapAudiences ----------------------------------------------------------

func TestMapAudiences(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
		wantNil  bool
		wantKeys []string
	}{
		{
			name:    "nil_audience_returns_nil",
			audience: nil,
			wantNil: true,
		},
		{
			name:    "empty_audience_returns_nil",
			audience: []string{},
			wantNil: true,
		},
		{
			name:     "single_audience",
			audience: []string{"service-a"},
			wantKeys: []string{"service-a"},
		},
		{
			name:     "multiple_audiences",
			audience: []string{"service-a", "service-b", "service-c"},
			wantKeys: []string{"service-a", "service-b", "service-c"},
		},
		{
			// Duplicate values overwrite the same key; map length is one.
			name:     "duplicate_audiences_deduplicated",
			audience: []string{"service-a", "service-a"},
			wantKeys: []string{"service-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Claims{Audience: tt.audience}
			got := c.MapAudiences()

			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil map for case %q, got %v", tt.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("unexpected nil map for case %q", tt.name)
			}
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("expected %d keys, got %d: %v", len(tt.wantKeys), len(got), got)
			}
			for _, key := range tt.wantKeys {
				if !got[key] {
					t.Fatalf("expected key %q in map for case %q, got %v", key, tt.name, got)
				}
			}
		})
	}
}

// ---- MapScopes -------------------------------------------------------------

func TestMapScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   string
		wantNil  bool
		wantKeys []string
	}{
		{
			name:    "empty_string_returns_nil",
			scopes:  "",
			wantNil: true,
		},
		{
			name:    "single_space_returns_nil",
			scopes:  " ",
			wantNil: true,
		},
		{
			name:    "multiple_spaces_returns_nil",
			scopes:  "   ",
			wantNil: true,
		},
		{
			name:     "single_scope",
			scopes:   "r:service:*",
			wantKeys: []string{"r:service:*"},
		},
		{
			name:     "multiple_scopes",
			scopes:   "r:service:* w:service:*",
			wantKeys: []string{"r:service:*", "w:service:*"},
		},
		{
			// Duplicate scopes overwrite the same map key; length is one.
			name:     "duplicate_scopes_deduplicated",
			scopes:   "r:service:* r:service:*",
			wantKeys: []string{"r:service:*"},
		},
		{
			// FieldsSeq strips leading, trailing, and consecutive whitespace.
			name:     "extra_whitespace_trimmed",
			scopes:   "  r:service:*  w:other:*  ",
			wantKeys: []string{"r:service:*", "w:other:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Claims{Scopes: tt.scopes}
			got := c.MapScopes()

			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil map for case %q, got %v", tt.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("unexpected nil map for case %q", tt.name)
			}
			if len(got) != len(tt.wantKeys) {
				t.Fatalf("expected %d keys, got %d: %v", len(tt.wantKeys), len(got), got)
			}
			for _, key := range tt.wantKeys {
				if !got[key] {
					t.Fatalf("expected key %q in map for case %q, got %v", key, tt.name, got)
				}
			}
		})
	}
}

// ---- BuildBaseString -------------------------------------------------------

func TestBuildBaseString(t *testing.T) {
	baseToken := Token{
		Header: Header{Alg: ES512, Typ: TokenType},
		Claims: fixedClaims(),
	}

	tests := []struct {
		name    string
		token   Token
		wantErr bool
		check   func(t *testing.T, result string)
	}{
		{
			name:    "produces_two_dot_separated_segments",
			token:   baseToken,
			wantErr: false,
			check: func(t *testing.T, result string) {
				parts := strings.Split(result, ".")
				if len(parts) != 2 {
					t.Fatalf("expected 2 segments, got %d: %q", len(parts), result)
				}
			},
		},
		{
			// JWT spec (RFC 7515) requires RawURL base64 — no padding or standard chars.
			name:    "output_is_rawurl_encoded_no_padding",
			token:   baseToken,
			wantErr: false,
			check: func(t *testing.T, result string) {
				if strings.ContainsAny(result, "=+/") {
					t.Fatalf("output contains padding or non-URL-safe characters: %q", result)
				}
			},
		},
		{
			name:    "header_segment_decodes_to_correct_header",
			token:   baseToken,
			wantErr: false,
			check: func(t *testing.T, result string) {
				seg := strings.Split(result, ".")[0]
				decoded, err := base64.RawURLEncoding.DecodeString(seg)
				if err != nil {
					t.Fatalf("header segment is not valid RawURL base64: %v", err)
				}
				var h Header
				if err := json.Unmarshal(decoded, &h); err != nil {
					t.Fatalf("header segment does not unmarshal to Header: %v", err)
				}
				if h.Alg != ES512 || h.Typ != TokenType {
					t.Fatalf("decoded header mismatch: got %+v", h)
				}
			},
		},
		{
			name:    "claims_segment_decodes_to_correct_claims",
			token:   baseToken,
			wantErr: false,
			check: func(t *testing.T, result string) {
				seg := strings.Split(result, ".")[1]
				decoded, err := base64.RawURLEncoding.DecodeString(seg)
				if err != nil {
					t.Fatalf("claims segment is not valid RawURL base64: %v", err)
				}
				var c Claims
				if err := json.Unmarshal(decoded, &c); err != nil {
					t.Fatalf("claims segment does not unmarshal to Claims: %v", err)
				}
				fc := fixedClaims()
				if c.Issuer != fc.Issuer || c.Subject != fc.Subject {
					t.Fatalf("decoded claims mismatch: got %+v", c)
				}
			},
		},
		{
			// Fixed timestamps ensure the output is identical across calls.
			name:    "deterministic_for_same_input",
			token:   baseToken,
			wantErr: false,
			check: func(t *testing.T, result string) {
				second, err := baseToken.BuildBaseString()
				if err != nil {
					t.Fatalf("second call failed: %v", err)
				}
				if result != second {
					t.Fatalf("non-deterministic output:\n  first:  %q\n  second: %q", result, second)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.token.BuildBaseString()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// ---- BuildTokenFromRaw -----------------------------------------------------

func TestBuildTokenFromRaw(t *testing.T) {
	goodHeader := Header{Alg: ES512, Typ: TokenType}
	goodClaims := Claims{
		Jti:      "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		Issuer:   "https://auth.example.com",
		Subject:  "user@example.com",
		Audience: []string{"service-a"},
		IssuedAt: time.Now().Unix(),
		Expires:  time.Now().Add(time.Hour).Unix(),
	}

	headerSeg := encodeSegment(goodHeader)
	claimsSeg := encodeSegment(goodClaims)
	sigSeg := base64.RawURLEncoding.EncodeToString(fakeSig)
	validRaw := makeRawToken(headerSeg, claimsSeg, sigSeg)

	invalidBase64Seg := "!@#$%^&"
	invalidJSONSeg := base64.RawURLEncoding.EncodeToString([]byte("not-json"))

	tests := []struct {
		name      string
		token     string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, tok *Token)
	}{
		{
			name:    "valid_token_full_roundtrip",
			token:   validRaw,
			wantErr: false,
			check: func(t *testing.T, tok *Token) {
				if tok.Header.Alg != ES512 {
					t.Errorf("header alg: want %s, got %s", ES512, tok.Header.Alg)
				}
				if tok.Header.Typ != TokenType {
					t.Errorf("header typ: want %s, got %s", TokenType, tok.Header.Typ)
				}
				if tok.Claims.Issuer != goodClaims.Issuer {
					t.Errorf("issuer: want %q, got %q", goodClaims.Issuer, tok.Claims.Issuer)
				}
				if tok.Claims.Subject != goodClaims.Subject {
					t.Errorf("subject: want %q, got %q", goodClaims.Subject, tok.Claims.Subject)
				}
				if tok.Raw != validRaw {
					t.Errorf("Raw does not match input token")
				}
				if tok.BaseString != headerSeg+"."+claimsSeg {
					t.Errorf("BaseString does not match first two segments")
				}
				if len(tok.Signature) != len(fakeSig) {
					t.Errorf("signature length: want %d, got %d", len(fakeSig), len(tok.Signature))
				}
			},
		},
		{
			name:      "token_too_short",
			token:     strings.Repeat("a", 15),
			wantErr:   true,
			errSubstr: "16 characters",
		},
		{
			name:      "token_too_long",
			token:     strings.Repeat("a", 4097),
			wantErr:   true,
			errSubstr: "4096 characters",
		},
		{
			name:      "two_segments_rejected",
			token:     headerSeg + "." + claimsSeg,
			wantErr:   true,
			errSubstr: "3 segments",
		},
		{
			name:      "four_segments_rejected",
			token:     headerSeg + "." + claimsSeg + "." + sigSeg + ".extra",
			wantErr:   true,
			errSubstr: "3 segments",
		},
		{
			name:      "invalid_base64_in_header",
			token:     makeRawToken(invalidBase64Seg, claimsSeg, sigSeg),
			wantErr:   true,
			errSubstr: "failed to base64 decode jwt header",
		},
		{
			name:      "invalid_json_in_header",
			token:     makeRawToken(invalidJSONSeg, claimsSeg, sigSeg),
			wantErr:   true,
			errSubstr: "failed to unmarshal json to jwt header",
		},
		{
			name:      "invalid_base64_in_claims",
			token:     makeRawToken(headerSeg, invalidBase64Seg, sigSeg),
			wantErr:   true,
			errSubstr: "failed to base64 decode jwt claims",
		},
		{
			name:      "invalid_json_in_claims",
			token:     makeRawToken(headerSeg, invalidJSONSeg, sigSeg),
			wantErr:   true,
			errSubstr: "failed to unmarshal json to jwt claims",
		},
		{
			name:      "invalid_base64_in_signature",
			token:     makeRawToken(headerSeg, claimsSeg, invalidBase64Seg),
			wantErr:   true,
			errSubstr: "failed to decode signature from token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := BuildTokenFromRaw(tt.token)
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

// ---- BuildAudiences --------------------------------------------------------

func TestBuildAudiences(t *testing.T) {
	tests := []struct {
		name   string
		scopes string
		want   []string
	}{
		{
			name:   "empty_string_returns_nil",
			scopes: "",
			want:   nil,
		},
		{
			name:   "whitespace_only_returns_nil",
			scopes: "   ",
			want:   nil,
		},
		{
			name:   "single_scope_one_service",
			scopes: "w:service-a:*",
			want:   []string{"service-a"},
		},
		{
			name:   "multiple_scopes_different_services",
			scopes: "w:service-a:* r:service-b:*",
			want:   []string{"service-a", "service-b"},
		},
		{
			// Read and write scopes for the same service produce one audience entry.
			name:   "duplicate_service_deduplicated",
			scopes: "w:service-a:* r:service-a:*",
			want:   []string{"service-a"},
		},
		{
			// First appearance order is preserved; the duplicate is ignored.
			name:   "preserves_first_appearance_order",
			scopes: "w:service-a:* r:service-b:* w:service-a:*",
			want:   []string{"service-a", "service-b"},
		},
		{
			// A scope with no colon has fewer than 2 parts and must be skipped.
			name:   "malformed_scope_no_colon_skipped",
			scopes: "invalid",
			want:   nil,
		},
		{
			// An empty service name (w::*) must be skipped.
			name:   "scope_with_empty_service_skipped",
			scopes: "w::*",
			want:   nil,
		},
		{
			// Valid scopes are extracted; malformed ones are silently skipped.
			name:   "mixed_valid_and_malformed",
			scopes: "invalid w:service-a:* w::*",
			want:   []string{"service-a"},
		},
		{
			// FieldsSeq handles extra surrounding and internal whitespace.
			name:   "extra_whitespace_handled",
			scopes: "  w:service-a:*  r:service-b:*  ",
			want:   []string{"service-a", "service-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildAudiences(tt.scopes)

			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil for case %q, got %v", tt.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("unexpected nil for case %q", tt.name)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			for i, v := range tt.want {
				if got[i] != v {
					t.Fatalf("index %d: expected %q, got %q", i, v, got[i])
				}
			}
		})
	}
}
