package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	RealIssuer  string = "api.ran.com"
	RealSubject string = "erebor_abf7c176-3f3b-4226-98de-a9a6f00e3a6c"
)

var (
	RealAudience      = []string{"shaw"}
	RealAllowedScopes = []string{"r:shaw:*", "w:shaw:*"}
)

func TestIsAuthorized(t *testing.T) {

	issuedAt := time.Now().UTC()

	testCases := []struct {
		name  string
		jwt   *Token
		valid bool
		err   error
	}{
		{
			name: "success - valid token signature",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: nil,
		},
		{
			name: "fail - valid signature, no scopes",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "",
				},
			},

			err: errors.New("forbidden: incorrect or missing scopes"),
		},
		{
			name: "fail - valid signature, tampered base string",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   "liar-liar",
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("unauthorized: failed to verify jwt signature"),
		},
		{
			name: "fail - valid signature, expired token",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Add(-5 * time.Minute).Unix(),
					NotBefore: issuedAt.Add(-5 * time.Minute).Unix(),
					Expires:   issuedAt.Add(-1 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("unauthorized: token expired"),
		},
		{
			name: "fail - valid signature, future issued at",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Add(5 * time.Minute).Unix(),
					NotBefore: issuedAt.Add(5 * time.Minute).Unix(),
					Expires:   issuedAt.Add(10 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("unauthorized: issued at is in the future"),
		},
		{
			name: "fail - valid signature, incorrect audience",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  []string{"not-shaw"},
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("forbidden: incorrect audience"),
		},
		{
			name: "fail - valid signature, incorrect scopes",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   RealSubject,
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("forbidden: incorrect or missing scopes"),
		},
		{
			name: "fail - empty signature",
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   "empty signature",
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
			},

			err: errors.New("unauthorized: missing signature"),
		},
		{
			name: "fail - invalid signature: truncated", // trucated signature
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   "truncated signature",
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
				Signature: []byte("invalid-signature"),
			},

			err: errors.New("failed to decode signature from token:"),
		},
		{
			name: "fail - invalid signature: wrong signature", // taken from a different test case
			jwt: &Token{
				Header: Header{Alg: ES512, Typ: TokenType},
				Claims: Claims{
					Jti:       "3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
					Issuer:    RealIssuer,
					Subject:   "wrong signature",
					Audience:  RealAudience,
					IssuedAt:  issuedAt.Unix(),
					NotBefore: issuedAt.Unix(),
					Expires:   issuedAt.Add(5 * time.Minute).Unix(),
					Scopes:    "r:shaw:* r:otherservice:* w:otherservice:*",
				},
				Signature: []byte("invalid-signature"),
			},

			err: errors.New("unauthorized: failed to verify jwt signature"),
		},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Log("Private key gen failed: ", err)
	}
	signer := NewSigner(privateKey)
	verifier := NewVerifier("shaw", &privateKey.PublicKey)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := signer.Mint(tc.jwt)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("Expected error: %v, got: %v", tc.err, err)
			}

			// TEST: tampering with the base string for test name: "fail - valid signature, tampered base string"
			if tc.jwt.Claims.Subject == "liar-liar" {
				// taking the valid signature from successful test case token and adding it to the tampered base string
				tc.jwt.Token = tc.jwt.BaseString + "." + "AZ1zKzfskIJNz3lP4f-QKK2VTIP9APxbLLnwVmZcLQi7PFC_PHmDkIlVQvc0AqTiGexMXdpcbzrQ2CocOrvM5fMoACcv2N8nYDRggKgOtoVHQEPXH1nknb4_H7_ZUqpLxuimip_6Tmdsj_PQh1c3YK3rbngxIgNuewCxgHCLG4Pq93B4"
			}

			// TEST: empty signature for test name: "fail - missing signature"
			if tc.jwt.Claims.Subject == "empty signature" {
				tc.jwt.Token = tc.jwt.BaseString + "."
				tc.jwt.Signature = nil
			}

			// TEST: invalid signature for test name: "fail - invalid signature"
			if tc.jwt.Claims.Subject == "truncated signature" {
				tc.jwt.Token = tc.jwt.Token[0 : len(tc.jwt.Token)-10]
			}

			// TEST: wrong sigature: signature from a different token
			if tc.jwt.Claims.Subject == "wrong signature" {
				tc.jwt.Token = tc.jwt.BaseString + "." + "AHodklXjRKSu5Xu1_Fs5tfYm4l9IRv6l4gKAP8j1MEzmwvbWMziVl_3foJOAy5GFXBsxq7E40r9ZH9HOEP25NAvzAAai54I2twNS-DM81tbiaLpOjDwOqU4PImPcaKaoWAkLZKfm7jeFmYHqLu3o_-rcO3aHvb7CchRj8MLVXgE9UxgA"
			}

			_, err = verifier.BuildAuthorized(RealAllowedScopes, tc.jwt.Token)
			if err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
				t.Errorf("Expected error: %v, got: %v", tc.err, err)
			}
		})
	}

}
