package jwt

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Verifer is a an interface that performs signature verification and authorization checks on authorization tokens.
type Verifier interface {
	// VerifySignature takes in a message and signature and verifies the signature against the message
	VerifySignature(msg string, sig []byte) error

	// BuildAuthorized takes in a list of allowed scopes and a token string
	// and creates a jwt object ONLY if the token is authorized
	// by a valid signature.  Otherwise it retuns nil and an error.
	BuildAuthorized(allowedScopes []string, token string) (*Token, error)
}

// NewVerifier creates a new Verifier object with a service name and public key.
// Note: service name is provided to ensure it is in the token audiences.
func NewVerifier(svcName string, pubKey *ecdsa.PublicKey) Verifier {
	return &verifier{
		ServiceName: svcName,
		PublicKey:   pubKey,
	}
}

var _ Verifier = (*verifier)(nil)

type verifier struct {
	ServiceName string
	PublicKey   *ecdsa.PublicKey
}

// VerifySignature implements the Verifier interface.  It takes in a message and signature and verifies the signature against the message.
func (v *verifier) VerifySignature(msg string, sig []byte) error {
	return v.verifySignature(msg, sig)
}

// verifySignature takes in a message and signature and verifies the signature against the message.
func (v *verifier) verifySignature(msg string, sig []byte) error {

	// check for no msg
	if msg == "" {
		return fmt.Errorf("unauthorized: missing message")
	}

	// ES512 raw r‖s serialization is always exactly 2*Keysize bytes.
	if len(sig) != 2*Keysize {
		return fmt.Errorf("unauthorized: invalid signature length: expected %d bytes, got %d", 2*Keysize, len(sig))
	}

	// hash base signature string
	hasher := sha512.New()
	hasher.Write([]byte(msg))

	hashedMsg := hasher.Sum(nil)

	// divide signature in half to get r and s
	// 66 bit keysize was looked up for ecdsa 512
	r := big.NewInt(0).SetBytes(sig[:Keysize])
	s := big.NewInt(0).SetBytes(sig[Keysize:])

	// verify signature
	if verified := ecdsa.Verify(v.PublicKey, hashedMsg, r, s); verified {
		return nil
	}

	return fmt.Errorf("unauthorized: failed to verify jwt signature")
}

// IsAuthorized implements the Verifier interface.  In this implementation, it validates the signature,
// as well as checks the token for valid audiences, scopes, and expiration.
// It also checks for "Bearer " and snips if present
func (v *verifier) BuildAuthorized(allowedScopes []string, token string) (*Token, error) {

	trimmed := strings.TrimSpace(token)

	token = strings.TrimPrefix(trimmed, "Bearer ")

	// check for empty token
	if token == "" {
		return nil, fmt.Errorf("unauthorized: missing token")
	}

	jot, err := BuildTokenFromRaw(token)
	if err != nil {
		return nil, err
	}

	// quick input validation
	// header is correct algorithm and type
	if err := jot.Header.ValidateHeader(); err != nil {
		return nil, fmt.Errorf("unauthorized: invalid token header: %v", err)
	}

	// claims have at minimum required fields
	if err := jot.Claims.ValidateClaims(); err != nil {
		return nil, fmt.Errorf("unauthorized: invalid token claims: %v", err)
	}

	// check signature
	if err := v.verifySignature(jot.BaseString, jot.Signature); err != nil {
		return nil, err
	}

	// check issued time.
	// padding time to avoid clock sync issues.
	if time.Now().Add(2*time.Second).Unix() < jot.Claims.IssuedAt {
		return nil, fmt.Errorf("unauthorized: issued at is in the future")
	}

	// check expiry
	if time.Now().Unix() > jot.Claims.Expires {
		return nil, fmt.Errorf("unauthorized: token expired")
	}

	// check audiences
	if ok := v.hasValidAudiences(jot); !ok {
		return nil, fmt.Errorf("forbidden: incorrect audience")
	}

	// check scopes
	if ok := v.hasValidScopes(allowedScopes, jot); !ok {
		return nil, fmt.Errorf("forbidden: incorrect or missing scopes")
	}

	return jot, nil
}

// hasValidAudiences is a helper method which checks if the jwt token has the correct audience.
// It does not validate the signature of the token.
func (v *verifier) hasValidAudiences(jot *Token) bool {

	audiences := jot.Claims.MapAudiences()

	return audiences[v.ServiceName]
}

// hasValidScopes is a helper method which checks if the jwt token has the correct scopes.
// It does not validate the signature of the token.
func (v *verifier) hasValidScopes(allowedScopes []string, jot *Token) bool {

	// make sure token has scopes
	if jot.Claims.Scopes == "" {
		return false
	}

	// set jwt scopes to map
	jwtScopes := jot.Claims.MapScopes()

	// check if allowed scopes are in jwt scopes
	for _, allowed := range allowedScopes {
		if jwtScopes[allowed] {
			return true
		}
	}

	// default to false -> unauthorized
	return false
}
