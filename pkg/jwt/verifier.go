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

	// IsAuthorized takes in a list of allowed scopes and a token string and returns a boolean and error
	IsAuthorized(allowedScopes []string, token string) (bool, error)
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

	// check for no msg
	if msg == "" {
		return fmt.Errorf("unauthorized: missing message")
	}

	// check for no signature
	if len(sig) == 0 {
		return fmt.Errorf("unauthorized: missing signature")
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
func (v *verifier) IsAuthorized(allowedScopes []string, token string) (bool, error) {

	token = strings.TrimPrefix(token, "Bearer ")

	jwt, err := BuildFromToken(token)
	if err != nil {
		return false, err
	}

	// check signature
	if err := v.VerifySignature(jwt.BaseString, jwt.Signature); err != nil {
		return false, err
	}

	// check issued time.
	// padding time to avoid clock sync issues.
	if time.Now().Add(2*time.Second).Unix() < jwt.Claims.IssuedAt {
		return false, fmt.Errorf("unauthorized: issued at is in the future")
	}

	// check expiry
	if time.Now().Unix() > jwt.Claims.Expires {
		return false, fmt.Errorf("unauthorized: token expired")
	}

	// check audiences
	if ok := v.hasValidAudences(jwt); !ok {
		return false, fmt.Errorf("forbidden: incorrect audience")
	}

	// check scopes
	if v.hasValidScopes(allowedScopes, jwt) {
		return true, nil
	} else {
		return false, fmt.Errorf("forbidden: incorrect or missing scopes")
	}
}

// hasValidAudiences is a helper method which checks if the jwt token has the correct audience.
// It does not validate the signature of the token.
func (v *verifier) hasValidAudences(jwt *Token) bool {

	if len(jwt.Claims.Audience) > 0 {
		for _, aud := range jwt.Claims.Audience {
			if aud == v.ServiceName {
				return true
			}
		}
	}

	return false
}

// hasValidScopes is a helper method which checks if the jwt token has the correct scopes.
// It does not validate the signature of the token.
func (v *verifier) hasValidScopes(allowedScopes []string, jwt *Token) bool {

	// make sure token has scopes
	if jwt.Claims.Scopes == "" {
		return false
	}

	// parse scopes string to slice
	scopes := strings.Split(jwt.Claims.Scopes, " ")

	// set jwt scopes to map
	jwtScopes := make(map[string]bool)
	for _, scope := range scopes {
		jwtScopes[scope] = true
	}

	// check if allowed scopes are in jwt scopes
	for _, allowed := range allowedScopes {
		if jwtScopes[allowed] {
			return true
		}
	}

	// default to false: unauthorized
	return false
}
