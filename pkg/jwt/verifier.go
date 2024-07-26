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
	VerifySignature(msg string, sig []byte) error
	IsAuthorized(allowedScopes []string, token string) (bool, error)
}

func NewJwtVerifier(svcName string, pubKey *ecdsa.PublicKey) Verifier {
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

func (v *verifier) VerifySignature(msg string, sig []byte) error {

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

	return fmt.Errorf("unauthorized: unable to verify jwt signature")
}

// check for "Bearer " and snips if present
func (v *verifier) IsAuthorized(allowedScopes []string, token string) (bool, error) {

	token = strings.TrimPrefix(token, "Bearer ")

	// includes signature validation:  will error if invalid
	jwt, err := v.BuildFromToken(token)
	if err != nil {
		return false, err
	}

	// check issued time.
	// padding time to avoid clock sync issues.
	if time.Now().Add(2*time.Second).Unix() < jwt.Claims.IssuedAt {
		return false, fmt.Errorf("unauthorized: token valid period not yet begun")
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
		return false, fmt.Errorf("forbiddon: incorrect or missing scopes")
	}
}

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

// assumes verified jwt
func (v *verifier) hasValidScopes(allowedScopes []string, jwt *Token) bool {

	// make sure token has scopes
	if jwt.Claims.Scopes == "" {
		return false
	}

	// parse scopes string to slice
	scopes := strings.Split(jwt.Claims.Scopes, " ")

	// set jwt scopes to map
	jwtScopes := make(map[string]bool)
	for _, v := range scopes {
		jwtScopes[v] = true
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
