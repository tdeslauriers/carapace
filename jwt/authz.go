package jwt

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Verifying Signatures
type JwtVerifier interface {
	VerifyJwtSignature(msg string, sig []byte) error
	BuildJwtFromToken(token string) (*JwtToken, error)         // requires valid signature
	HasValidScopes(allowedScopes []string, jwt *JwtToken) bool // assumes token has been verified
	IsAuthorized(allowedScopes []string, token string) (bool, error)
}

type JwtVerifierService struct {
	PublicKey *ecdsa.PublicKey
}

func (v *JwtVerifierService) VerifyJwtSignature(msg string, sig []byte) error {

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

	return fmt.Errorf("unable to verify jwt signature")
}

// includes signature validation
func (v *JwtVerifierService) BuildJwtFromToken(token string) (*JwtToken, error) {

	segments := strings.Split(token, ".")
	if len(segments) > 3 {
		return nil, fmt.Errorf("jwt token not properly formatted")
	}

	// base signature string
	msg := segments[0] + "." + segments[1]

	// decode signature from base64
	sig, err := base64.URLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, fmt.Errorf("unable to decode signature from token: %v", err)
	}

	// verify signature
	if err := v.VerifyJwtSignature(msg, sig); err != nil {
		return nil, fmt.Errorf("unable to build jwt from token: %v", err)
	}

	// parse header
	var header JwtHeader
	decodedHead, err := base64.URLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("unable to build jwt header from token: %v", err)
	}
	err = json.Unmarshal(decodedHead, &header)
	if err != nil {
		return nil, fmt.Errorf("unable to build jwt header from token: %v", err)
	}

	// parse claims
	var claims JwtClaims
	decodedClaims, err := base64.URLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("unable to build jwt claims from token: %v", err)
	}
	err = json.Unmarshal(decodedClaims, &claims)
	if err != nil {
		return nil, fmt.Errorf("unable to build jwt claims from token: %v", err)
	}

	return &JwtToken{header, claims, sig, token}, nil
}

// assumes verified jwt
func (v *JwtVerifierService) HasValidScopes(allowedScopes []string, jwt *JwtToken) bool {

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

func (v *JwtVerifierService) IsAuthorized(allowedScopes []string, token string) (bool, error) {

	// includes signature validation
	jwt, err := v.BuildJwtFromToken(token)
	if err != nil {
		return false, err
	}

	if v.HasValidScopes(allowedScopes, jwt) {
		return true, nil
	} else {
		return false, fmt.Errorf("unauthorized")
	}
}
