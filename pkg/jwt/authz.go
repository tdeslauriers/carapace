package jwt

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// S2sUnauthorizedErrMsg is a generalized error message retruned when a service-to-service token is unauthorized.
	// This could be for many reasons, which will be included in logs.  This exists so that it can be returned to clients
	// and and logic/decisioning can be based upon it.
	S2sUnauthorizedErrMsg = "failed to validate s2s token"

	// UserUnauthorizedErrMsg is a generalized error message retruned when a service-to-service token is unauthorized.
	// This could be for many reasons, which will be included in logs.  This exists so that it can be returned to clients
	// and and logic/decisioning can be based upon it.
	UserUnauthorizedErrMsg = "failed to validate user token"
)

// Verifying Signatures
type JwtVerifier interface {
	VerifyJwtSignature(msg string, sig []byte) error
	BuildJwtFromToken(token string) (*JwtToken, error) // validates signature
	IsAuthorized(allowedScopes []string, token string) (bool, error)
}

func NewJwtVerifier(svcName string, pubKey *ecdsa.PublicKey) JwtVerifier {
	return &jwtVerifier{
		ServiceName: svcName,
		PublicKey:   pubKey,
	}
}

var _ JwtVerifier = (*jwtVerifier)(nil)

type jwtVerifier struct {
	ServiceName string
	PublicKey   *ecdsa.PublicKey
}

func (v *jwtVerifier) VerifyJwtSignature(msg string, sig []byte) error {

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

// includes signature validation
func (v *jwtVerifier) BuildJwtFromToken(token string) (*JwtToken, error) {

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
		return nil, err
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

// check for "Bearer " and snips if present
func (v *jwtVerifier) IsAuthorized(allowedScopes []string, token string) (bool, error) {

	token = strings.TrimPrefix(token, "Bearer ")

	// includes signature validation:  will error if invalid
	jwt, err := v.BuildJwtFromToken(token)
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
		return false, fmt.Errorf("unauthorized: not intended audience")
	}

	// check scopes
	if v.hasValidScopes(allowedScopes, jwt) {
		return true, nil
	} else {
		return false, fmt.Errorf("unauthorized: incorrect or missing scopes")
	}
}

func (v *jwtVerifier) hasValidAudences(jwt *JwtToken) bool {

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
func (v *jwtVerifier) hasValidScopes(allowedScopes []string, jwt *JwtToken) bool {

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
