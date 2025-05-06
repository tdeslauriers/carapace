package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (

	// S2sUnauthorizedErrMsg is a generalized error message retruned when a service-to-service token is unauthorized.
	S2sUnauthorizedErrMsg = "failed to validate s2s access token"

	// S2sForbiddenErrMsg is a generalized error message returned when a service-to-service token is unauthorized.
	S2sForbiddenErrMsg = "forbidden: s2s access token does not contain either the correct audience, the correct scopes, or both"

	// UserUnauthorizedErrMsg is a generalized error message retruned when a service-to-service token is unauthorized.
	UserUnauthorizedErrMsg = "failed to validate user access token"

	// UserForbdiddenErrMsg is a generalized error message returned when a user token is unauthorized.
	UserForbdiddenErrMsg = "forbidden: user access token does not contain either the correct audience, the correct scopes, or both"

)

const (
	ES512     string = "ES512" // alg
	TokenType string = "JWT"
	Keysize   int    = 66 // ecdsa 512 spec
)

// Header is the first part of a jwt incluiding the signing algorithm and token type
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims is the second part of a jwt including the issuer, subject, audience, issued at, not before, and expiration
// Scopes is a space delimited string of scopes
// Fields for ID Token (OICD Conncet Standard) are included, but omitted if empty
type Claims struct {
	Jti       string   `json:"jti,omitempty"` // jwt unique identifier / uuid
	Issuer    string   `json:"iss"`           // url of issuing service
	Subject   string   `json:"sub"`           // email or user/client uuid
	Audience  []string `json:"aud"`           // intended recipient(s) -> restricted service
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Expires   int64    `json:"exp"`
	Scopes    string   `json:"scp,omitempty"` // OAuth2: not array, space delimited string: "r:service* w:othersevice:*"

	// ID Token Fields
	Nonce      string `json:"nonce,omitempty"`       // random string to prevent replay attacks
	Email      string `json:"email,omitempty"`       // email address
	Name       string `json:"name,omitempty"`        // full name
	GivenName  string `json:"given_name,omitempty"`  // first name
	FamilyName string `json:"family_name,omitempty"` // last name
	Birthdate  string `json:"birthdate,omitempty"`   // date of birth
}

// MapAudiences is a convenience method that creates a map of audiences from the claims for easy lookup.
func (c *Claims) MapAudiences() map[string]bool {

	audMap := make(map[string]bool, len(c.Audience))

	for _, aud := range c.Audience {
		audMap[aud] = true
	}
	return audMap
}

// MapScopes is a convenience method that creates a map of scopes from the claims for easy lookup.
func (c *Claims) MapScopes() map[string]bool {

	scopes := strings.Split(c.Scopes, " ")

	scopeMap := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	return scopeMap
}

// Token is a struct to hold the jwt header, claims, and signature,
// it also includes the base64 encoded complete token to be used in http headers
type Token struct {
	Header     Header
	Claims     Claims
	BaseString string // first two segments of the token, base64 encoded header.claims
	Signature  []byte
	Token      string // base 64 encoded token header.claims.signature
}

// BuildBaseString  is a helper funciton that returns a base64 encoded string of the jwt header and claims.
// Expectation is that this can/would be used to create a signature.
func (jwt *Token) BuildBaseString() (string, error) {

	// header to json -> base64
	jsonHeader, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt header to json")
	}
	encodedHeader := base64.URLEncoding.EncodeToString(jsonHeader)

	// claims to json -> base64
	jsonClaims, err := json.Marshal(jwt.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt claims to json")
	}
	encodedClaims := base64.URLEncoding.EncodeToString(jsonClaims)

	// chunks := [2]string{encodedHeader, encodedClaims}
	// return strings.Join(chunks[:], "."), nil
	return encodedHeader + "." + encodedClaims, nil
}

// BuildFromToken is a helper function that takes a jwt token string, decodes it, and returns a jwt Token struct.
// NOTE: that the signature is NOT verified in this function.
func BuildFromToken(token string) (*Token, error) {

	// light weight validation
	if len(token) < 16 || len(token) > 4096 { // larger than a typical token or a cookie can store
		return nil, fmt.Errorf("token must be greater than 16 characters and less than 4096 characters")
	}

	// split token into segments
	segments := strings.Split(token, ".")
	if len(segments) < 3 || len(segments) > 3 {
		return nil, fmt.Errorf("jwt token not properly formatted into 3 segments separated by '.'")
	}

	// parse header
	var header Header
	decodedHead, err := base64.URLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode jwt header segment from token string: %v", err)
	}
	err = json.Unmarshal(decodedHead, &header)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to jwt header from token string: %v", err)
	}

	// parse claims
	var claims Claims
	decodedClaims, err := base64.URLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode jwt claims segment from token string: %v", err)
	}
	err = json.Unmarshal(decodedClaims, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to jwt claims from token string: %v", err)
	}

	// decode signature from base64
	sig, err := base64.URLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature from token: %v", err)
	}

	return &Token{
		Header:     header,
		Claims:     claims,
		BaseString: segments[0] + "." + segments[1],
		Signature:  sig,
		Token:      token}, nil
}
