package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
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

// ValidateHeader checks that the jwt header fields match the expected algorithm and token type.
// It rejects any algorithm other than ES512, including "none", which is an exploit vector.
func (h *Header) ValidateHeader() error {
	if h.Alg != ES512 {
		return fmt.Errorf("invalid jwt header: alg must be %s, got %q", ES512, h.Alg)
	}
	if h.Typ != TokenType {
		return fmt.Errorf("invalid jwt header: typ must be %s, got %q", TokenType, h.Typ)
	}
	return nil
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

// ValidateClaims checks that required claims fields are present and well-formed.
// Time-based checks (expiry, not-before) and semantic checks (audience match, scope match)
// are the responsibility of the Verifier.
func (c *Claims) ValidateClaims() error {

	if c.Issuer == "" {
		return fmt.Errorf("invalid jwt claims: issuer (iss) is required")
	}

	if c.Subject == "" {
		return fmt.Errorf("invalid jwt claims: subject (sub) is required")
	}

	if len(c.Audience) == 0 {
		return fmt.Errorf("invalid jwt claims: audience (aud) is required")
	}

	if c.IssuedAt == 0 {
		return fmt.Errorf("invalid jwt claims: issued at (iat) is required")
	}

	if c.Expires == 0 {
		return fmt.Errorf("invalid jwt claims: expiration (exp) is required")
	}

	if c.Jti != "" {
		if err := validate.ValidateUuid(c.Jti); err != nil {
			return fmt.Errorf("invalid jwt claims: jti must be a valid uuid: %w", err)
		}
	}

	return nil
}

// MapAudiences is a convenience method that creates a map of audiences from the claims for easy lookup.
func (c *Claims) MapAudiences() map[string]bool {

	if len(c.Audience) == 0 {
		return nil
	}

	audMap := make(map[string]bool, len(c.Audience))
	for _, aud := range c.Audience {
		audMap[aud] = true
	}

	return audMap
}

// MapScopes is a convenience method that creates a map of scopes from the claims for easy lookup.
func (c *Claims) MapScopes() map[string]bool {

	var scopeMap map[string]bool
	for scope := range strings.FieldsSeq(c.Scopes) {

		if scopeMap == nil {

			scopeMap = make(map[string]bool)
		}

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
	Raw        string // base 64 encoded token header.claims.signature
}

// BuildBaseString  is a helper funciton that returns a base64 encoded string of the jwt header and claims.
// Expectation is that this can/would be used to create a signature.
func (jwt *Token) BuildBaseString() (string, error) {

	// header to json -> base64
	jsonHeader, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt header to json: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)

	// claims to json -> base64
	jsonClaims, err := json.Marshal(jwt.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt claims to json: %w", err)
	}
	encodedClaims := base64.RawURLEncoding.EncodeToString(jsonClaims)

	// chunks := [2]string{encodedHeader, encodedClaims}
	// return strings.Join(chunks[:], "."), nil
	return encodedHeader + "." + encodedClaims, nil
}

// BuildTokenFromRaw is a helper function that takes a jwt token string, decodes it, and returns a jwt Token struct.
// NOTE: signature (and other data/fields) is NOT verified in this function: builder/decoder only.
func BuildTokenFromRaw(token string) (*Token, error) {

	// light weight validation
	if len(token) < 16 || len(token) > 4096 { // larger than a typical token or a cookie can store
		return nil, fmt.Errorf("token must be greater than 16 characters and less than 4096 characters")
	}

	// split token into segments
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("jwt token not properly formatted into 3 segments separated by '.'")
	}

	// parse header
	var header Header
	decodedHead, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode jwt header segment from token string: %v", err)
	}
	err = json.Unmarshal(decodedHead, &header)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to jwt header from token string: %v", err)
	}

	// parse claims
	var claims Claims
	decodedClaims, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode jwt claims segment from token string: %v", err)
	}
	err = json.Unmarshal(decodedClaims, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to jwt claims from token string: %v", err)
	}

	// decode signature from base64
	sig, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature from token: %v", err)
	}

	return &Token{
		Header:     header,
		Claims:     claims,
		BaseString: segments[0] + "." + segments[1],
		Signature:  sig,
		Raw:        token}, nil
}

// BuildAudiences is a helper func to build audience []string from a string of space-delimited scope string values, eg., "w:service:* r:service:*"
func BuildAudiences(scopes string) (audiences []string) {

	uniqueServices := make(map[string]struct{})

	for scope := range strings.FieldsSeq(scopes) {

		chunks := strings.SplitN(scope, ":", 3)
		if len(chunks) < 2 || chunks[1] == "" {
			continue
		}

		svc := chunks[1]
		if _, ok := uniqueServices[svc]; !ok {

			uniqueServices[svc] = struct{}{}
			audiences = append(audiences, svc)
		}
	}

	return
}
