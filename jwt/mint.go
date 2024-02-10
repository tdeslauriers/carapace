package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

const ES512 string = "ES512" // alg
const TokenType string = "JWT"
const Keysize int = 66 // ecdsa 512 spec

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JwtClaims struct {
	Jti       string   `json:"jti"` // jwt unique identifier / uuid
	Issuer    string   `json:"iss"` // url of issuing service
	Subject   string   `json:"sub"` // email or user/client uuid
	Audience  []string `json:"aud"` // intended recipient(s) -> restricted service
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Expires   int64    `json:"exp"`
	Scopes    string   `json:"scp,omitempty"` // OAuth2: not array, space delimited string: "r:service* w:othersevice:*"
}

type JwtToken struct {
	Header    JwtHeader
	Claims    JwtClaims
	Signature []byte
	Token     string // base 64 encoded token header.claims.signature
}

func (jwt *JwtToken) SignatureBaseString() (string, error) {

	// header to json -> base64
	jsonHeader, err := json.Marshal(jwt.Header)
	if err != nil {
		log.Panic("failed to marshal jwt header to json.")
	}
	encodedHeader := base64.URLEncoding.EncodeToString(jsonHeader)

	// claims to json -> base64
	jsonClaims, err := json.Marshal(jwt.Claims)
	if err != nil {
		log.Panic("failed to marshal jwt claims to json.")
	}
	encodedClaims := base64.URLEncoding.EncodeToString(jsonClaims)

	// chunks := [2]string{encodedHeader, encodedClaims}
	// return strings.Join(chunks[:], "."), nil
	return encodedHeader + "." + encodedClaims, nil
}

// Signing
type JwtSigner interface {
	CreateJwtSignature(*JwtToken) error
	MintJwt(*JwtToken) error
}

type JwtSignerService struct {
	PrivateKey *ecdsa.PrivateKey
}

// adds signature to a jwt
func (sign *JwtSignerService) CreateJwtSignature(jwt *JwtToken) error {

	msg, err := jwt.SignatureBaseString()
	if err != nil {
		return err
	}

	// hash to sha512
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashedMsg := hasher.Sum(nil)

	// sign with ecdsa 512 priv key
	if r, s, err := ecdsa.Sign(rand.Reader, sign.PrivateKey, hashedMsg); err == nil {

		// validate length in bits
		curveBytes := sign.PrivateKey.Curve.Params().BitSize
		keyBytes := curveBytes / 8
		if curveBytes%8 > 0 {
			keyBytes += 1
		}

		// serialize r and s
		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes])
		s.FillBytes(out[keyBytes:])

		jwt.Signature = out
		return nil
	} else {
		return err
	}
}

func (sign *JwtSignerService) MintJwt(jwt *JwtToken) error {

	msg, err := jwt.SignatureBaseString()
	if err != nil {
		return fmt.Errorf("unable to create jwt signature base string(message): %v", err)
	}

	if err := sign.CreateJwtSignature(jwt); err != nil {
		return fmt.Errorf("unable to create jwt signature: %v", err)
	}
	sig := base64.URLEncoding.EncodeToString(jwt.Signature)

	jwt.Token = msg + "." + sig

	return nil
}
