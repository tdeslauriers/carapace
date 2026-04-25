package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Signer is an interface that signs or "mints" signtures for authorization tokens.
type Signer interface {

	// Mint takes in a pointer to the jwt struct and creates, then appends the
	// cryptographic signature and base64 token values to the Token struct
	// Mint assumes the jwt Token.Header and jwt Token.Claims fields are already populated
	Mint(*Token) error
}

func NewSigner(priv *ecdsa.PrivateKey) Signer {
	return &signer{
		PrivateKey: priv,
	}
}

var _ Signer = (*signer)(nil)

type signer struct {
	PrivateKey *ecdsa.PrivateKey
}

// createSignature takes the BaseString (msg) comprised of
// the base64 encoded json header + . + claims of the jwt token
// creates a cryptographic signature for the jwt token and adds it to the jwt Token struct
func (sgn *signer) createSignature(msg string, jwt *Token) error {

	// check for empty message
	if msg == "" {
		return fmt.Errorf("failed to create jwt signature: missing message")
	}

	// quick input validation of header and claims
	if err := jwt.Header.ValidateHeader(); err != nil {
		return fmt.Errorf("failed to create jwt signature: invalid token header: %w", err)
	}

	if err := jwt.Claims.ValidateClaims(); err != nil {
		return fmt.Errorf("failed to create jwt signature: invalid token claims: %w", err)
	}

	// hash to sha512
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashedMsg := hasher.Sum(nil)

	// sign with ecdsa 512 priv key
	r, s, err := ecdsa.Sign(rand.Reader, sgn.PrivateKey, hashedMsg)
	if err != nil {
		return fmt.Errorf("failed to sign jwt token msg: %w", err)
	}

	// validate length in bits
	curveBytes := sgn.PrivateKey.Curve.Params().BitSize
	keyBytes := curveBytes / 8
	if curveBytes%8 > 0 {
		keyBytes++
	}

	// serialize r and s
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[0:keyBytes])
	s.FillBytes(out[keyBytes:])

	jwt.Signature = out

	return nil

}

// Mint implements the Signer interface and creates, appends a cryptographic signature to the jwt Token.Signature field.
// It also creates, appends the base64 encoded token to the jwt Token struct
// Mint assumes the jwt Token.Header and jwt Token.Claims fields are already populated
func (sgn *signer) Mint(jwt *Token) error {

	msg, err := jwt.BuildBaseString()
	if err != nil {
		return fmt.Errorf("failed to create jwt signature base string(message): %w", err)
	}
	jwt.BaseString = msg

	if err := sgn.createSignature(msg, jwt); err != nil {
		return fmt.Errorf("failed to create jwt signature: %w", err)
	}
	sig := base64.RawURLEncoding.EncodeToString(jwt.Signature)

	jwt.Raw = msg + "." + sig

	return nil
}
