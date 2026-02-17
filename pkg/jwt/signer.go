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
func (signer *signer) createSignature(msg string, jwt *Token) error {

	// hash to sha512
	hasher := sha512.New()
	hasher.Write([]byte(msg))
	hashedMsg := hasher.Sum(nil)

	// sign with ecdsa 512 priv key
	if r, s, err := ecdsa.Sign(rand.Reader, signer.PrivateKey, hashedMsg); err == nil {

		// validate length in bits
		curveBytes := signer.PrivateKey.Curve.Params().BitSize
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

// Mint implements the Signer interface and creates, appends a cryptographic signature to the jwt Token.Signature field.
// It also creates, appends the base64 encoded token to the jwt Token struct
// Mint assumes the jwt Token.Header and jwt Token.Claims fields are already populated
func (signer *signer) Mint(jwt *Token) error {

	msg, err := jwt.BuildBaseString()
	if err != nil {
		return fmt.Errorf("failed to create jwt signature base string(message): %v", err)
	}
	jwt.BaseString = msg

	if err := signer.createSignature(msg, jwt); err != nil {
		return fmt.Errorf("failed to create jwt signature: %v", err)
	}
	sig := base64.URLEncoding.EncodeToString(jwt.Signature)

	jwt.Token = msg + "." + sig

	return nil
}
