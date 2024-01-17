package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

var issuer, subject, audience string = "shaw.com", "erebor_abf7c176-3f3b-4226-98de-a9a6f00e3a6c", "api.ran.com"

func TestJwtSignatures(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Log("Private key gen failed: ", err)
	}
	signer := JwtSignerService{privateKey}

	header := JwtHeader{ES512, TokenType}

	claims1 := JwtClaims{
		"3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		issuer,
		subject,
		audience,
		1704992428,
		1704992428,
		1704996028,
		nil,
	}

	jwt := JwtToken{Header: header, Claims: claims1}
	signer.MintJwt(&jwt)

	verifier := JwtVerifierService{&privateKey.PublicKey}
	if err := verifier.VerifyJwtSignature(jwt.Token); err != nil {
		t.Logf("failed to verify jwt token signature: %v", err)
		t.Fail()
	}

	claims2 := JwtClaims{
		"3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
		issuer,
		"liar-liar",
		audience,
		1704992428,
		1704992428,
		1704996028,
		nil,
	}

	fake := JwtToken{Header: header, Claims: claims2}
	badMsg, _ := fake.SignatureBaseString()
	legitSig := base64.URLEncoding.EncodeToString(jwt.Signature)

	forgery := badMsg + "." + legitSig
	if err := verifier.VerifyJwtSignature(forgery); err == nil {
		t.Logf("incorrectly validated jwt w/ a tampered message, but real signature.")
		t.Fail()
	}

}
