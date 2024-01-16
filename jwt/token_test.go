package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var issuer, subject, audience string = "shaw.com", "erebor_abf7c176-3f3b-4226-98de-a9a6f00e3a6c", "api.ran.com"

func TestCreateSignature(t *testing.T) {

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

	jwt1 := JwtToken{Header: header, Claims: claims1}
	signer.MintJwt(&jwt1)
	t.Log(jwt1.Token)

	claims2 := JwtClaims{
		"3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		issuer,
		subject,
		audience,
		1704992428,
		1704992428,
		1704996028,
		nil,
	}

	jwt2 := JwtToken{Header: header, Claims: claims2}
	signer.MintJwt(&jwt2)

	claims3 := JwtClaims{
		"not-the-same-person",
		issuer,
		subject,
		audience,
		1704992428,
		1704992428,
		1704996028,
		nil,
	}

	jwt3 := JwtToken{Header: header, Claims: claims3}
	signer.MintJwt(&jwt3)

}
