package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var issuer, subject string = "api.ran.com", "erebor_abf7c176-3f3b-4226-98de-a9a6f00e3a6c"
var audience = []string{"shaw"}

func TestJwtSignatures(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Log("Private key gen failed: ", err)
	}
	signer := NewJwtSigner(privateKey)

	header := JwtHeader{ES512, TokenType}

	issuedAt := time.Now()

	claims1 := JwtClaims{
		"3bb72d75-dcfa-400a-a78e-5a4ecd0d3f09",
		issuer,
		subject,
		audience,
		issuedAt.Unix(),
		issuedAt.Unix(),
		issuedAt.Add(5 * time.Minute).Unix(),
		"r:shaw:* r:otherservice:* w:otherservice:*",
	}

	jwt := JwtToken{Header: header, Claims: claims1}
	signer.MintJwt(&jwt)

	verifier := jwtVerifier{"shaw", &privateKey.PublicKey}
	segments := strings.Split(jwt.Token, ".")
	msg := segments[0] + "." + segments[1]
	sig, _ := base64.URLEncoding.DecodeString(segments[2])

	if err := verifier.VerifyJwtSignature(msg, sig); err != nil {
		t.Logf("failed to verify jwt token signature: %v", err)
		t.Fail()
	}

	rebuild, err := verifier.BuildJwtFromToken(jwt.Token)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	if rebuild.Claims.Issuer != issuer ||
		rebuild.Claims.Subject != subject ||
		rebuild.Claims.Audience[0] != audience[0] {
		t.Fail()
	}

	allowed := []string{"r:shaw:*", "w:shaw:*"}
	if !verifier.hasValidScopes(allowed, rebuild) {
		t.Log("Scopes failed")
		t.Fail()
	}

	// whole enchilada
	authd, err := verifier.IsAuthorized(allowed, jwt.Token)
	if err != nil {
		t.Logf("error generated trying to validate token comprehensively: %v", err)
		t.Fail()
	}
	if !authd {
		t.Logf("Should have checked signature, built jwt, and verified scopes, and returned true, but was false.")
		t.Fail()
	}

	claims2 := JwtClaims{
		"3bb72d75-dcfa-400a-a78e-5a4ecd0d3f05",
		issuer,
		"liar-liar",
		audience,
		issuedAt.Unix(),
		issuedAt.Unix(),
		issuedAt.Add(5 * time.Minute).Unix(),
		"",
	}

	fake := JwtToken{Header: header, Claims: claims2}
	badMsg, _ := fake.SignatureBaseString()
	legitSig := jwt.Signature
	forgery := badMsg + "." + base64.URLEncoding.EncodeToString(legitSig)

	if err := verifier.VerifyJwtSignature(badMsg, legitSig); err == nil {
		t.Logf("incorrectly validated jwt w/ a tampered message, but real signature.")
		t.Fail()
	}

	_, err = verifier.BuildJwtFromToken(forgery)
	if err == nil {
		t.Log("Invalid signature means jwt should not be built")
		t.Fail()
	}

}


