package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
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
	signer := NewJwtSignerService(privateKey)

	header := JwtHeader{ES512, TokenType}

	issuedAt := time.Now()
	log.Printf("token: %d", issuedAt.Unix())

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

	verifier := JwtVerifierService{"shaw", &privateKey.PublicKey}
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
	if !verifier.HasValidScopes(allowed, rebuild) {
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

func TestSig(t *testing.T) {

	privPem, err := base64.StdEncoding.DecodeString(os.Getenv("RAN_SIGNING_KEY"))
	if err != nil {
		log.Fatalf("Could not decode (base64) signing key Env var: %v", err)
	}
	privBlock, _ := pem.Decode(privPem)
	privateKey, err := x509.ParseECPrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("unable to parse x509 EC Private Key: %v", err)
	}
	verifier := &JwtVerifierService{"shaw", &privateKey.PublicKey}

	var allowed []string = []string{"r:ran:*"}

	if authorized, err := verifier.IsAuthorized(allowed, "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI4YTc4ZDAxMC0yY2NiLTQyZjUtOGZlYS00OGIxZDI3OTY5MTUiLCJpc3MiOiJyYW4iLCJzdWIiOiI4ODFmYWQ4NS0zYTFiLTQ0YTYtYmZkNC0yMGE3NWFlZWFkMDUiLCJhdWQiOlsicmFuIl0sImlhdCI6MTcwOTA1MDU2NywibmJmIjoxNzA5MDUwNTY3LCJleHAiOjE3MDkwNTExNjcsInNjcCI6InI6cmFuOioifQ==.ANaXdJticc-j9P88Ckq5RPEivXGBg7Z4sS00vywA6rKA_JEIIWLR5UeYh9ey66D2kys52lGXLMY9jmM1D39v-8ENAcLyxOwpS5K3AyaKKKebadHYgdI4xRFWpZYNe0WNhFyBKvtCBf8Hol5BM6TbwBVhUpQ9iqDlTNxOpqzQMtL_JsYQ"); !authorized {
		if err.Error() == "unauthorized" {
			log.Print(err.Error())
			t.Fail()
		} else {
			log.Printf("This is a mess: %v", err)
			t.Fail()
		}
	}
}
