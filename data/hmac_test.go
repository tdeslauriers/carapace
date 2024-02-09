package data

import (
	"encoding/base64"
	"testing"
)

func TestHmac(t *testing.T) {

	secret := base64.StdEncoding.EncodeToString([]byte("super-duper-secret"))
	hmac := HmacIndexer{secret}

	index, err := hmac.ObtainBlindIndex("darth.vader@empire.com")
	if err != nil {
		t.Log(err)
	}

	rindex, err := hmac.ObtainBlindIndex("darth.vader@empire.com")
	if err != nil {
		t.Log(err)
	}

	if index != rindex {
		t.Logf("reindexing of value did not produce the same result")
		t.Fail()
	}
}
