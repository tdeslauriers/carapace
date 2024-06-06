package data

import (
	"testing"
)

func TestHmac(t *testing.T) {

	hmac := NewIndexer([]byte("DeathStarPlans"))

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
