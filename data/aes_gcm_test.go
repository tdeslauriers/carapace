package data

import (
	"testing"
)

const Plaintext string = "firstname.lastname@email.com"

func TestAesCipher(t *testing.T) {

	// set key to env var
	r := GenerateAesGcmKey()

	serviceKey := NewServiceAesGcmKey(r)

	encrypted, err := serviceKey.EncyptServiceData(Plaintext)
	if err != nil {
		t.Logf("Failed to encrypt test data: %v", err)
		t.Fail()
	}

	decrypted, err := serviceKey.DecyptServiceData(encrypted)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	if Plaintext != decrypted {
		t.Logf("Failed to decrypt data correctly, decrypted: %s", decrypted)
		t.Fail()
	}

	sameCrypted, err := serviceKey.EncyptServiceData(Plaintext)
	if err != nil {
		t.Logf("Failed to encrypt test data: %v", err)
		t.Fail()
	}
	if sameCrypted == encrypted {
		t.Logf("Encrypted same value to the same cipher: oracle vuln")
		t.Fail()
	}
}
