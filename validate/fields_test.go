package validate

import "testing"

func TestValidateFields(t *testing.T) {

	// test valid email format

	email := "darth.vader@empire.com"
	if err := ValidateEmail(email); err != nil {
		t.Fail()
	}

	noDomain := "darth.vader@com"
	noAtSymbol := "darth.vader-empire.com"
	badChar := "darth,vader@empire.com"
	short := "darth"

	tests := []string{noDomain, noAtSymbol, badChar, short}
	for _, v := range tests {
		if err := ValidateEmail(v); err == nil {
			t.Logf(err.Error())
			t.Fail()
		}
	}
}
