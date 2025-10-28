package validate

import "testing"

func TestValidateEmail(t *testing.T) {

	// test valid email format
	email := "darth.vader@empire.com"
	if err := IsValidEmail(email); err != nil {
		t.Fail()
	}

	noDomain := "darth.vader@com"
	noAtSymbol := "darth.vader-empire.com"
	badChar := "darth,vader@empire.com"
	short := "darth"

	tests := []string{noDomain, noAtSymbol, badChar, short}
	for _, v := range tests {
		if err := IsValidEmail(v); err == nil {
			t.Log(err)
			t.Fail()
		}
	}
}

func TestValidatePassword(t *testing.T) {

	good := "Ch6Zxd@GpdGN7URmmG3t"
	if err := IsValidPassword(good); err != nil {
		t.Logf("failed to validate good password: %v", err)
		t.Fail()
	}

	fail := "too_short"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: too short")
		t.Fail()
	}

	fail = "THERE_ARE_NO_LOWERCASE_CHARS"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: no lowercase letters")
		t.Fail()
	}

	fail = "there_are_no_uppercase_letters"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: no uppercase letters")
		t.Fail()
	}

	fail = "there_are_no_number_chars"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: no numbers")
		t.Fail()
	}

	fail = "notEven1SpecialChar"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: no special chars")
		t.Fail()
	}

	fail = "Ch6Zxd@G_~!@#$%^&*_pdGN7URmmG3t"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: keyboard sequence")
		t.Fail()
	}

	fail = "Ch6Zxd@G_\\][poiu_pdGN7URmmG3t"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: reverse keyboard sequence")
		t.Fail()
	}

	fail = "Ch6Zxd@G_hijklmnop_pdGN7URmmG3t"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: alphabet")
		t.Fail()
	}

	fail = "Ch6Zxd@G_sqrponmlkj_pdGN7"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: reverse alphabet")
		t.Fail()
	}

	fail = "Ch6Zxd@G_ttTtT_pdGN7URmmG3t"
	if err := IsValidPassword(fail); err == nil {
		t.Logf("password should error: repeat chars")
		t.Fail()
	}

}

func TestNames(t *testing.T) {

	good := []string{"Darth", "柔道", "de la Riva", "O'Brian", "Jean-Luc", "Muñoz"}
	for _, v := range good {
		if err := IsValidName(v); err != nil {
			t.Logf("name: %s should pass regex: %v", v, err)
			t.Fail()
		}
	}

	fail := []string{"Fonz👍", "Darth+Vader", "Bond; James Bond", "Henry8", "hulk@smash", "new\\nline"}
	for _, v := range fail {
		if err := IsValidName(v); err == nil {
			t.Logf("name: %s should fail regex: %v", v, err)
			t.Fail()
		}
	}
}

func TestValidateBirthDay(t *testing.T) {

	good := []string{"1969-01-10", "2002-02-02"}
	for _, v := range good {
		if err := IsValidBirthday(v); err != nil {
			t.Logf("%s should be valid dob: %v", v, err)
		}
	}

	fail := []string{"1900-01-10", "2202-02-02"}
	for _, v := range fail {
		if err := IsValidBirthday(v); err != nil {
			t.Logf("%s should be valid dob: %v", v, err)
		}
	}
}

func TestValidUuid(t *testing.T) {

	uuids := []string{
		"93c10464-0a09-435c-a8fc-3b8a38525b8d",
		"not-a-uuid",
	}

	for i := range uuids {
		if !IsValidUuid(uuids[0]) {
			t.Logf("'%s' is a valid Uuid.\n", uuids[i])
			t.Fail()
		}
		if IsValidUuid(uuids[1]) {
			t.Logf("'%s' is NOT valid Uuid.\n", uuids[i])
			t.Fail()
		}
	}
}
