package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	EmailRegex string = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z0-9]{2,7}$`
	EmailMax   int    = 254
	EmailMin   int    = 6 // min length is 3, tho domain rules make them longer: 6

	NameMin   int    = 1
	NameMax   int    = 32
	NameRegex string = `^[\p{L}\p{M}'\-\s]+$`

	PasswordMin         int    = 16
	PasswordMax         int    = 64
	UpperCase           string = `[A-Z]`
	LowerCase           string = `[a-z]`
	Number              string = `[0-9]`
	SpecialChar         string = `[\@\!\#\$\%\^\&\*\(\)\_\+\{\}\:\;\"\'<>\,\.\?\/\|\\\=\-\[\]\~]`
	KeyboardSequenceMax int    = 5
	RepeatCharMax       int    = 4 // allowing 4 for true randomness and ggGg scenarios

	UuidPattern string = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
)

var (
	emailRegex       = regexp.MustCompile(EmailRegex)
	nameRegex        = regexp.MustCompile(NameRegex)
	upperCaseRegex   = regexp.MustCompile(UpperCase)
	lowerCaseRegex   = regexp.MustCompile(LowerCase)
	numberRegex      = regexp.MustCompile(Number)
	specialCharRegex = regexp.MustCompile(SpecialChar)
	uuidRegex        = regexp.MustCompile(UuidPattern)

	// includes alphabet
	KeyboardSequences = []string{"`1234567890-=", `~!@#$\%^&*()_+`, "qwertyuiop[]\\", "qwertyuiop{}|", "asdfghjkl;'", "asdfghjkl:\"", "zxcvbnm,./", "zxcvbnm<>?", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]", "!qaz@wsx#edc$rfv%tgb^yhn&ujm*ik,(ol.)p:?_{\"+}", "=[;.-pl,0okm9ijn8uhb7ygv6tfc5rdx4esz3wa2q1]", `}"?+{:>_pl<)okm(ijn*uhb&ygv^tfc\%rdx$esz#wa@q!`, "abcdefghijklmnopqrstuvwxyz"}
)

func ValidateEmail(email string) error {

	email = strings.TrimSpace(email)

	// technically, min length of email is 3, but must be 6 to pass regex
	// max length of email can be 254 chars
	if TooShort(email, EmailMin) || TooLong(email, EmailMax) {
		return fmt.Errorf("email must be between %d and %d characters in length", EmailMin, EmailMax)
	}

	if !emailRegex.MatchString(email) {
		return fmt.Errorf("email address must be valid format, eg., name@domain.com")
	}

	return nil
}

func ValidateName(name string) error {

	name = strings.TrimSpace(name)

	if TooShort(name, NameMin) || TooLong(name, NameMax) {
		return fmt.Errorf("name should be between %d and %d characters in length", NameMin, NameMax)
	}

	if !nameRegex.MatchString(name) {
		return errors.New("name includes illegal characters")
	}

	return nil
}

// ValidateBirthday does not handle empty string, aka a required field — it only checks format.
// An empty string is treated as "not provided" and passes without error.
func ValidateBirthday(dob string) error {
	dob = strings.TrimSpace(dob)

	// handle empty string
	if len(dob) == 0 {
		return nil
	}

	// parse
	birthday, err := time.Parse("2006-01-02", dob)
	if err != nil {
		return fmt.Errorf("birth date not properly formatted: %v", err)
	}

	now := time.Now()

	if birthday.After(now) {
		return fmt.Errorf("birth date cannot be in the future")
	}

	age := now.Year() - birthday.Year()

	// adjust age in case birthday hasn't occurred yet this year
	if now.Month() < birthday.Month() || (now.Month() == birthday.Month() && now.Day() < birthday.Day()) {
		age--
	}

	// allows exactly 120 years old
	if age > 120 {
		return fmt.Errorf("date of birth cannot be greater than 120 years ago")
	}

	return nil
}

func ValidatePassword(password string) error {
	password = strings.TrimSpace(password)

	if TooShort(password, PasswordMin) || TooLong(password, PasswordMax) {
		return fmt.Errorf("password should be between %d and %d characters in length", PasswordMin, PasswordMax)
	}

	if !upperCaseRegex.MatchString(password) {
		return errors.New("password must include at least 1 uppercase letter")
	}

	if !lowerCaseRegex.MatchString(password) {
		return errors.New("password must include at least 1 lowercase letter")
	}

	if !numberRegex.MatchString(password) {
		return errors.New("password must include at least 1 number")
	}

	if !specialCharRegex.MatchString(password) {
		return errors.New("password must include at least 1 special character")
	}

	// keyboard sequence
	if err := ContainsKeyboardSequence(password); err != nil {
		return fmt.Errorf("password %s", err)
	}

	// repeat characters
	if err := RepeatChar(password); err != nil {
		return fmt.Errorf("password %s", err)
	}

	return nil
}

func RepeatChar(password string) error {

	lowerPassword := strings.ToLower(password)

	count := 1
	for i := 1; i < len(lowerPassword); i++ {
		if lowerPassword[i] == lowerPassword[i-1] {
			count++
			if count > RepeatCharMax {
				return fmt.Errorf("contains repeated characters greater than %d characters long", RepeatCharMax)
			}
		} else {
			count = 1
		}
	}

	return nil
}

// ContainsKeyboardSequence checks the password sequentially against all known keyboard sequences.
// A plain loop is correct and fast enough for 13 sequences — goroutines added overhead without benefit.
func ContainsKeyboardSequence(password string) error {
	for _, seq := range KeyboardSequences {
		if IsKeyboardSequence(password, seq) {
			return fmt.Errorf("contains keyboard sequences longer than %d characters, eg., 'qwerty'", KeyboardSequenceMax)
		}
	}
	return nil
}

// includes reverse of any sequence
func IsKeyboardSequence(password, sequence string) bool {

	lowerPassword := strings.ToLower(password)
	both := []string{sequence, reverseOrder(sequence)}

	for _, seq := range both {
		for i := 0; i <= len(seq); i++ {
			for j := i + KeyboardSequenceMax; j <= len(seq); j++ {
				substr := seq[i:j]

				if len(substr) >= KeyboardSequenceMax && contains(lowerPassword, substr) {
					return true
				}
			}
		}
	}

	return false
}

func reverseOrder(s string) string {

	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

func contains(password, sequence string) bool {

	if len(sequence) == 0 || len(password) < len(sequence) {
		return false
	}
	return strings.Contains(password, sequence)
}

func TooShort(s string, min int) bool {
	return len(strings.TrimSpace(s)) < min
}

func TooLong(s string, max int) bool {
	return len(strings.TrimSpace(s)) > max
}

func ValidateUuid(uuid string) error {
	uuid = strings.TrimSpace(uuid)
	if TooShort(uuid, 36) || TooLong(uuid, 36) {
		return fmt.Errorf("UUID must be exactly 36 characters in length")
	}
	if !uuidRegex.MatchString(uuid) {
		return fmt.Errorf("UUID must be in valid format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	return nil
}
