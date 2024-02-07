package validate

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	EmailRegex string = `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,7}$`
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
)

// includes alphabet
var KeyboardSequences = []string{"`1234567890-=", `~!@#$\%^&*()_+`, "qwertyuiop[]\\", "qwertyuiop{}|", "asdfghjkl;'", "asdfghjkl:\"", "zxcvbnm,./", "zxcvbnm<>?", "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]", "!qaz@wsx#edc$rfv%tgb^yhn&ujm*ik,(ol.)p:?_{\"+}", "=[;.-pl,0okm9ijn8uhb7ygv6tfc5rdx4esz3wa2q1]", `}"?+{:>_pl<)okm(ijn*uhb&ygv^tfc\%rdx$esz#wa@q!`, "abcdefghijklmnopqrstuvwxyz"}

func ValidateEmail(email string) error {

	// technically, min length of email is 3, but must be 6 to pass regex
	// max length of email can be 254 chars
	if TooShort(email, EmailMin) || TooLong(email, EmailMax) {
		return fmt.Errorf("email must be between 6 and 254 characters in length")
	}

	if !MatchesRegex(email, EmailRegex) {
		return fmt.Errorf("email address not properly formatted")
	}

	return nil
}

func ValidateName(name string) error {

	if TooShort(name, NameMin) || TooLong(name, NameMax) {
		return fmt.Errorf("name should be between 16 and 64 characters in length")
	}

	if !MatchesRegex(name, NameRegex) {
		return errors.New("name includes illegal characters")
	}

	return nil
}

func ValidateBirthday(dob string) error {

	// parse
	birthday, err := time.Parse("2006-01-02", dob)
	if err != nil {
		return fmt.Errorf("birthday not properly formatted: %v", err)
	}

	now := time.Now()

	if birthday.After(now) {
		return fmt.Errorf("birthday cannot be in the future")
	}

	age := now.Year() - birthday.Year()

	// adjust age in case birthday hasn't occurred yet this year
	if now.Month() < birthday.Month() || (now.Month() == birthday.Month() && now.Day() < birthday.Day()) {
		age--
	}

	if age >= 110 {
		return fmt.Errorf("birth year greater than 110 years ago")
	}

	return nil
}

func ValidatePassword(password string) error {

	if TooShort(password, PasswordMin) || TooLong(password, PasswordMax) {
		return fmt.Errorf("password should be between 16 and 64 characters in length")
	}

	if !MatchesRegex(password, UpperCase) {
		return errors.New("password must include at least 1 uppercase letter")
	}

	if !MatchesRegex(password, LowerCase) {
		return errors.New("password must include at least 1 lowercase letter")
	}

	if !MatchesRegex(password, Number) {
		return errors.New("password must include at least 1 number")
	}

	if !MatchesRegex(password, SpecialChar) {
		return errors.New("password must include at least 1 special character")
	}

	// keyboard sequence
	if err := ContainsKeyboardSequence(password); err != nil {
		return err
	}

	// repeat characters
	if err := RepeatChar(password); err != nil {
		return err
	}

	return nil
}

func MatchesRegex(s, pattern string) bool {

	rgx, err := regexp.Compile(pattern)
	if err != nil {
		log.Panicf("unable to compile regex pattern: %s: %v", pattern, err)
	}

	return rgx.MatchString(s)
}

func RepeatChar(password string) error {

	lowerPassword := strings.ToLower(password)

	count := 1
	for i := 1; i < len(lowerPassword); i++ {
		if lowerPassword[i] == lowerPassword[i-1] {
			count++
			if count > RepeatCharMax {
				return fmt.Errorf("not allowed to repeat characters more than %d times", RepeatCharMax)
			}
		} else {
			count = 1
		}
	}

	return nil
}

func ContainsKeyboardSequence(password string) error {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // avoid leaking go routines

	results := make(chan bool, 1)
	var wg sync.WaitGroup

	for _, seq := range KeyboardSequences {
		wg.Add(1)
		go func(sequence string) {
			defer wg.Done()

			found := IsKeyboardSequence(password, sequence)

			select {
			case results <- found:
				// cancel all routines if true returned to channel
				if found {
					cancel()
				}
			case <-ctx.Done():
				// context cancelled, exit
				return
			}
		}(seq)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result {
			return fmt.Errorf("password contains keyboard sequence")
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

func TooShort(field interface{}, min int) bool {

	switch f := field.(type) {
	case string:
		return len(f) < min
	case []byte:
		return len(f) < min
	default:
		log.Panicf("Min length check only takes string or byte slice: %v", reflect.TypeOf(field))
		return false
	}
}

func TooLong(field interface{}, max int) bool {

	switch f := field.(type) {
	case string:
		return len(f) > max
	case []byte:
		return len(f) > max
	default:
		log.Panicf("Max length check only takes string or byte slice: %v", reflect.TypeOf(field))
		return false
	}
}
