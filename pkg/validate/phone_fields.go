package validate

import "fmt"

const (
	CountryCodeRegex = `^[1-9]\d{0,2}$`
	PhoneNumberRegex = `^\d{4,15}$`
)

func IsValidCountryCode(code string) error {

	if !MatchesRegex(code, CountryCodeRegex) {
		return fmt.Errorf("country code must be numeric and between 1 and 3 digits")
	}

	return nil
}

func IsValidPhoneNumber(number string) error {

	if !MatchesRegex(number, PhoneNumberRegex) {
		return fmt.Errorf("phone number must be numeric and between 4 and 15 digits")
	}

	return nil
}
