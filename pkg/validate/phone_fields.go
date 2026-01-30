package validate

import (
	"fmt"
	"regexp"
)

const (
	CountryCodeRegex = `^[1-9]\d{0,2}$`
	PhoneNumberRegex = `^\d{4,15}$`
	ExtensionRegex   = `^\d{1,6}$`
)

var (
	ccReg  = regexp.MustCompile(CountryCodeRegex)
	pnReg  = regexp.MustCompile(PhoneNumberRegex)
	extReg = regexp.MustCompile(ExtensionRegex)
)

// IsValidCountryCode validates a country code is well formatted
func IsValidCountryCode(code string) error {

	if !ccReg.MatchString(code) {
		return fmt.Errorf("country code must be numeric and between 1 and 3 digits")
	}

	return nil
}

// IsValidPhoneNumber validates a phone number is well formatted
func IsValidPhoneNumber(number string) error {

	if !pnReg.MatchString(number) {
		return fmt.Errorf("phone number must be numeric and between 4 and 15 digits")
	}

	return nil
}

// IsValidExtension validates a phone extension is well formatted
func IsValidExtension(extension string) error {

	if !extReg.MatchString(extension) {
		return fmt.Errorf("extension must be numeric and between 1 and 6 digits")
	}

	return nil
}
