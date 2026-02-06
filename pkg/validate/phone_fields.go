package validate

import (
	"errors"
	"regexp"
	"strings"
)

// Compile regexes once for better performance
var (
	countryCodeRegex = regexp.MustCompile(`^[1-9]\d{0,2}$`)
	phoneNumberRegex = regexp.MustCompile(`^\d{4,15}$`)
	extensionRegex   = regexp.MustCompile(`^\d{1,6}$`)
)

// ValidateCountryCode validates a country code is well formatted
func ValidateCountryCode(code string) error {
	code = strings.TrimSpace(code)

	if code == "" {
		return errors.New("country code is required")
	}

	if !countryCodeRegex.MatchString(code) {
		return errors.New("country code must be numeric and between 1 and 3 digits")
	}

	return nil
}

// ValidatePhoneNumber validates a phone number is well formatted
func ValidatePhoneNumber(number string) error {
	number = strings.TrimSpace(number)

	if number == "" {
		return errors.New("phone number is required")
	}

	if !phoneNumberRegex.MatchString(number) {
		return errors.New("phone number must be numeric and between 4 and 15 digits")
	}

	return nil
}

// ValidateExtension validates a phone extension is well formatted
func ValidateExtension(extension string) error {
	extension = strings.TrimSpace(extension)

	// Extension is optional
	if extension == "" {
		return nil
	}

	if !extensionRegex.MatchString(extension) {
		return errors.New("extension must be numeric and between 1 and 6 digits")
	}

	return nil
}
