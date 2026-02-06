package validate

import (
	"errors"
	"regexp"
	"strings"
)

// Compile regexes once for better performance
var (
	streetAddressRegex = regexp.MustCompile(`^[a-zA-Z0-9\s,.'#-]{1,100}$`)
	cityRegex          = regexp.MustCompile(`^[a-zA-Z\s.'-]{2,50}$`)
	stateRegex         = regexp.MustCompile(`^[A-Z]{2}$`)
	zipCodeRegex       = regexp.MustCompile(`^\d{5}(-\d{4})?$`)
	countryRegex       = regexp.MustCompile(`^[a-zA-Z\s.'-]{2,50}$`)
)

// ValidateStreetAddress validates the primary street address line
func ValidateStreetAddress(address string) error {
	address = strings.TrimSpace(address)

	if address == "" {
		return errors.New("street address is required")
	}

	if !streetAddressRegex.MatchString(address) {
		return errors.New("street address contains invalid characters or exceeds 100 characters")
	}

	return nil
}

// ValidateStreetAddress2 validates the optional secondary address line
func ValidateStreetAddress2(address string) error {
	address = strings.TrimSpace(address)

	// Empty is valid for address line 2
	if address == "" {
		return nil
	}

	if !streetAddressRegex.MatchString(address) {
		return errors.New("street address line 2 contains invalid characters or exceeds 100 characters")
	}

	return nil
}

// ValidateCity validates the city name
func ValidateCity(city string) error {
	city = strings.TrimSpace(city)

	if city == "" {
		return errors.New("city is required")
	}

	if !cityRegex.MatchString(city) {
		return errors.New("city must be 2-50 characters and contain only letters, spaces, periods, apostrophes, and hyphens")
	}

	return nil
}

// ValidateState validates the US state code (2-letter abbreviation)
func ValidateState(state string) error {
	state = strings.TrimSpace(state)
	state = strings.ToUpper(state)

	if state == "" {
		return errors.New("state is required")
	}

	if !stateRegex.MatchString(state) {
		return errors.New("state must be a 2-letter code (e.g., CA, NY, TX)")
	}

	return nil
}

// ValidateZipCode validates US ZIP codes (5-digit or ZIP+4 format)
func ValidateZipCode(zipCode string) error {
	zipCode = strings.TrimSpace(zipCode)

	if zipCode == "" {
		return errors.New("ZIP code is required")
	}

	if !zipCodeRegex.MatchString(zipCode) {
		return errors.New("ZIP code must be 5 digits or 5+4 format (e.g., 12345 or 12345-6789)")
	}

	return nil
}

// ValidateCountry validates the country name
func ValidateCountry(country string) error {
	country = strings.TrimSpace(country)

	if country == "" {
		return errors.New("country is required")
	}

	if !countryRegex.MatchString(country) {
		return errors.New("country must be 2-50 characters and contain only letters, spaces, periods, apostrophes, and hyphens")
	}

	return nil
}
