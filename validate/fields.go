package validate

import (
	"fmt"
	"regexp"
)

const (
	emailRegex string = `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,7}$`
)

func ValidateEmail(email string) error {

	// max length of email can be 254 chars
	if len(email) > 254 {
		return fmt.Errorf("email address is too long: 254 character maximum")
	}

	// min length is 3, tho domain rules make them longer: 6
	if len(email) < 6 {
		return fmt.Errorf("email address is too short, must be at least 3 characters")
	}

	regex := regexp.MustCompile(emailRegex)
	if !regex.MatchString(email) {
		return fmt.Errorf("email address not properly formatted")
	}

	return nil
}
