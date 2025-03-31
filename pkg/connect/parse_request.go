package connect

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// GetValidSlug parses the request and returns the slug if it is valid.
// If the slug is not valid, an error is returned.
func GetValidSlug(r *http.Request) (string, error) {

	// get the url slug from the request
	segments := strings.Split(r.URL.Path, "/")

	var slug string
	if len(segments) > 1 {
		slug = segments[len(segments)-1]
	} else {
		return "", fmt.Errorf("no slug found in request")
	}

	if !validate.IsValidUuid(slug) {
		return "", fmt.Errorf("invalid or not well formatted slug")
	}

	return slug, nil
}

// GetSessionToken parses the request and returns the session token if it is valid formatted.
// If the session token is not valid, an error is returned.
// Note: this is format validation only, not business logic validation, ie, does not check if the token is expired.
func GetSessionToken(r *http.Request) (string, error) {

	// get the session token from the request
	sessionToken := r.Header.Get("Authorization")
	if sessionToken == "" {
		return "", fmt.Errorf("no session token found in request")
	}

	if !validate.IsValidUuid(sessionToken) {
		return "", fmt.Errorf("invalid or not well formatted session token")
	}

	return sessionToken, nil
}
