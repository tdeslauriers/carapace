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
