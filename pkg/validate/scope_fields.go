package validate

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/config"
)

const (
	
	ScopeRegex string = `^[a-zA-Z0-9:\*]{7,64}$`
	ScopeMin   int    = 7
	ScopeMax   int    = 64

	ScopeNameRegex string = `^[a-zA-Z0-9\s]{2,32}$`
	ScopeNameMin   int    = 2
	ScopeNameMax   int    = 32
)



// IsValidScope checks if a scope is valid via regex criteria and access options.
// should be r:service:* or w:service:* or d:service:*, etc.
func IsValidScope(scope string) (bool, error) {

	logger := slog.Default().With(slog.String(config.ComponentJwt, config.ComponentValidate), slog.String(config.ServiceKey, config.ServiceCarapace))

	rgx, err := regexp.Compile(ScopeRegex)
	if err != nil {
		logger.Error("failed to compile scope regex")
	}

	if !rgx.MatchString(scope) {
		return false, fmt.Errorf(`scope must be between %d and %d characters long, 
			and may only contain upper and lower case letters, numbers, ':', or '*'`, ScopeMin, ScopeMax)
	}

	// split scope by ':'
	parts := strings.Split(scope, ":")
	if len(parts) < 2 {
		return false, fmt.Errorf("scope must contain at least one access option and a service name")
	}

	// access options
	opts := []string{"r", "w", "d"}
	validOpts := false
	for _, opt := range opts {
		if parts[0] == opt {
			validOpts = true
		}
	}
	if !validOpts {
		return false, fmt.Errorf("scope must contain at least one valid access option: 'r', 'w', or 'd'")
	}

	return true, nil
}

func IsValidScopeName(name string) (bool, error) {

	logger := slog.Default().With(slog.String(config.ComponentJwt, config.ComponentValidate), slog.String(config.ServiceKey, config.ServiceCarapace))

	rgx, err := regexp.Compile(ScopeNameRegex)
	if err != nil {
		logger.Error("failed to compile scope name regex")
	}

	if !rgx.MatchString(name) {
		return false, fmt.Errorf(`scope name must be between %d and %d characters long, 
				and may only contain upper and lower case letters, numbers, or spaces`, ScopeNameMin, ScopeNameMax)
	}

	return true, nil
}
