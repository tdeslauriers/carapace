package validate

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// ScopeRegex validates character content only; length is enforced by ScopeMin/ScopeMax.
	ScopeRegex string = `^[a-zA-Z0-9:\*]+$`
	ScopeMin   int    = 7
	ScopeMax   int    = 64

	// ScopeNameRegex validates character content only; length is enforced by ScopeNameMin/ScopeNameMax.
	ScopeNameRegex string = `^[a-zA-Z0-9\s]+$`
	ScopeNameMin   int    = 2
	ScopeNameMax   int    = 32
)

var (
	scopeRegex     = regexp.MustCompile(ScopeRegex)
	scopeNameRegex = regexp.MustCompile(ScopeNameRegex)
)

// ValidateScope checks if a scope is valid via regex criteria and access options.
// Expected format: r:service:* or w:service:* or d:service:*, etc.
func ValidateScope(scope string) error {
	scope = strings.TrimSpace(scope)
	if TooShort(scope, ScopeMin) || TooLong(scope, ScopeMax) {
		return fmt.Errorf("scope must be between %d and %d characters", ScopeMin, ScopeMax)
	}

	if !scopeRegex.MatchString(scope) {
		return fmt.Errorf("scope may only contain letters, numbers, ':', or '*'")
	}

	parts := strings.Split(scope, ":")
	if len(parts) < 2 {
		return fmt.Errorf("scope must contain at least one access option and a service name")
	}

	switch parts[0] {
	case "r", "w", "d":
		return nil
	default:
		return fmt.Errorf("scope must start with a valid access option: 'r', 'w', or 'd'")
	}
}

func ValidateScopeName(name string) error {
	name = strings.TrimSpace(name)
	if TooShort(name, ScopeNameMin) || TooLong(name, ScopeNameMax) {
		return fmt.Errorf("scope name must be between %d and %d characters", ScopeNameMin, ScopeNameMax)
	}
	if !scopeNameRegex.MatchString(name) {
		return fmt.Errorf("scope name may only contain letters, numbers, or spaces")
	}
	return nil
}
