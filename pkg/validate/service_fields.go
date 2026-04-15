package validate

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// ServiceNameRegex validates character content only; length is enforced by ServiceNameMin/ServiceNameMax.
	ServiceNameRegex string = `^[a-z0-9]+$`
	ServiceNameMin   int    = 2
	ServiceNameMax   int    = 32
)

var (
	serviceNameRegex = regexp.MustCompile(ServiceNameRegex)
)

// ValidateServiceName checks if a service name is valid via regex criteria.
func ValidateServiceName(service string) error {
	service = strings.TrimSpace(service)
	if TooShort(service, ServiceNameMin) || TooLong(service, ServiceNameMax) {
		return fmt.Errorf("service name must be between %d and %d characters", ServiceNameMin, ServiceNameMax)
	}
	if !serviceNameRegex.MatchString(service) {
		return fmt.Errorf("service name may only contain lower case letters and/or numbers")
	}
	return nil
}
