package validate

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/tdeslauriers/carapace/pkg/config"
)

const (
	ServiceNameRegex string = `^[a-z0-9]{2,32}$`
	ServiceNameMin   int    = 2
	ServiceNameMax   int    = 32
)

// IsValidServiceName checks if a service name is valid via regex criteria.
func IsValidServiceName(service string) (bool, error) {

	logger := slog.Default().With(slog.String(config.ComponentJwt, config.ComponentValidate), slog.String(config.ServiceKey, config.ServiceCarapace))

	rgx, err := regexp.Compile(ServiceNameRegex)
	if err != nil {
		logger.Error("unable to compile service name regex")
	}

	if !rgx.MatchString(service) {
		return false, fmt.Errorf(`service name must be between %d and %d characters long, 
			and may only contain upper and lower case letters and/or numbers`, ServiceNameMin, ServiceNameMax)
	}

	return true, nil
}
