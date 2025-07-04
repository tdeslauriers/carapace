package validate

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/tdeslauriers/carapace/pkg/config"
)

const (
	PermissionNameRegex string = `^[a-zA-Z0-9]{2,32}$`
	PermissionNameMin   int    = 2
	PermissionNameMax   int    = 32
)

func IsValidPermissionName(name string) (bool, error) {

	logger := slog.Default().With(slog.String(config.ComponentKey, config.ComponentValidate), slog.String(config.ServiceKey, config.ServiceCarapace))

	rgx, err := regexp.Compile(PermissionNameRegex)
	if err != nil {
		logger.Error("failed to compile scope name regex")
	}

	if !rgx.MatchString(name) {
		return false, fmt.Errorf(`scope name must be between %d and %d characters long, 
				and may only contain upper and lower case letters, numbers, or spaces`, PermissionNameMin, PermissionNameMax)
	}

	return true, nil
}
