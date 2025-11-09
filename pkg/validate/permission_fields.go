package validate

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/tdeslauriers/carapace/internal/util"
)

const (
	PermissionNameRegex string = `^[a-zA-Z0-9 ]{2,32}$`
	PermissionNameMin   int    = 2
	PermissionNameMax   int    = 32

	PermissionRegex string = `^[A-Z0-9_]{2,64}$`
	PermissionMin   int    = 2
	PermissionMax   int    = 64
)

func IsValidPermissionName(name string) (bool, error) {

	logger := slog.Default().
		With(slog.String(util.ComponentKey, util.ComponenetPermissions)).
		With(slog.String(util.FrameworkKey, util.FrameworkCarapace)).
		With(slog.String(util.PackageKey, util.PackageValidate))

	rgx, err := regexp.Compile(PermissionNameRegex)
	if err != nil {
		logger.Error("failed to compile permission name regex", slog.String("err", err.Error()))
	}

	if !rgx.MatchString(name) {
		return false, fmt.Errorf(`permission name must be between %d and %d characters long, 
				and may only contain upper and lower case letters, numbers, or spaces`, PermissionNameMin, PermissionNameMax)
	}

	return true, nil
}

func IsValidPermission(permission string) (bool, error) {

	logger := slog.Default().
		With(slog.String(util.ComponentKey, util.ComponenetPermissions)).
		With(slog.String(util.FrameworkKey, util.FrameworkCarapace)).
		With(slog.String(util.PackageKey, util.PackageValidate))

	rgx, err := regexp.Compile(PermissionRegex)
	if err != nil {
		logger.Error("failed to compile permission regex", slog.String("err", err.Error()))
	}

	if !rgx.MatchString(permission) {
		return false, fmt.Errorf(`permission must be between %d and %d characters long, 
				and may only contain upper case letters, numbers, or underscores`, PermissionMin, PermissionMax)
	}

	return true, nil
}
