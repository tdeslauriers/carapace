package validate

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// PermissionNameRegex validates character content only; length is enforced by PermissionNameMin/PermissionNameMax.
	PermissionNameRegex string = `^[a-zA-Z0-9 ]+$`
	PermissionNameMin   int    = 2
	PermissionNameMax   int    = 32

	// PermissionRegex validates character content only; length is enforced by PermissionMin/PermissionMax.
	PermissionRegex string = `^[A-Z0-9_]+$`
	PermissionMin   int    = 2
	PermissionMax   int    = 64
)

var (
	permissionNameRegex = regexp.MustCompile(PermissionNameRegex)
	permissionRegex     = regexp.MustCompile(PermissionRegex)
)

func ValidatePermissionName(name string) error {
	name = strings.TrimSpace(name)
	if TooShort(name, PermissionNameMin) || TooLong(name, PermissionNameMax) {
		return fmt.Errorf("permission name must be between %d and %d characters", PermissionNameMin, PermissionNameMax)
	}
	if !permissionNameRegex.MatchString(name) {
		return fmt.Errorf("permission name may only contain letters, numbers, or spaces")
	}
	return nil
}

func ValidatePermission(permission string) error {
	permission = strings.TrimSpace(permission)
	if TooShort(permission, PermissionMin) || TooLong(permission, PermissionMax) {
		return fmt.Errorf("permission must be between %d and %d characters", PermissionMin, PermissionMax)
	}
	if !permissionRegex.MatchString(permission) {
		return fmt.Errorf("permission may only contain upper case letters, numbers, or underscores")
	}
	return nil
}
