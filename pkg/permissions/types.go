package permissions

import (
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (
	UserForbidden string = "forbidden: user does not have the correct permissions"
)

// Permission is a model struct for the permissions table in a resource
// representing a fine grained permission local to that application.
type Permission struct {
	Csrf string `db:"csrf" json:"csrf,omitempty"`

	Id          string          `db:"uuid" json:"uuid,omitempty"`
	ServiceName string          `db:"service_name" json:"service_name"`
	Permission  string          `db:"permission" json:"permission"` // this is the permission string, eg CURATOR not the name
	Name        string          `db:"name" json:"name"`
	Description string          `db:"description" json:"description"`
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at,omitempty"`
	Active      bool            `db:"active" json:"active"`
	Slug        string          `db:"slug" json:"slug,omitempty"`
}

// validate checks if the permission's fields are valid/well-formed.
func (p *Permission) Validate() error {

	// uuid's and dates may not yet exist, so those should only be validated if they are set.
	// additional checks are performed by services, so uuid values are removed, it is not a problem.

	// validate csrf token if it is set
	if p.Csrf != "" {
		if validate.ValidateUuid(p.Csrf) != nil {
			return fmt.Errorf("invalid csrf token in permission payload")
		}
	}

	// validate id if it is set
	if p.Id != "" {
		if validate.ValidateUuid(strings.TrimSpace(p.Id)) != nil {
			return fmt.Errorf("invalid permission id in permission payload")
		}
	}

	// check service name
	if err := validate.ValidateServiceName(strings.TrimSpace(p.ServiceName)); err != nil {
		return fmt.Errorf("invalid service name in permission payload: %v", err)
	}

	// check description length
	if validate.TooShort(p.Description, 2) || validate.TooLong(p.Description, 256) {
		return fmt.Errorf("invalid description in permission payload")
	}

	// check permission string
	if err := validate.ValidatePermission(strings.TrimSpace(p.Permission)); err != nil {
		return fmt.Errorf("invalid permission in permission payload: %v", err)
	}

	// check permission name
	if err := validate.ValidatePermissionName(strings.TrimSpace(p.Name)); err != nil {
		return fmt.Errorf("invalid permission name in permission payload: %v", err)
	}

	// check slug if it is set
	if p.Slug != "" {
		if validate.ValidateUuid(strings.TrimSpace(p.Slug)) != nil {
			return fmt.Errorf("invalid slug in permission payload")
		}
	}

	return nil
}

// PermissionRecord is a model which represents a permission record in the database.
type PermissionRecord struct {
	Id          string          `db:"uuid" json:"uuid,omitempty"`
	ServiceName string          `db:"service_name" json:"service_name"`
	Permission  string          `db:"permission" json:"permission"`   // encrypted
	Name        string          `db:"name" json:"name"`               // encrypted
	Description string          `db:"description" json:"description"` // encrypted
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at,omitempty"`
	Active      bool            `db:"active" json:"active"`
	Slug        string          `db:"slug" json:"slug,omitempty"`
	SlugIndex   string          `db:"slug_index" json:"slug_index,omitempty"`
}

// Validate checks if the permission is valid/well-formed
func (p *PermissionRecord) Validate() error {

	// validate id if it is set
	if p.Id != "" {
		if validate.ValidateUuid(strings.TrimSpace(p.Id)) != nil {
			return fmt.Errorf("invalid permission id in permission payload")
		}
	}

	// check service name
	if err := validate.ValidateServiceName(strings.TrimSpace(p.ServiceName)); err != nil {
		return fmt.Errorf("invalid service name in permission payload: %v", err)
	}

	// check permission name
	if err := validate.ValidatePermissionName(strings.TrimSpace(p.Name)); err != nil {
		return fmt.Errorf("invalid permission name in permission payload: %v", err)
	}

	// check description length
	if validate.TooShort(p.Description, 2) || validate.TooLong(p.Description, 256) {
		return fmt.Errorf("invalid description in permission payload")
	}

	// check slug if it is set
	if p.Slug != "" {
		if validate.ValidateUuid(strings.TrimSpace(p.Slug)) != nil {
			return fmt.Errorf("invalid slug in permission payload")
		}
	}

	return nil
}

// UpdatePermissionsCmd us a model used as a command to update the permissions associated with an entity.
// Note, the entity could be a user, an image, an album, or any other resourse identifier,
// eg, email address, image slug, album slug, etc.
type UpdatePermissionsCmd struct {
	Entity      string   `json:"entity"`
	Permissions []string `json:"permissions"`
}

// Validate checks if the update permissions command is valid/well-formed
func (cmd *UpdatePermissionsCmd) Validate() error {

	// light-weight validation of the entity since it is a lookup and can be many
	// things like a user email, image slug, album slug, etc.
	if len(cmd.Entity) < 2 || len(cmd.Entity) > 64 {
		return fmt.Errorf("invalid entity in update permissions command: must be between 2 and 64 characters")
	}

	// check permission slugs
	// note: for now, these are uuids, but could be any string in the future
	for _, permission := range cmd.Permissions {
		if validate.ValidateUuid(permission) != nil {
			return fmt.Errorf("invalid permission slug in update permissions command: %s", permission)
		}
	}

	return nil
}
