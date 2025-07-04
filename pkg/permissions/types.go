package permissions

import (
	"fmt"

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
	Name        string          `db:"name" json:"name"`
	Service     string          `db:"service" json:"service"`
	Description string          `db:"description" json:"description"`
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at,omitempty"`
	Active      bool            `db:"active" json:"active"`
	Slug        string          `db:"slug" json:"slug,omitempty"`
}

var allowedServices = map[string]struct{}{
	"pixie":      {},
	"apprentice": {},
}

func isServiceAllowed(input string) bool {
	_, ok := allowedServices[input]
	return ok
}

// validate checks if the permission's fields are valid/well-formed.
func (p *Permission) Validate() error {

	// uuid's and dates may not yet exist, so those should only be validated if they are set.
	// additional checks are performed by services, so uuid values are removed, it is not a problem.

	// validate csrf token if it is set
	if p.Csrf != "" {
		if !validate.IsValidUuid(p.Csrf) {
			return fmt.Errorf("invalid csrf token in permission payload")
		}
	}

	// validate id if it is set
	if p.Id != "" {
		if !validate.IsValidUuid(p.Id) {
			return fmt.Errorf("invalid permission id in permission payload")
		}
	}

	// check service name
	if ok, err := validate.IsValidServiceName(p.Service); !ok {
		return fmt.Errorf("invalid service name in permission payload: %v", err)
	}

	// check if service is allowed
	if !isServiceAllowed(p.Service) {
		return fmt.Errorf("service %s is not a valid service name", p.Service)
	}

	// check permission name
	if ok, err := validate.IsValidPermissionName(p.Name); !ok {
		return fmt.Errorf("invalid permission name in permission payload: %v", err)
	}

	// check description length
	if validate.TooShort(p.Description, 2) || validate.TooLong(p.Description, 256) {
		return fmt.Errorf("invalid description in permission payload")
	}

	// check slug if it is set
	if p.Slug != "" {
		if !validate.IsValidUuid(p.Slug) {
			return fmt.Errorf("invalid slug in permission payload")
		}
	}

	return nil
}
