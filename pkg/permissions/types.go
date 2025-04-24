package permissions

import "github.com/tdeslauriers/carapace/pkg/data"

// Permission is a model struct for the permissions table in a resource
// representing a fine grained permission local to that application.
type Permission struct {
	Id          string          `db:"uuid" json:"uuid"`
	Premission  string          `db:"permission" json:"permission"`
	Description string          `db:"description" json:"description"`
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at"`
	Active      bool            `db:"active" json:"active"`
	Slug        string          `db:"slug" json:"slug"`
}
