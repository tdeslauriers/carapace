package permissions

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// PerissionsRepository defines the interface for permissions database operations.
type PermissionsRepository interface {

	// FindAll retrieves all permissions from the database.
	// Note: this does not decrypt any encrypted fields.
	FindAll() ([]PermissionRecord, error)

	// FindBySlugIndex retrieves a permission by its slug index from the database.
	// Note: this does not decrypt any encrypted fields.
	FindBySlugIndex(index string) (*PermissionRecord, error)

	// InsertPermission adds a new permission record to the database.
	// Note: the permission fields should already be encrypted before calling this method.
	InsertPermission(p PermissionRecord) error

	// UpdatePermission updates an existing permission record in the database.
	// Note: the permission fields should already be encrypted before calling this method.
	// Not all fields are updatable.
	UpdatePermission(p PermissionRecord) error
}

// NewPermissionsRepository creates a new instance of PermissionsRepository, returning an underlying concrete impl.
func NewPermissionsRepository(db *sql.DB) PermissionsRepository {
	return &permissionsRepository{
		sql: db,
	}
}

var _ PermissionsRepository = (*permissionsRepository)(nil)

// permissionsRepository implements the PermissionsRepository interface for managing permissions in the database.
type permissionsRepository struct {
	sql *sql.DB
}

// FindAll gets all permissions from the database.
// Note: this does not decrypt any encrypted fields.
func (r *permissionsRepository) FindAll() ([]PermissionRecord, error) {

	qry := `
		SELECT
			uuid,
			service_name,
			permission,
			name,
			description,
			created_at,
			active,
			slug,
			slug_index
		FROM permission`

	records, err := data.SelectRecords[PermissionRecord](r.sql, qry)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// FindBySlugIndex retrieves a permission by its slug index from the database.
// Note: this does not decrypt any encrypted fields.
func (r *permissionsRepository) FindBySlugIndex(index string) (*PermissionRecord, error) {

	qry := `
		SELECT
			uuid,
			service_name,
			permission,
			name,
			description,
			created_at,
			active,
			slug,
			slug_index
		FROM permission
		WHERE slug_index = ?`

	record, err := data.SelectOneRecord[PermissionRecord](r.sql, qry, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("permission not found")
		}
		return nil, fmt.Errorf("failed to retrieve permission: %w", err)
	}

	return &record, nil
}

// InsertPermission adds a new permission record to the database.
// Note: the permission fields should already be encrypted before calling this method.
func (r *permissionsRepository) InsertPermission(p PermissionRecord) error {

	qry := `
		INSERT INTO permission (
			uuid,
			service_name,
			permission,
			name,
			description,
			created_at,
			active,
			slug,
			slug_index
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(r.sql, qry, p)
}

// UpdatePermission updates an existing permission record in the database.
// Note: the permission fields should already be encrypted before calling this method.
// Not all fields are updatable.
func (r *permissionsRepository) UpdatePermission(p PermissionRecord) error {

	qry := `
		UPDATE permission SET
			permission = ?,
			name = ?,
			description = ?,
			active = ?
		WHERE slug_index = ?`

	return data.UpdateRecord(
		r.sql,
		qry,
		p.Permission,  // to update
		p.Name,        // to update
		p.Description, // to update
		p.Active,      // to update
		p.SlugIndex,   // WHERE clause
	)
}
