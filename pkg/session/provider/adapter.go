package provider

import (
	"context"
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Repository defines the interface for s2s token provider database operations.
type Repository interface {

	// FindActiveTokens retrieves all active service tokens from the database for a specified service name.
	// Active is defined by tokens tied to an unexpired refresh
	FindActiveTokens(ctx context.Context, serviceName string) ([]S2sAuthorization, error)

	// InsertToken inserts a new service token record into the database.
	InsertToken(ctx context.Context, token S2sAuthorization) error

	// DeleteServiceTknById deletes a service token by its uuid from the database.
	DeleteTokenById(ctx context.Context, uuid string) error
}

// NewRepository creates a new instance of Repository, returning an underlying concrete impl.
func NewRepository(db *sql.DB) Repository {
	return &repository{
		db: db,
	}
}

var _ Repository = (*repository)(nil)

// repository is the concrete implementation of the Repository interface.
type repository struct {
	db *sql.DB
}

// FindActiveTokens retrieves all active service tokens from the database.
// Active is defined by tokens tied to an unexpired refresh
func (r *repository) FindActiveTokens(ctx context.Context, serviceName string) ([]S2sAuthorization, error) {

	qry := `
		SELECT 
			uuid, 
			service_name,
			service_token, 
			service_expires, 
			refresh_token, 
			refresh_expires 
		FROM servicetoken
		WHERE refresh_expires > UTC_TIMESTAMP()
			AND service_name = ?`

	return data.SelectRecords[S2sAuthorization](r.db, qry, serviceName)
}

// InsertToken inserts a new service token record into the database.
func (r *repository) InsertToken(ctx context.Context, token S2sAuthorization) error {

	qry := `
		INSERT INTO servicetoken (
			uuid, 
			service_name, 
			service_token, 
			service_expires, 
			refresh_token, 
			refresh_expires) 
		VALUES (?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(r.db, qry, token)
}

// DeleteServiceTknById deletes a service token by its uuid from the database.
func (r *repository) DeleteTokenById(ctx context.Context, uuid string) error {

	qry := `
		DELETE FROM servicetoken
		WHERE uuid = ?`

	return data.DeleteRecord(r.db, qry, uuid)
}
