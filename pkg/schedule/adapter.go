package schedule

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Repository defines the interface for scheduled database operations.
type Repository interface {

	// FindSessionAccessTknXrefs finds xrefs between session and access tokens based on refresh expiry.
	FindExpiredRefreshXrefs() ([]SessionAccessXref, error)

	// FindExpiredAccessTknXrefs finds xrefs between session and access tokens based on session expiry.
	FindExpiredAccessTknXrefs(hours int) ([]SessionAccessXref, error)

	// FindSessionOauthXrefs finds xrefs between session and oauth tokens based on session.
	FindExpiredOauthXrefs(hours int) ([]SessionOauthXref, error)

	// DeleteAccessToken deletes expired access tokens from the database by
	// checking if their refresh expiry has passed.
	DeleteExpiredAccessToken() error

	// DeleteExpiredSvcTkns deletes expired service tokens from the database based
	// on the expiry time of their refresh tokens.
	DeleteExpiredSvcTkns() error

	// DeleteOauthFlow deletes expired oauth flows from the database.
	// meaning, they are older than the specified number of hours and not attached to a session.
	DeleteOauthFlow(hours int) error

	// DeleteExpiredSession deletes expired sessions from the database,
	// meaning, they are older than the specified number of hours and not attached to any tokens, etc.
	DeleteExpiredSession(hours int) error

	// DeleteExpiredRefresh deletes expired refresh tokens from the database.
	DeleteExpiredRefresh(hours int) error

	// DeleteSessionAccessTknXref deletes session-access token xref records by Id.
	DeleteSessionAccessTknXref(id int) error

	// DeleteSessionOauthXref deletes session-oauth token xref records by Id.
	DeleteSessionOauthXref(id int) error

	// DeleteAuthCodeXrefs deletes auth code xref records where the authcode is older than ten minutes.
	DeleteAuthCodeXrefs() error

	// DeleteAuthCode deletes auth codes that are older than ten minutes.
	DeleteAuthCode() error
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

// DeleteSessionAccessTknXref finds xrefs between session and access tokens based on refresh expiry.
func (r *repository) FindExpiredRefreshXrefs() ([]SessionAccessXref, error) {

	qry := `
		SELECT 
			ua.id,
			ua.uxsession_uuid,
			ua.accesstoken_uuid
		FROM uxsession_accesstoken ua
			LEFT OUTER JOIN accesstoken a ON ua.accesstoken_uuid = a.uuid
		WHERE a.refresh_expires < UTC_TIMESTAMP()`
	xrefs, err := data.SelectRecords[SessionAccessXref](r.db, qry)
	if err != nil {
		return nil, err
	}

	return xrefs, nil
}

// FindSessionOauthXrefs finds xrefs between session and oauth tokens based on session expiry.
func (r *repository) FindExpiredOauthXrefs(hours int) ([]SessionOauthXref, error) {

	qry := `
		SELECT 
			uo.id,
			uo.uxsession_uuid,
			uo.oauthflow_uuid
		FROM uxsession_oauthflow uo
			LEFT OUTER JOIN uxsession u ON uo.uxsession_uuid = u.uuid
		WHERE u.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()`
	xrefs, err := data.SelectRecords[SessionOauthXref](r.db, qry, hours)
	if err != nil {
		return nil, err
	}

	return xrefs, nil
}

// FindExpiredAccessTknXrefs finds xrefs between session and access tokens based on session expiry.
func (r *repository) FindExpiredAccessTknXrefs(hours int) ([]SessionAccessXref, error) {

	qry := `
		SELECT
			ua.id,
			ua.uxsession_uuid,
			ua.accesstoken_uuid
		FROM uxsession_accesstoken ua
			LEFT OUTER JOIN uxsession u ON ua.uxsession_uuid = u.uuid
		WHERE u.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()`
	xrefs, err := data.SelectRecords[SessionAccessXref](r.db, qry, hours)
	if err != nil {
		return nil, err
	}

	return xrefs, nil
}

// DeleteAccessToken deletes expired access tokens from the database
// by checking if their refresh expiry has passed.
func (r *repository) DeleteExpiredAccessToken() error {

	qry := `
		DELETE FROM accesstoken 
		WHERE refresh_expires < UTC_TIMESTAMP()`
	if err := data.DeleteRecord(r.db, qry); err != nil {
		return err
	}

	return nil
}

// DeleteExpiredSvcTkns deletes expired service tokens from the database based
// on the expiry time of their refresh tokens.
func (r *repository) DeleteExpiredSvcTkns() error {

	query := `
		DELETE FROM servicetoken 
		WHERE refresh_expires < UTC_TIMESTAMP()`
	if err := data.DeleteRecord(r.db, query); err != nil {
		return err
	}

	return nil
}

// DeleteOauthFlow deletes expired oauth flows from the database.
// meaning, they are older than the specified number of hours and not attached to a session.
func (r *repository) DeleteOauthFlow(hours int) error {

	query := `
		DELETE o
		FROM oauthflow o
			LEFT OUTER JOIN uxsession_oauthflow uo ON o.uuid = uo.oauthflow_uuid
		WHERE o.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()
			AND uo.oauthflow_uuid IS NULL`
	if err := data.DeleteRecord(r.db, query, hours); err != nil {
		return err
	}

	return nil
}

// DeleteExpiredSession deletes expired sessions from the database,
// meaning, they are older than the specified number of hours and not attached to any tokens, etc.
func (r *repository) DeleteExpiredSession(hours int) error {

	query := `
	DELETE u
	FROM uxsession u
		LEFT OUTER JOIN uxsession_accesstoken ua ON u.uuid = ua.uxsession_uuid
	WHERE u.created_at + INTERVAL ? HOUR < UTC_TIMESTAMP()
		AND ua.uxsession_uuid IS NULL`
	if err := data.DeleteRecord(r.db, query, hours); err != nil {
		return err
	}

	return nil
}

// DeleteExpiredRefresh deletes expired refresh tokens from the database.
func (r *repository) DeleteExpiredRefresh(hours int) error {

	query := `
		DELETE FROM refresh
		WHERE created_at < NOW() + INTERVAL ? HOUR < UTC_TIMESTAMP()`
	if err := data.DeleteRecord(r.db, query, hours); err != nil {
		return err
	}

	return nil
}

// DeleteSessionAccessTknXref deletes session-access token xref records by Id.
func (r *repository) DeleteSessionAccessTknXref(id int) error {

	query := `
		DELETE FROM uxsession_accesstoken
		WHERE id = ?`
	if err := data.DeleteRecord(r.db, query, id); err != nil {
		return err
	}

	return nil
}

// DeleteSessionOauthXref deletes session-oauth token xref records by Id.
func (r *repository) DeleteSessionOauthXref(id int) error {

	query := `
		DELETE FROM uxsession_oauthtoken
		WHERE id = ?`
	if err := data.DeleteRecord(r.db, query, id); err != nil {
		return err
	}

	return nil
}

// DeleteAuthCodeXrefs deletes auth code xref records where the authcode is older than ten minutes.
func (r *repository) DeleteAuthCodeXrefs() error {

	qry := `
		DELETE aa
		FROM authcode_account aa 
			LEFT OUTER JOIN authcode a ON aa.authcode_uuid = a.uuid
		WHERE a.created_at + INTERVAL 10 MINUTE < UTC_TIMESTAMP()`
	if err := data.DeleteRecord(r.db, qry); err != nil {
		return err
	}

	return nil
}

// DeleteAuthCode deletes auth codes that are older than ten minutes.
func (r *repository) DeleteAuthCode() error {

	qry := `
		DELETE FROM authcode 
		WHERE created_at + INTERVAL 10 MINUTE < UTC_TIMESTAMP()`
	if err := data.DeleteRecord(r.db, qry); err != nil {
		return err
	}

	return nil
}
