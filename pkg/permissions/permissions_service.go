package permissions

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

type PermissionsService interface {
	// GetAllPermissions retrieves all permissions in the database/persistence layer.
	GetAllPermissions() (map[string]PermissionRecord, []PermissionRecord, error)

	// GetPermissionBySlug retrieves a permission by its slug from the database/persistence layer.
	GetPermissionBySlug(slug string) (*PermissionRecord, error)

	// CreatePermission creates a new permission in the database/persistence layer.
	CreatePermission(p *PermissionRecord) (*PermissionRecord, error)

	// UpdatePermission updates an existing permission in the database/persistence layer.
	// or returns an error if the update fails.
	UpdatePermission(p *PermissionRecord) error
}

// NewPermissionsService creates a new permissions service and provides a pointer to a concrete implementation.
func NewPermissionsService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) PermissionsService {
	return &permissionsService{
		sql:     sql,
		indexer: i,
		cryptor: NewPermissionCryptor(c),

		logger: slog.Default().
			With(slog.String(util.ServiceKey, "carapace")).
			With(slog.String(util.ComponentKey, util.ComponenetPermissions)),
	}
}

var _ PermissionsService = (*permissionsService)(nil)

// permissionsService implements the Service interface for managing permissions to gallery data models and images.
type permissionsService struct {
	sql     data.SqlRepository
	indexer data.Indexer
	cryptor PermissionCryptor

	logger *slog.Logger
}

// GetAllPermissions implements the Service interface method to retrieve all permissions from the database/persistence layer.
func (s *permissionsService) GetAllPermissions() (map[string]PermissionRecord, []PermissionRecord, error) {

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
	var ps []PermissionRecord
	if err := s.sql.SelectRecords(qry, &ps); err != nil {
		s.logger.Error("Failed to retrieve permissions", slog.Any("error", err))
		return nil, nil, err
	}

	// check if any permissions were found
	// if not, return
	if len(ps) == 0 {
		s.logger.Warn("No permissions found in the database")
		return nil, nil, nil
	}

	// if records found, decrypt sensitive fields: name, permission, description, slug
	var (
		wg     sync.WaitGroup
		pmChan = make(chan PermissionRecord, len(ps))
		errs   = make(chan error, len(ps))
	)

	for _, p := range ps {
		wg.Add(1)
		go func(permission PermissionRecord) {
			defer wg.Done()

			decrypted, err := s.cryptor.DecryptPermission(permission)
			if err != nil {
				errs <- fmt.Errorf("failed to decrypt permission '%s': %v", permission.Id, err)
				return
			}

			pmChan <- *decrypted
		}(p)
	}

	wg.Wait()
	close(pmChan)
	close(errs)

	// check for errors during decryption
	if len(errs) > 0 {
		var errsList []error
		for e := range errs {
			errsList = append(errsList, e)
		}
		if len(errsList) > 0 {
			return nil, nil, errors.Join(errsList...)
		}
	}

	// collect decrypted permissions
	permissions := make([]PermissionRecord, 0, len(ps))
	psMap := make(map[string]PermissionRecord, len(ps))
	for p := range pmChan {
		permissions = append(permissions, p)
		psMap[p.Slug] = p
	}

	s.logger.Info(fmt.Sprintf("retrieved and decrypted %d permission(s) from the database", len(permissions)))

	return psMap, permissions, nil
}

// GetPermissionBySlug implements the Service interface method to retrieve a permission by its slug from the database/persistence layer.
func (s *permissionsService) GetPermissionBySlug(slug string) (*PermissionRecord, error) {

	// validate slug
	// redundant check, but good practice
	if valid := validate.IsValidUuid(slug); !valid {
		s.logger.Error("Invalid slug provided", slog.String("slug", slug))
		return nil, fmt.Errorf("invalid slug: %s", slug)
	}

	// get blind index for the slug
	index, err := s.indexer.ObtainBlindIndex(slug)
	if err != nil {
		s.logger.Error("Failed to generate blind index for slug", slog.Any("error", err))
		return nil, fmt.Errorf("failed to generate blind index for slug: %v", err)
	}

	// query to retrieve the permission by slug index
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
	var p PermissionRecord
	if err := s.sql.SelectRecord(qry, &p, index); err != nil {
		if err == sql.ErrNoRows {
			s.logger.Error(fmt.Sprintf("No permission found for slug '%s'", slug))
			return nil, fmt.Errorf("no permission found for slug '%s'", slug)
		} else {
			s.logger.Error(fmt.Sprintf("Failed to retrieve permission by slug '%s': %v", slug, err))
			return nil, fmt.Errorf("failed to retrieve permission by slug '%s': %v", slug, err)
		}
	}

	// prepare the permission by decrypting sensitive fields and removing unnecessary fields
	prepared, err := s.cryptor.DecryptPermission(p)
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to prepare permission '%s': %v", slug, err))
		return nil, fmt.Errorf("failed to prepare permission 'slug %s': %v", slug, err)
	}

	return prepared, nil
}

// CreatePermission implements the Service interface method to create a new permission in the database/persistence layer.
func (s *permissionsService) CreatePermission(p *PermissionRecord) (*PermissionRecord, error) {

	// validate the permission
	// redundant check, but but good practice
	if err := p.Validate(); err != nil {
		s.logger.Error("Failed to validate permission", slog.Any("error", err))
		return nil, fmt.Errorf("invalid permission: %v", err)
	}

	// create uuid and set it in the permission record
	id, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error("Failed to generate UUID for permission", slog.Any("error", err))
		return nil, fmt.Errorf("failed to generate UUID for permission: %v", err)
	}
	p.Id = id.String()

	// create created_at timestamp and set it in the permission record
	now := time.Now().UTC()
	p.CreatedAt = data.CustomTime{Time: now}

	// create a slug for the permission and set it in the permission record
	slug, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error("Failed to generate slug for permission", slog.Any("error", err))
		return nil, fmt.Errorf("failed to generate slug for permission: %v", err)
	}
	p.Slug = slug.String()

	// generate a blind index for the slug and set it in the permission record
	index, err := s.indexer.ObtainBlindIndex(p.Slug)
	if err != nil {
		s.logger.Error("Failed to generate blind index for slug", slog.Any("error", err))
		return nil, fmt.Errorf("failed to generate blind index for slug: %v", err)
	}
	p.SlugIndex = index

	// encrypt the sensitive fields in the permission record
	encrypted, err := s.cryptor.EncryptPermission(p)
	if err != nil {
		s.logger.Error(fmt.Sprintf("Failed to encrypt permission '%s': %v", p.Id, err))
		return nil, fmt.Errorf("failed to encrypt permission '%s': %v", p.Id, err)
	}

	// insert the permission record into the database
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
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?
		)`
	if err := s.sql.InsertRecord(qry, *encrypted); err != nil {
		s.logger.Error("failed to insert permission record into database", slog.Any("error", err))
		return nil, fmt.Errorf("failed to insert permission record into database: %v", err)
	}

	s.logger.Info(fmt.Sprintf("created permission '%s' in the database", encrypted.Id))

	// return unencrypted permission record
	// remove slug index as it is not needed in the response
	p.SlugIndex = "" // clear slug index as it is not needed in the response

	return p, nil
}

// UpdatePermission implements the Service interface method to update an existing permission in the database/persistence layer.
func (s *permissionsService) UpdatePermission(p *PermissionRecord) error {

	// validate the permission
	// redundant check, but good practice
	if err := p.Validate(); err != nil {
		s.logger.Error("Failed to validate permission", slog.Any("error", err))
		return fmt.Errorf("invalid permission: %v", err)
	}

	// get the blind index for the slug
	index, err := s.indexer.ObtainBlindIndex(p.Slug)
	if err != nil {
		s.logger.Error(fmt.Sprintf("Failed to generate blind index for slug '%s': %v", p.Slug, err))
		return fmt.Errorf("failed to generate blind index for slug '%s': %v", p.Slug, err)
	}

	// encrypt fields for persisting the updated permission
	encrypted, err := s.cryptor.EncryptPermission(p)
	if err != nil {
		s.logger.Error(fmt.Sprintf("Failed to encrypt permission '%s': %v", p.Id, err))
		return fmt.Errorf("failed to encrypt permission '%s': %v", p.Id, err)
	}

	// update the permission record in the database
	qry := `
		UPDATE permission SET
			permission = ?,
			name = ?,
			description = ?,
			active = ?,
			slug = ?
		WHERE slug_index = ?`
	if err := s.sql.UpdateRecord(qry, encrypted.Permission, encrypted.Name, encrypted.Description, encrypted.Active, encrypted.Slug, index); err != nil {
		s.logger.Error(fmt.Sprintf("failed to update permission '%s - %s' in the database: %v", p.Id, p.Name, err))
		return fmt.Errorf("failed to update permission '%s' in the database: %v", p.Name, err)
	}

	s.logger.Info(fmt.Sprintf("updated permission '%s' in the database", p.Id))
	return nil
}
