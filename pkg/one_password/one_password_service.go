package onepassword

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/tdeslauriers/carapace/internal/util"
)

// Service is an interface for the one_password service.
type Service interface {

	// GetDocument gets a document from 1password if it exists
	GetDocument(title, vault string) ([]byte, error)

	// UpsertDocument upserts a document in 1password, eg., a client certificate .pem file
	UpsertDocument(path, title, vault string, tags []string) error
}

// New is a factory function that returns a new one_password service interface.
func NewService(cli Cli) Service {
	return &service{
		cli: cli,

		logger: slog.Default().With(slog.String(util.ServiceKey, util.ServiceOnePassword)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface.
type service struct {
	cli Cli

	logger *slog.Logger
}

// GetDocument gets a document from 1password if it exists
func (s *service) GetDocument(title, vault string) ([]byte, error) {
	return s.cli.GetDocument(title, vault)
}

// UpsertDocument upserts a document in 1password, eg., a client certificate .pem file
func (s *service) UpsertDocument(path, title, vault string, tags []string) error {

	// light weight input validation
	if len(path) < 1 {
		return fmt.Errorf("file path is required to upsert 1password item/document")
	}
	if len(title) < 1 {
		return fmt.Errorf("title is required to upsert 1password item/document")
	}
	if len(vault) < 1 {
		return fmt.Errorf("vault is required to upsert 1password item/document")
	}
	if len(tags) < 1 {
		return fmt.Errorf("tags are required to upsert 1password item/document")
	}

	// Using get item vs get document to check if document exists so that the value is not
	// returned by default --> get document returns the document value and this is just a check
	doc, err := s.cli.GetItem(title, vault)
	if err != nil {
		if strings.Contains(err.Error(), fmt.Sprintf(`"%s" isn't an item`, title)) {
			s.logger.Warn(fmt.Sprintf("no 1password item '%s' found in vault: %s", title, vault))
		} else {
			// need to exit if error is not 'not found' error
			return fmt.Errorf("failed to get 1password item %s: %v", title, err)
		}
	}

	// if document doesn't exist, create it
	if doc == nil {
		s.logger.Info(fmt.Sprintf("creating 1password item/document: %s in vault: %s", title, vault))
		if err := s.cli.CreateDocument(path, title, vault, tags); err != nil {
			return fmt.Errorf("failed to create 1password document: %v", err)
		}

		return nil
	}

	// if document exists, edit document.
	s.logger.Info(fmt.Sprintf("updating 1password item/document: %s in vault: %s", title, vault))
	if err := s.cli.EditDocument(path, title); err != nil {
		return fmt.Errorf("failed to edit 1password item/document: %v", err)
	}

	return nil
}
