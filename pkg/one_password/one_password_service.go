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

	// GetItem gets an item from 1password if it exists
	GetItem(title, vault string) (*Item, error)

	// UpsertItem upserts an item in 1password
	UpsertItem(item *Item) error
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

// GetItem gets an item from 1password if it exists
func (s *service) GetItem(title, vault string) (*Item, error) {
	return s.cli.GetItem(title, vault)
}

// UpsertItem upserts an item in 1password
func (s *service) UpsertItem(item *Item) error {

	// light weight input validation
	if item == nil {
		return fmt.Errorf("item is required to upsert 1password item")
	}
	if len(item.Title) < 1 {
		return fmt.Errorf("title is required to upsert 1password item")
	}
	if len(item.Vault.Name) < 1 {
		return fmt.Errorf("vault is required to upsert 1password item")
	}
	if len(item.Fields) < 1 {
		return fmt.Errorf("fields are required to upsert 1password item")
	}

	// check if item exists so that "duplicate values" are not created
	// 1password will allow you to create more than one entry with the same name.
	exists, err := s.cli.GetItem(item.Title, item.Vault.Name)
	if err != nil {
		if strings.Contains(err.Error(), fmt.Sprintf(`"%s" isn't an item`, item.Title)) {
			s.logger.Warn(fmt.Sprintf("no 1password item '%s' found in vault: %s", item.Title, item.Vault.Name))
		} else {
			// need to exit if error is not 'not found' error
			return fmt.Errorf("failed to get 1password item %s: %v", item.Title, err)
		}
	}

	// if item doesn't exist, create it
	if exists == nil {
		s.logger.Info(fmt.Sprintf("creating 1password item: %s in vault: %s", item.Title, item.Vault.Name))
		if err := s.cli.CreateItem(item); err != nil {
			return fmt.Errorf("failed to create 1password item: %v", err)
		}

		return nil
	}

	// if item exists, edit item.
	// NOTE: any added fields to the core item type will be blown away unless you re-submit them with the edit.
	// However standard files like website will preserve the values.
	// To preserve data integrity, we should always get the item, update the impacted fields,
	// and then submit the whole item to 'op item edit'
	exists = updateItemFields(item, exists)

	s.logger.Info(fmt.Sprintf("updating 1password item: %s in vault: %s", item.Title, item.Vault.Name))
	if err := s.cli.EditItem(exists); err != nil {
		return fmt.Errorf("failed to edit 1password item: %v", err)
	}

	return nil
}

// updateItemFields updates the fields of an item that I would commonly want to update.
// It is NOT comprehensive and should be used as a helper function only.
// Exists param is the item that already exists in 1password and is therefore more robust, so it is returned
func updateItemFields(edited, exists *Item) *Item {

	// Id will likely never be updated

	// update title
	if edited.Title != "" && edited.Title != exists.Title {
		exists.Title = edited.Title
	}

	// update tags
	if len(edited.Tags) > 0 {
		for _, et := range edited.Tags {
			var found bool
			for _, ex := range exists.Tags {
				if et == ex {
					found = true
					break
				}
			}
			if !found {
				exists.Tags = append(exists.Tags, et)
			}
		}
	}

	// version will likely never be updated

	// update vault
	// vault id will not be present in the edited item, so we can't compare it
	if edited.Vault.Name != "" && edited.Vault.Name != exists.Vault.Name {
		exists.Vault = edited.Vault
	}

	// update category
	if edited.Category != "" && edited.Category != exists.Category {
		exists.Category = edited.Category
	}

	// additional info will be replaced with the new value
	if edited.AdditionalInfo != "" && edited.AdditionalInfo != exists.AdditionalInfo {
		exists.AdditionalInfo = edited.AdditionalInfo
	}

	// update urls
	if len(edited.Urls) > 0 {
		for _, et := range edited.Urls {
			var found bool
			for _, ex := range exists.Urls {
				if et.Href == ex.Href {
					found = true
					break
				}
			}
			if !found {
				exists.Urls = append(exists.Urls, et)
			}
		}
	}

	// update fields
	if len(edited.Fields) > 0 {
		for _, ef := range edited.Fields {
			var found bool
			for i, ex := range exists.Fields {
				if ef.Label == ex.Label {
					found = true
					// update value
					exists.Fields[i].Type = ef.Type
					exists.Fields[i].Purpose = ef.Purpose
					exists.Fields[i].Value = ef.Value
					exists.Fields[i].Reference = ef.Reference
					exists.Fields[i].PasswordDetails = ef.PasswordDetails
					break
				}
			}
			if !found {
				exists.Fields = append(exists.Fields, ef)
			}
		}
	}

	// update files: this should be done as a document...

	return exists
}
