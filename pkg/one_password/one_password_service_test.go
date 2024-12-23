package onepassword

import (
	"fmt"
	"strings"
	"testing"
)

func TestUpsertDocument(t *testing.T) {

	testCases := []struct {
		name     string
		filePath string
		title    string
		vault    string
		tags     []string
		err      error
	}{
		{
			name:     "test success - created new file",
			filePath: "/test/data/test.txt",
			title:    "test_create",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      nil,
		},
		{
			name:     "test success - updated existing file",
			filePath: "/test/data/test.txt",
			title:    "test_update",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      nil,
		},
		{
			name:     "test failure - file path is required",
			filePath: "",
			title:    "test_upsert",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("file path is required"),
		},
		{
			name:     "test failure - title is required",
			filePath: "/test/data/test.txt",
			title:    "",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("title is required"),
		},
		{
			name:     "test failure - vault is required",
			filePath: "/test/data/test.txt",
			title:    "test_upsert",
			vault:    "",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("vault is required"),
		},
		{
			name:     "test failure - tags are required",
			filePath: "/test/data/test.txt",
			title:    "test_upsert",
			vault:    "Shared",
			tags:     []string{},
			err:      fmt.Errorf("tags are required"),
		},
		{
			name:     "test failure - failed to get item",
			filePath: "/test/data/test.txt",
			title:    "test_get_fail",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("failed to get item"),
		},
		{
			name:     "test failure - failed to create new file",
			filePath: "/test/data/test.txt",
			title:    "test_create_fail",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("failed to create document"),
		},
		{
			name:     "test failure - failed to update existing file",
			filePath: "/test/data/test.txt",
			title:    "test_update_fail",
			vault:    "Shared",
			tags:     []string{"Endor"},
			err:      fmt.Errorf("failed to edit document"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cli := NewService(&mockCli{})
			err := cli.UpsertDocument(tc.filePath, tc.title, tc.vault, tc.tags)
			if err != nil {
				if !strings.Contains(err.Error(), tc.err.Error()) {
					t.Errorf("%v", err)
				}
			}
		})
	}

}

type mockCli struct{}

func (m *mockCli) GetDocument(title, vault string) ([]byte, error) {
	return nil, nil
}

func (m *mockCli) CreateDocument(file, title, vault string, tags []string) error {
	if title == "test_create_fail" {
		return fmt.Errorf("failed to create document")
	}
	return nil
}

func (m *mockCli) EditDocument(file, title string) error {
	if title == "test_update_fail" {
		return fmt.Errorf("failed to edit document")
	}
	return nil
}

func (m *mockCli) GetItem(title, vault string) (*Item, error) {

	if title == "test_get_fail" {
		return nil, fmt.Errorf("error getting item")
	}
	return &Item{
		Title: "test_upsert",
		Vault: Vault{
			Name: "Shared",
		},
		Tags: []string{"Endor"},
	}, nil
}

func (m *mockCli) CreateItem(item *Item) error {
	return nil
}

func (m *mockCli) EditItem(item *Item) error {
	return nil
}
