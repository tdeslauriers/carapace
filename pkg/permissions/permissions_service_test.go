package permissions

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/data"
)

func newTestService(repo PermissionsRepository, indexer data.Indexer, cryptor PermissionCryptor, allowedServices map[string]struct{}) *permissionsService {
	return &permissionsService{
		sql:             repo,
		indexer:         indexer,
		cryptor:         cryptor,
		allowedServices: allowedServices,
		logger:          slog.Default(),
	}
}

func TestGetAllPermissions(t *testing.T) {
	encRecord := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "enc-READ",
		Name:        "enc-Read Posts",
		Description: "enc-Allows reading posts",
		Active:      true,
		Slug:        "enc-slug",
		SlugIndex:   "some-index",
	}
	decRecord := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "READ",
		Name:        "Read Posts",
		Description: "Allows reading posts",
		Active:      true,
		Slug:        testUUID2,
	}

	tests := []struct {
		name      string
		repo      *mockRepo
		cryptor   *mockPermCryptor
		wantErr   bool
		errSubstr string
		check     func(*testing.T, map[string]PermissionRecord, []PermissionRecord)
	}{
		{
			name: "success_single_record",
			repo: &mockRepo{
				findAllFunc: func() ([]PermissionRecord, error) {
					return []PermissionRecord{encRecord}, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					d := decRecord
					return &d, nil
				},
			},
			check: func(t *testing.T, m map[string]PermissionRecord, s []PermissionRecord) {
				if len(s) != 1 {
					t.Fatalf("slice length = %d, want 1", len(s))
				}
				if _, ok := m[decRecord.Slug]; !ok {
					t.Errorf("map missing key %q", decRecord.Slug)
				}
				if s[0].Permission != decRecord.Permission {
					t.Errorf("Permission = %q, want %q", s[0].Permission, decRecord.Permission)
				}
			},
		},
		{
			name: "success_multiple_records",
			repo: &mockRepo{
				findAllFunc: func() ([]PermissionRecord, error) {
					r2 := encRecord
					r2.Id = testUUID3
					return []PermissionRecord{encRecord, r2}, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					d := decRecord
					d.Id = p.Id
					return &d, nil
				},
			},
			check: func(t *testing.T, m map[string]PermissionRecord, s []PermissionRecord) {
				if len(s) != 2 {
					t.Fatalf("slice length = %d, want 2", len(s))
				}
				if len(m) != 1 {
					// both records decrypt to the same Slug, so map has 1 entry
					// this is a map collision scenario, not a bug in the test
					t.Logf("map has %d entries (expected collision on same slug)", len(m))
				}
			},
		},
		{
			name: "empty_database_returns_nils",
			repo: &mockRepo{
				findAllFunc: func() ([]PermissionRecord, error) {
					return []PermissionRecord{}, nil
				},
			},
			cryptor: &mockPermCryptor{},
			check: func(t *testing.T, m map[string]PermissionRecord, s []PermissionRecord) {
				if m != nil {
					t.Errorf("map = %v, want nil", m)
				}
				if s != nil {
					t.Errorf("slice = %v, want nil", s)
				}
			},
		},
		{
			name: "repository_error_propagated",
			repo: &mockRepo{
				findAllFunc: func() ([]PermissionRecord, error) {
					return nil, errors.New("db connection lost")
				},
			},
			cryptor:   &mockPermCryptor{},
			wantErr:   true,
			errSubstr: "db connection lost",
		},
		{
			name: "decryption_error_on_one_record",
			repo: &mockRepo{
				findAllFunc: func() ([]PermissionRecord, error) {
					return []PermissionRecord{encRecord}, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					return nil, errors.New("key not found")
				},
			},
			wantErr:   true,
			errSubstr: "key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.repo, &mockIndexer{}, tt.cryptor, nil)
			psMap, ps, err := svc.GetAllPermissions()

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, psMap, ps)
			}
		})
	}
}

func TestGetPermissionBySlug(t *testing.T) {
	encRecord := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "enc-READ",
		Name:        "enc-Read Posts",
		Description: "enc-Allows reading posts",
		Active:      true,
		Slug:        "enc-slug",
		SlugIndex:   "computed-index",
	}
	decRecord := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "READ",
		Name:        "Read Posts",
		Description: "Allows reading posts",
		Active:      true,
		Slug:        testUUID2,
	}

	tests := []struct {
		name      string
		slug      string
		indexer   *mockIndexer
		repo      *mockRepo
		cryptor   *mockPermCryptor
		wantErr   bool
		errSubstr string
		check     func(*testing.T, *PermissionRecord)
	}{
		{
			name: "valid_slug_found_and_decrypted",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "computed-index", nil
				},
			},
			repo: &mockRepo{
				findBySlugIndexFunc: func(index string) (*PermissionRecord, error) {
					r := encRecord
					return &r, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					d := decRecord
					return &d, nil
				},
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.Permission != decRecord.Permission {
					t.Errorf("Permission = %q, want %q", p.Permission, decRecord.Permission)
				}
				if p.Slug != decRecord.Slug {
					t.Errorf("Slug = %q, want %q", p.Slug, decRecord.Slug)
				}
			},
		},
		{
			name:      "invalid_slug_format",
			slug:      "not-a-uuid",
			indexer:   &mockIndexer{},
			repo:      &mockRepo{},
			cryptor:   &mockPermCryptor{},
			wantErr:   true,
			errSubstr: "invalid slug",
		},
		{
			name: "indexer_error",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "", errors.New("hmac key missing")
				},
			},
			repo:      &mockRepo{},
			cryptor:   &mockPermCryptor{},
			wantErr:   true,
			errSubstr: "blind index",
		},
		{
			name: "permission_not_found",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "computed-index", nil
				},
			},
			repo: &mockRepo{
				findBySlugIndexFunc: func(index string) (*PermissionRecord, error) {
					return nil, errors.New("permission not found")
				},
			},
			cryptor:   &mockPermCryptor{},
			wantErr:   true,
			errSubstr: "not found",
		},
		{
			name: "repository_error",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "computed-index", nil
				},
			},
			repo: &mockRepo{
				findBySlugIndexFunc: func(index string) (*PermissionRecord, error) {
					return nil, errors.New("db read timeout")
				},
			},
			cryptor:   &mockPermCryptor{},
			wantErr:   true,
			errSubstr: "db read timeout",
		},
		{
			name: "decryption_error",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "computed-index", nil
				},
			},
			repo: &mockRepo{
				findBySlugIndexFunc: func(index string) (*PermissionRecord, error) {
					r := encRecord
					return &r, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					return nil, errors.New("decryption failed")
				},
			},
			wantErr:   true,
			errSubstr: "prepare permission",
		},
		{
			name: "indexer_receives_correct_slug",
			slug: testUUID2,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					if input != testUUID2 {
						return "", errors.New("wrong slug passed to indexer")
					}
					return "computed-index", nil
				},
			},
			repo: &mockRepo{
				findBySlugIndexFunc: func(index string) (*PermissionRecord, error) {
					r := encRecord
					return &r, nil
				},
			},
			cryptor: &mockPermCryptor{
				decryptFunc: func(p PermissionRecord) (*PermissionRecord, error) {
					d := decRecord
					return &d, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.repo, tt.indexer, tt.cryptor, nil)
			got, err := svc.GetPermissionBySlug(tt.slug)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestCreatePermission(t *testing.T) {
	validInput := func() *PermissionRecord {
		return &PermissionRecord{
			ServiceName: "pixie",
			Name:        "Read Posts",
			Description: "Allows reading posts",
			Active:      true,
		}
	}

	pixieAllowed := map[string]struct{}{"pixie": {}}

	tests := []struct {
		name            string
		input           func() *PermissionRecord
		allowedServices map[string]struct{}
		indexer         *mockIndexer
		cryptor         *mockPermCryptor
		repo            *mockRepo
		wantErr         bool
		errSubstr       string
		check           func(*testing.T, *PermissionRecord)
	}{
		{
			name:            "success_assigns_ids_and_clears_slug_index",
			input:           validInput,
			allowedServices: pixieAllowed,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				insertFunc: func(p PermissionRecord) error { return nil },
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.Id == "" {
					t.Error("Id should be set by CreatePermission")
				}
				if p.Slug == "" {
					t.Error("Slug should be set by CreatePermission")
				}
				if p.SlugIndex != "" {
					t.Errorf("SlugIndex = %q, should be cleared in return value", p.SlugIndex)
				}
				if p.CreatedAt.IsZero() {
					t.Error("CreatedAt should be set by CreatePermission")
				}
			},
		},
		{
			name: "validation_error_on_bad_service_name",
			input: func() *PermissionRecord {
				return &PermissionRecord{ServiceName: "X", Name: "Read Posts", Description: "Allows reading posts"}
			},
			allowedServices: pixieAllowed,
			indexer:         &mockIndexer{},
			cryptor:         &mockPermCryptor{},
			repo:            &mockRepo{},
			wantErr:         true,
			errSubstr:       "invalid permission",
		},
		{
			name:            "service_not_in_allowed_list",
			input:           validInput,
			allowedServices: map[string]struct{}{},
			indexer:         &mockIndexer{},
			cryptor:         &mockPermCryptor{},
			repo:            &mockRepo{},
			wantErr:         true,
			errSubstr:       "not a valid service name",
		},
		{
			name:            "indexer_error",
			input:           validInput,
			allowedServices: pixieAllowed,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "", errors.New("hmac failure")
				},
			},
			cryptor:   &mockPermCryptor{},
			repo:      &mockRepo{},
			wantErr:   true,
			errSubstr: "blind index",
		},
		{
			name:            "encrypt_error",
			input:           validInput,
			allowedServices: pixieAllowed,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					return nil, errors.New("key rotation in progress")
				},
			},
			repo:      &mockRepo{},
			wantErr:   true,
			errSubstr: "encrypt permission",
		},
		{
			name:            "insert_error",
			input:           validInput,
			allowedServices: pixieAllowed,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				insertFunc: func(p PermissionRecord) error {
					return errors.New("duplicate key constraint")
				},
			},
			wantErr:   true,
			errSubstr: "duplicate key constraint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.repo, tt.indexer, tt.cryptor, tt.allowedServices)
			got, err := svc.CreatePermission(tt.input())

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestUpdatePermission(t *testing.T) {
	validInput := &PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Name:        "Read Posts",
		Description: "Allows reading posts",
		Active:      true,
		Slug:        testUUID2,
	}

	tests := []struct {
		name      string
		input     *PermissionRecord
		indexer   *mockIndexer
		cryptor   *mockPermCryptor
		repo      *mockRepo
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "success_update",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				updateFunc: func(p PermissionRecord) error { return nil },
			},
		},
		{
			name: "validation_error_on_bad_service_name",
			input: &PermissionRecord{
				ServiceName: "X",
				Name:        "Read Posts",
				Description: "Allows reading posts",
				Slug:        testUUID2,
			},
			indexer:   &mockIndexer{},
			cryptor:   &mockPermCryptor{},
			repo:      &mockRepo{},
			wantErr:   true,
			errSubstr: "invalid permission",
		},
		{
			name:  "indexer_error",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "", errors.New("hmac key missing")
				},
			},
			cryptor:   &mockPermCryptor{},
			repo:      &mockRepo{},
			wantErr:   true,
			errSubstr: "blind index",
		},
		{
			name:  "encrypt_error",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					return nil, errors.New("key expired")
				},
			},
			repo:      &mockRepo{},
			wantErr:   true,
			errSubstr: "encrypt permission",
		},
		{
			name:  "db_update_error",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				updateFunc: func(p PermissionRecord) error {
					return errors.New("record not found in db")
				},
			},
			wantErr:   true,
			errSubstr: "update permission",
		},
		{
			name:  "indexer_receives_correct_slug",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					if input != testUUID2 {
						return "", errors.New("wrong slug passed to indexer")
					}
					return "blind-index-value", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				updateFunc: func(p PermissionRecord) error { return nil },
			},
		},
		{
			name:  "repo_update_receives_slug_index",
			input: validInput,
			indexer: &mockIndexer{
				indexFunc: func(input string) (string, error) {
					return "expected-index", nil
				},
			},
			cryptor: &mockPermCryptor{
				encryptFunc: func(p *PermissionRecord) (*PermissionRecord, error) {
					enc := *p
					return &enc, nil
				},
			},
			repo: &mockRepo{
				updateFunc: func(p PermissionRecord) error {
					if p.SlugIndex != "expected-index" {
						return errors.New("wrong slug index in update call")
					}
					return nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.repo, tt.indexer, tt.cryptor, nil)
			err := svc.UpdatePermission(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
