package permissions

import (
	"errors"
	"strings"
	"testing"
)

func TestDecryptPermission(t *testing.T) {
	baseRecord := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "enc-READ",
		Name:        "enc-Read Posts",
		Description: "enc-Allows reading posts",
		Active:      true,
		Slug:        "enc-" + testUUID2,
		SlugIndex:   "some-blind-index",
	}

	tests := []struct {
		name        string
		input       PermissionRecord
		decryptFunc func(string) ([]byte, error)
		wantErr     bool
		errSubstr   string
		check       func(*testing.T, *PermissionRecord)
	}{
		{
			name:  "all_fields_decrypt_successfully",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				return []byte(strings.TrimPrefix(ciphertext, "enc-")), nil
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.Permission != "READ" {
					t.Errorf("Permission = %q, want %q", p.Permission, "READ")
				}
				if p.Name != "Read Posts" {
					t.Errorf("Name = %q, want %q", p.Name, "Read Posts")
				}
				if p.Description != "Allows reading posts" {
					t.Errorf("Description = %q, want %q", p.Description, "Allows reading posts")
				}
				if p.Slug != testUUID2 {
					t.Errorf("Slug = %q, want %q", p.Slug, testUUID2)
				}
				if p.Id != baseRecord.Id {
					t.Errorf("Id = %q, want %q", p.Id, baseRecord.Id)
				}
				if p.ServiceName != baseRecord.ServiceName {
					t.Errorf("ServiceName = %q, want %q", p.ServiceName, baseRecord.ServiceName)
				}
				if p.Active != baseRecord.Active {
					t.Errorf("Active = %v, want %v", p.Active, baseRecord.Active)
				}
			},
		},
		{
			name:  "slug_index_always_cleared",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				return []byte("decrypted"), nil
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.SlugIndex != "" {
					t.Errorf("SlugIndex = %q, want empty string", p.SlugIndex)
				}
			},
		},
		{
			name:  "decrypt_error_on_permission_field",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				if ciphertext == baseRecord.Permission {
					return nil, errors.New("key expired")
				}
				return []byte("decrypted"), nil
			},
			wantErr:   true,
			errSubstr: "permission",
		},
		{
			name:  "decrypt_error_on_name_field",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				if ciphertext == baseRecord.Name {
					return nil, errors.New("key expired")
				}
				return []byte("decrypted"), nil
			},
			wantErr:   true,
			errSubstr: "name",
		},
		{
			name:  "decrypt_error_on_description_field",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				if ciphertext == baseRecord.Description {
					return nil, errors.New("key expired")
				}
				return []byte("decrypted"), nil
			},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:  "decrypt_error_on_slug_field",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				if ciphertext == baseRecord.Slug {
					return nil, errors.New("key expired")
				}
				return []byte("decrypted"), nil
			},
			wantErr:   true,
			errSubstr: "slug",
		},
		{
			name:  "all_fields_fail_errors_joined",
			input: baseRecord,
			decryptFunc: func(ciphertext string) ([]byte, error) {
				return nil, errors.New("hsm unavailable")
			},
			wantErr:   true,
			errSubstr: "hsm unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewPermissionCryptor(&mockCryptor{decryptFunc: tt.decryptFunc})
			got, err := c.DecryptPermission(tt.input)

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

func TestEncryptPermission(t *testing.T) {
	baseRecord := &PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "READ",
		Name:        "Read Posts",
		Description: "Allows reading posts",
		Active:      true,
		Slug:        testUUID2,
		SlugIndex:   "some-blind-index",
	}

	tests := []struct {
		name        string
		input       *PermissionRecord
		encryptFunc func([]byte) (string, error)
		wantErr     bool
		errSubstr   string
		check       func(*testing.T, *PermissionRecord)
	}{
		{
			name:  "all_fields_encrypt_successfully",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				return "enc-" + string(d), nil
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.Permission != "enc-READ" {
					t.Errorf("Permission = %q, want %q", p.Permission, "enc-READ")
				}
				if p.Name != "enc-Read Posts" {
					t.Errorf("Name = %q, want %q", p.Name, "enc-Read Posts")
				}
				if p.Description != "enc-Allows reading posts" {
					t.Errorf("Description = %q, want %q", p.Description, "enc-Allows reading posts")
				}
				if !strings.HasPrefix(p.Slug, "enc-") {
					t.Errorf("Slug = %q, expected enc- prefix", p.Slug)
				}
				if p.Id != baseRecord.Id {
					t.Errorf("Id = %q, want %q", p.Id, baseRecord.Id)
				}
				if p.ServiceName != baseRecord.ServiceName {
					t.Errorf("ServiceName = %q, want %q", p.ServiceName, baseRecord.ServiceName)
				}
				if p.Active != baseRecord.Active {
					t.Errorf("Active = %v, want %v", p.Active, baseRecord.Active)
				}
			},
		},
		{
			name:  "slug_index_is_not_encrypted",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				return "enc-" + string(d), nil
			},
			check: func(t *testing.T, p *PermissionRecord) {
				if p.SlugIndex != "some-blind-index" {
					t.Errorf("SlugIndex = %q, should not be encrypted", p.SlugIndex)
				}
			},
		},
		{
			name:  "encrypt_error_on_permission_field",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				if string(d) == "READ" {
					return "", errors.New("key rotation in progress")
				}
				return "enc-" + string(d), nil
			},
			wantErr:   true,
			errSubstr: "permission",
		},
		{
			name:  "encrypt_error_on_name_field",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				if string(d) == "Read Posts" {
					return "", errors.New("key rotation in progress")
				}
				return "enc-" + string(d), nil
			},
			wantErr:   true,
			errSubstr: "name",
		},
		{
			name:  "encrypt_error_on_description_field",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				if string(d) == "Allows reading posts" {
					return "", errors.New("key rotation in progress")
				}
				return "enc-" + string(d), nil
			},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:  "encrypt_error_on_slug_field",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				if string(d) == testUUID2 {
					return "", errors.New("key rotation in progress")
				}
				return "enc-" + string(d), nil
			},
			wantErr:   true,
			errSubstr: "slug",
		},
		{
			name:  "all_fields_fail_errors_joined",
			input: baseRecord,
			encryptFunc: func(d []byte) (string, error) {
				return "", errors.New("hsm unavailable")
			},
			wantErr:   true,
			errSubstr: "hsm unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewPermissionCryptor(&mockCryptor{encryptFunc: tt.encryptFunc})
			got, err := c.EncryptPermission(tt.input)

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
