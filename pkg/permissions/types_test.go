package permissions

import (
	"strings"
	"testing"
)

const (
	testUUID  = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	testUUID2 = "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	testUUID3 = "c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
)


func TestPermission_Validate(t *testing.T) {
	tests := []struct {
		name      string
		input     Permission
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_all_fields_set",
			input: Permission{
				Csrf:        testUUID,
				Id:          testUUID2,
				ServiceName: "pixie",
				Permission:  "READ",
				Name:        "Read Posts",
				Description: "Allows reading posts",
				Active:      true,
				Slug:        testUUID3,
			},
		},
		{
			name: "valid_optional_fields_empty",
			input: Permission{
				ServiceName: "apprentice",
				Permission:  "READ_WRITE",
				Name:        "Read Write",
				Description: "Allows reading and writing",
			},
		},
		{
			name: "valid_permission_with_underscore",
			input: Permission{
				ServiceName: "pixie",
				Permission:  "MANAGE_USERS",
				Name:        "Manage Users",
				Description: "Allows managing users",
			},
		},
		{
			name:      "invalid_csrf_not_uuid",
			input:     Permission{Csrf: "not-a-uuid", ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "csrf",
		},
		{
			name:      "invalid_id_not_uuid",
			input:     Permission{Id: "not-a-uuid", ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission id",
		},
		{
			name:      "invalid_service_name_too_short",
			input:     Permission{ServiceName: "x", Permission: "READ", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},
		{
			name:      "invalid_service_name_uppercase",
			input:     Permission{ServiceName: "Pixie", Permission: "READ", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},
		{
			name:      "invalid_service_name_too_long",
			input:     Permission{ServiceName: strings.Repeat("a", 33), Permission: "READ", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},

		{
			name:      "invalid_description_too_short",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: "x"},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_description_empty",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: ""},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_description_too_long",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: strings.Repeat("a", 257)},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_permission_lowercase",
			input:     Permission{ServiceName: "pixie", Permission: "read", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "invalid permission",
		},
		{
			name:      "invalid_permission_too_short",
			input:     Permission{ServiceName: "pixie", Permission: "R", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "invalid permission",
		},
		{
			name:      "invalid_permission_has_space",
			input:     Permission{ServiceName: "pixie", Permission: "READ POSTS", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "invalid permission",
		},
		{
			name:      "invalid_permission_name_too_short",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "R", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission name",
		},
		{
			name:      "invalid_permission_name_special_char",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "Read@Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission name",
		},
		{
			name:      "invalid_permission_name_too_long",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: strings.Repeat("A", 33), Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission name",
		},
		{
			name:      "invalid_slug_not_uuid",
			input:     Permission{ServiceName: "pixie", Permission: "READ", Name: "Read Posts", Description: "Allows reading posts", Slug: "not-a-uuid"},
			wantErr:   true,
			errSubstr: "slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPermissionRecord_Validate(t *testing.T) {
	tests := []struct {
		name      string
		input     PermissionRecord
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_all_fields",
			input: PermissionRecord{
				Id:          testUUID,
				ServiceName: "pixie",
				Name:        "Read Posts",
				Description: "Allows reading posts",
				Active:      true,
				Slug:        testUUID2,
			},
		},
		{
			name: "valid_optional_fields_empty",
			input: PermissionRecord{
				ServiceName: "apprentice",
				Name:        "Write Posts",
				Description: "Allows writing posts",
			},
		},
		{
			name:      "invalid_id_not_uuid",
			input:     PermissionRecord{Id: "not-a-uuid", ServiceName: "pixie", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission id",
		},
		{
			name:      "invalid_service_name_too_short",
			input:     PermissionRecord{ServiceName: "x", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},
		{
			name:      "invalid_service_name_uppercase",
			input:     PermissionRecord{ServiceName: "Pixie", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},
		{
			name:      "invalid_service_name_has_hyphen",
			input:     PermissionRecord{ServiceName: "my-service", Name: "Read Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "service name",
		},
		{
			name:      "invalid_permission_name_too_short",
			input:     PermissionRecord{ServiceName: "pixie", Name: "R", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission name",
		},
		{
			name:      "invalid_permission_name_special_char",
			input:     PermissionRecord{ServiceName: "pixie", Name: "Read@Posts", Description: "Allows reading posts"},
			wantErr:   true,
			errSubstr: "permission name",
		},
		{
			name:      "invalid_description_empty",
			input:     PermissionRecord{ServiceName: "pixie", Name: "Read Posts", Description: ""},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_description_too_short",
			input:     PermissionRecord{ServiceName: "pixie", Name: "Read Posts", Description: "x"},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_description_too_long",
			input:     PermissionRecord{ServiceName: "pixie", Name: "Read Posts", Description: strings.Repeat("a", 257)},
			wantErr:   true,
			errSubstr: "description",
		},
		{
			name:      "invalid_slug_not_uuid",
			input:     PermissionRecord{ServiceName: "pixie", Name: "Read Posts", Description: "Allows reading posts", Slug: "not-a-uuid"},
			wantErr:   true,
			errSubstr: "slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestUpdatePermissionsCmd_Validate(t *testing.T) {
	tests := []struct {
		name      string
		input     UpdatePermissionsCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "valid_single_permission",
			input: UpdatePermissionsCmd{Entity: "user@example.com", Permissions: []string{testUUID}},
		},
		{
			name:  "valid_multiple_permissions",
			input: UpdatePermissionsCmd{Entity: "user@example.com", Permissions: []string{testUUID, testUUID2}},
		},
		{
			name:  "valid_empty_permissions_list",
			input: UpdatePermissionsCmd{Entity: "user@example.com", Permissions: []string{}},
		},
		{
			name:  "valid_entity_at_min_length",
			input: UpdatePermissionsCmd{Entity: "ab"},
		},
		{
			name:  "valid_entity_at_max_length",
			input: UpdatePermissionsCmd{Entity: strings.Repeat("a", 64)},
		},
		{
			name:      "invalid_entity_empty",
			input:     UpdatePermissionsCmd{Entity: ""},
			wantErr:   true,
			errSubstr: "entity",
		},
		{
			name:      "invalid_entity_too_short",
			input:     UpdatePermissionsCmd{Entity: "x"},
			wantErr:   true,
			errSubstr: "entity",
		},
		{
			name:      "invalid_entity_too_long",
			input:     UpdatePermissionsCmd{Entity: strings.Repeat("a", 65)},
			wantErr:   true,
			errSubstr: "entity",
		},
		{
			name:      "invalid_permission_not_uuid",
			input:     UpdatePermissionsCmd{Entity: "user@example.com", Permissions: []string{"not-a-uuid"}},
			wantErr:   true,
			errSubstr: "permission slug",
		},
		{
			name:      "invalid_second_permission_not_uuid",
			input:     UpdatePermissionsCmd{Entity: "user@example.com", Permissions: []string{testUUID, "bad-uuid"}},
			wantErr:   true,
			errSubstr: "permission slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
