package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// TestMoveObjectSameKey verifies that MoveObject returns nil without
// calling the MinIO SDK when src and dst are identical.
func TestMoveObjectSameKey(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: if the SDK is called, this test will panic,
		// which is the correct signal that the early-return guard is broken.
	}

	err := m.MoveObject(context.Background(), "images/photo.jpg", "images/photo.jpg")
	if err != nil {
		t.Fatalf("MoveObject with identical src and dst should return nil, got: %v", err)
	}
}

// TestMoveObjectKeyValidation verifies that MoveObject rejects invalid src/dst
// keys before reaching the MinIO SDK.
func TestMoveObjectKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	tests := []struct {
		name      string
		src       string
		dst       string
		errSubstr string
	}{
		{
			name:      "invalid_src_empty",
			src:       "",
			dst:       "images/photo.jpg",
			errSubstr: "source",
		},
		{
			name:      "invalid_src_path_traversal",
			src:       "../../etc/passwd",
			dst:       "images/photo.jpg",
			errSubstr: "source",
		},
		{
			name:      "invalid_dst_empty",
			src:       "images/photo.jpg",
			dst:       "",
			errSubstr: "destination",
		},
		{
			name:      "invalid_dst_null_byte",
			src:       "images/photo.jpg",
			dst:       "images/\x00photo.jpg",
			errSubstr: "destination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.MoveObject(context.Background(), tt.src, tt.dst)
			if err == nil {
				t.Fatalf("expected error for src=%q dst=%q, got nil", tt.src, tt.dst)
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

// invalidKeyTests is a shared set of invalid key cases used across method-level
// key validation tests — each method validates keys the same way.
var invalidKeyTests = []struct {
	name  string
	input string
}{
	{
		name:  "empty_key",
		input: "",
	},
	{
		name:  "path_traversal",
		input: "../../etc/passwd",
	},
	{
		name:  "null_byte",
		input: "uploads/file\x00name.jpg",
	},
}

// TestGetPreSignedPutUrlKeyValidation verifies that GetPreSignedPutUrl rejects
// invalid object keys before reaching the MinIO SDK.
func TestGetPreSignedPutUrlKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	for _, tt := range invalidKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetPreSignedPutUrl(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("expected error for key %q, got nil", tt.input)
			}
		})
	}
}

// TestGetSignedUrlKeyValidation verifies that GetSignedUrl rejects invalid
// object keys before reaching the MinIO SDK.
func TestGetSignedUrlKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	for _, tt := range invalidKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetSignedUrl(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("expected error for key %q, got nil", tt.input)
			}
		})
	}
}

// TestWithObjectKeyValidation verifies that WithObject rejects invalid object
// keys before reaching the MinIO SDK.
func TestWithObjectKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	for _, tt := range invalidKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.WithObject(context.Background(), tt.input, func(r ReadSeekCloser) error {
				return nil
			})
			if err == nil {
				t.Fatalf("expected error for key %q, got nil", tt.input)
			}
		})
	}
}

// TestDeleteObjectKeyValidation verifies that DeleteObject rejects invalid
// object keys before reaching the MinIO SDK.
func TestDeleteObjectKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	for _, tt := range invalidKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.DeleteObject(context.Background(), tt.input)
			if err == nil {
				t.Fatalf("expected error for key %q, got nil", tt.input)
			}
		})
	}
}

// TestDeleteObjectsEmptyKeys verifies that DeleteObjects returns nil without
// calling the MinIO SDK when the keys slice is empty.
func TestDeleteObjectsEmptyKeys(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: if the SDK is called, this test will panic,
		// which is the correct signal that the early-return guard is broken.
	}

	tests := []struct {
		name string
		keys []string
	}{
		{
			name: "nil_slice",
			keys: nil,
		},
		{
			name: "empty_slice",
			keys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := m.DeleteObjects(context.Background(), tt.keys); err != nil {
				t.Fatalf("DeleteObjects with %s should return nil, got: %v", tt.name, err)
			}
		})
	}
}

// TestDeleteObjectsKeyValidation verifies that DeleteObjects validates every key
// up front -- all-or-nothing -- before reaching the MinIO SDK, so a single
// invalid key anywhere in the slice must fail closed without deleting anything.
func TestDeleteObjectsKeyValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	tests := []struct {
		name      string
		keys      []string
		errSubstr string
	}{
		{
			name:      "single_invalid_key_empty",
			keys:      []string{""},
			errSubstr: "invalid object key",
		},
		{
			name:      "single_invalid_key_path_traversal",
			keys:      []string{"../../etc/passwd"},
			errSubstr: "invalid object key",
		},
		{
			name:      "single_invalid_key_null_byte",
			keys:      []string{"uploads/file\x00name.jpg"},
			errSubstr: "invalid object key",
		},
		{
			name:      "invalid_key_among_valid_keys",
			keys:      []string{"images/photo1.jpg", "images/photo2.jpg", "../../etc/passwd"},
			errSubstr: "invalid object key",
		},
		{
			name:      "invalid_key_first_in_slice",
			keys:      []string{"", "images/photo1.jpg"},
			errSubstr: "invalid object key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.DeleteObjects(context.Background(), tt.keys)
			if err == nil {
				t.Fatalf("expected error for keys %v, got nil", tt.keys)
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

// TestListObjectsPrefixValidation verifies that ListObjects rejects invalid
// key prefixes before reaching the MinIO SDK.
func TestListObjectsPrefixValidation(t *testing.T) {
	m := &minioStorage{
		bucket: "my-bucket",
		expiry: 15 * time.Minute,
		// client intentionally nil: SDK must not be reached for these cases.
	}

	tests := []struct {
		name      string
		prefix    string
		errSubstr string
	}{
		{
			name:      "empty_prefix",
			prefix:    "",
			errSubstr: "invalid object prefix",
		},
		{
			name:      "path_traversal",
			prefix:    "../../etc/passwd",
			errSubstr: "invalid object prefix",
		},
		{
			name:      "null_byte",
			prefix:    "uploads/file\x00name",
			errSubstr: "invalid object prefix",
		},
		{
			name:      "leading_slash",
			prefix:    "/uploads/photo.jpg",
			errSubstr: "invalid object prefix",
		},
		{
			name:      "too_long",
			prefix:    strings.Repeat("a", validate.KeyMaxLength+1),
			errSubstr: "invalid object prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := m.ListObjects(context.Background(), tt.prefix)
			if err == nil {
				t.Fatalf("expected error for prefix %q, got nil", tt.prefix)
			}
			if keys != nil {
				t.Fatalf("expected nil keys on error, got %v", keys)
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}
