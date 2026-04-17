package validate

import (
	"strings"
	"testing"
	"time"
)

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple_key",
			input:   "photo.jpg",
			wantErr: false,
		},
		{
			name:    "valid_path_style",
			input:   "users/123/avatar.jpg",
			wantErr: false,
		},
		{
			name:    "valid_with_spaces",
			input:   "my photo album/summer 2024.jpg",
			wantErr: false,
		},
		{
			name:    "valid_with_unicode",
			input:   "uploads/façade.jpg",
			wantErr: false,
		},
		{
			name:    "valid_with_special_chars",
			input:   "uploads/file+name=value@host.jpg",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   strings.Repeat("a", KeyMinLength),
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("a", KeyMaxLength),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "ab",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("a", KeyMaxLength+1),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_whitespace_only",
			input:     "   ",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_null_byte",
			input:     "uploads/file\x00name.jpg",
			wantErr:   true,
			errSubstr: "null bytes",
		},
		{
			name:      "invalid_path_traversal_relative",
			input:     "../../etc/passwd",
			wantErr:   true,
			errSubstr: "path traversal",
		},
		{
			name:      "invalid_path_traversal_embedded",
			input:     "uploads/../../../secret",
			wantErr:   true,
			errSubstr: "path traversal",
		},
		{
			name:      "invalid_not_utf8",
			input:     "uploads/\xff\xfe.jpg",
			wantErr:   true,
			errSubstr: "UTF-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestIsAllowedEvent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "allowed_put",
			input: "s3:ObjectCreated:Put",
			want:  true,
		},
		{
			name:  "allowed_post",
			input: "s3:ObjectCreated:Post",
			want:  true,
		},
		{
			name:  "allowed_copy",
			input: "s3:ObjectCreated:Copy",
			want:  true,
		},
		{
			name:  "allowed_complete_multipart",
			input: "s3:ObjectCreated:CompleteMultipartUpload",
			want:  true,
		},
		{
			name:  "disallowed_delete",
			input: "s3:ObjectRemoved:Delete",
			want:  false,
		},
		{
			name:  "disallowed_empty",
			input: "",
			want:  false,
		},
		{
			name:  "disallowed_unknown",
			input: "s3:ObjectCreated:Unknown",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedEvent(tt.input)
			if got != tt.want {
				t.Fatalf("IsAllowedEvent(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateEventName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_put",
			input:   "s3:ObjectCreated:Put",
			wantErr: false,
		},
		{
			name:    "valid_complete_multipart",
			input:   "s3:ObjectCreated:CompleteMultipartUpload",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "s3",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_not_allowed",
			input:     "s3:ObjectRemoved:Delete",
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "invalid_unknown_action",
			input:     "s3:ObjectCreated:Unknown",
			wantErr:   true,
			errSubstr: "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidatePrincipalId(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "pixie",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   strings.Repeat("a", PrincipalIDMinLength),
			wantErr: false,
		},
		{
			name:    "valid_exact_max",
			input:   strings.Repeat("a", PrincipalIDMaxLength),
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "ab",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("a", PrincipalIDMaxLength+1),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_uppercase",
			input:     "Pixie",
			wantErr:   true,
			errSubstr: "lowercase letters",
		},
		{
			name:      "invalid_numbers",
			input:     "pixie123",
			wantErr:   true,
			errSubstr: "lowercase letters",
		},
		{
			name:      "invalid_hyphen",
			input:     "pixie-svc",
			wantErr:   true,
			errSubstr: "lowercase letters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrincipalId(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateBucketName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "my-bucket",
			wantErr: false,
		},
		{
			name:    "valid_alphanumeric",
			input:   "bucket123",
			wantErr: false,
		},
		{
			name:    "valid_exact_min",
			input:   "abc",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "ab",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_long",
			input:     strings.Repeat("a", BucketNameMaxLength+1),
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_uppercase",
			input:     "MyBucket",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_starts_with_hyphen",
			input:     "-bucket",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_ends_with_hyphen",
			input:     "bucket-",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_underscore",
			input:     "my_bucket",
			wantErr:   true,
			errSubstr: "lowercase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateArn(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_s3_arn",
			input:   "arn:aws:s3:::my-bucket",
			wantErr: false,
		},
		{
			name:    "valid_iam_arn",
			input:   "arn:aws:iam::123456789012:user/johndoe",
			wantErr: false,
		},
		{
			name:    "valid_minio_arn",
			input:   "arn:minio:s3:::my-bucket",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "arn:aws:s3",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_missing_arn_prefix",
			input:     "aws:iam::123456789012:user/johndoe",
			wantErr:   true,
			errSubstr: "invalid ARN format",
		},
		{
			name:      "invalid_wrong_format",
			input:     "not-an-arn-at-all-but-long-enough",
			wantErr:   true,
			errSubstr: "invalid ARN format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateArn(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateSize(t *testing.T) {
	tests := []struct {
		name      string
		input     int64
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_one_byte",
			input:   1,
			wantErr: false,
		},
		{
			name:    "valid_one_mb",
			input:   1024 * 1024,
			wantErr: false,
		},
		{
			name:    "valid_max_5tb",
			input:   S3ObjectSizeMax,
			wantErr: false,
		},
		{
			name:      "invalid_zero",
			input:     0,
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_negative",
			input:     -1,
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_exceeds_max",
			input:     S3ObjectSizeMax + 1,
			wantErr:   true,
			errSubstr: "between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSize(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %d", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %d: %v", tt.input, err)
			}
		})
	}
}

func TestValidateEtag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_md5_etag",
			input:   "d41d8cd98f00b204e9800998ecf8427e",
			wantErr: false,
		},
		{
			name:    "valid_multipart_etag",
			input:   "d41d8cd98f00b204e9800998ecf8427e-3",
			wantErr: false,
		},
		{
			name:    "valid_uppercase",
			input:   "D41D8CD98F00B204E9800998ECF8427E",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "d",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_non_hex",
			input:     "d41d8cd98f00b204e9800998ecf8427z",
			wantErr:   true,
			errSubstr: "hexadecimal",
		},
		{
			name:      "invalid_space",
			input:     "d41d8cd9 8f00b204",
			wantErr:   true,
			errSubstr: "hexadecimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEtag(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateSequencer(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_hex_sequencer",
			input:   "0055AED6DCD90C26",
			wantErr: false,
		},
		{
			name:    "valid_alphanumeric",
			input:   "ABC123",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "A",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_hyphen",
			input:     "ABC-123",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "ABC@123",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSequencer(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateContentType(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_image_jpeg",
			input:   "image/jpeg",
			wantErr: false,
		},
		{
			name:    "valid_application_json",
			input:   "application/json",
			wantErr: false,
		},
		{
			name:    "valid_text_plain",
			input:   "text/plain",
			wantErr: false,
		},
		{
			name:    "valid_with_dot",
			input:   "application/vnd.ms-excel",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_no_slash",
			input:     "imagejpeg",
			wantErr:   true,
			errSubstr: "invalid content type",
		},
		{
			name:      "invalid_missing_subtype",
			input:     "image/",
			wantErr:   true,
			errSubstr: "invalid content type",
		},
		{
			name:      "invalid_spaces",
			input:     "image/ jpeg",
			wantErr:   true,
			errSubstr: "invalid content type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContentType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateVersionId(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_alphanumeric",
			input:   "3HL4kqtJvjVBH40Nrjfkd",
			wantErr: false,
		},
		{
			name:    "valid_with_dots_hyphens_underscores",
			input:   "v1.0-beta_2",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "1",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_special_char",
			input:     "version@1",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_space",
			input:     "version 1",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVersionId(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateStorageClass(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_standard",
			input:   "STANDARD",
			wantErr: false,
		},
		{
			name:    "valid_reduced_redundancy",
			input:   "REDUCED_REDUNDANCY",
			wantErr: false,
		},
		{
			name:    "valid_with_dots",
			input:   "STANDARD.IA",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_short",
			input:     "ST",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_space",
			input:     "STANDARD IA",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "STANDARD@IA",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStorageClass(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateSchemaVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "1.0",
			wantErr: false,
		},
		{
			name:    "valid_with_hyphen",
			input:   "2-0",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "1",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_space",
			input:     "1 0",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "1.0@beta",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchemaVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_simple",
			input:   "MyConfig",
			wantErr: false,
		},
		{
			name:    "valid_with_dots_hyphens",
			input:   "my-config.v1",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_too_short",
			input:     "ab",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_space",
			input:     "my config",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "config@v1",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfiguration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateEventVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_semver",
			input:   "2.1",
			wantErr: false,
		},
		{
			name:    "valid_with_hyphen",
			input:   "2-1",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "2",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_space",
			input:     "2 1",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "2.1@rc",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateEventSource(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_aws_s3",
			input:   "aws:s3",
			wantErr: false,
		},
		{
			name:    "valid_minio_s3",
			input:   "minio:s3",
			wantErr: false,
		},
		{
			name:    "valid_with_dots",
			input:   "aws.s3.us-east-1",
			wantErr: false,
		},
		{
			name:      "invalid_too_short",
			input:     "ab",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_space",
			input:     "aws s3",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
		{
			name:      "invalid_special_char",
			input:     "aws@s3",
			wantErr:   true,
			errSubstr: "alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventSource(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateEventTime(t *testing.T) {
	now := time.Now().UTC()
	validTime := now.Add(-1 * time.Hour).Format(time.RFC3339)
	futureTime := now.Add(1 * time.Hour).Format(time.RFC3339)
	tooOldTime := now.Add(-25 * time.Hour).Format(time.RFC3339)

	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_one_hour_ago",
			input:   validTime,
			wantErr: false,
		},
		{
			name:    "valid_just_now",
			input:   now.Format(time.RFC3339),
			wantErr: false,
		},
		{
			name:      "invalid_future",
			input:     futureTime,
			wantErr:   true,
			errSubstr: "future",
		},
		{
			name:      "invalid_too_old",
			input:     tooOldTime,
			wantErr:   true,
			errSubstr: "24 hours",
		},
		{
			name:      "invalid_wrong_format",
			input:     "2024-01-15 10:00:00",
			wantErr:   true,
			errSubstr: "RFC3339",
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "RFC3339",
		},
		{
			name:      "invalid_date_only",
			input:     "2024-01-15",
			wantErr:   true,
			errSubstr: "RFC3339",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventTime(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateRegion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_aws_region",
			input:   "us-east-1",
			wantErr: false,
		},
		{
			name:    "valid_with_dots",
			input:   "us.east.1",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "a",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_uppercase",
			input:     "US-EAST-1",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_space",
			input:     "us east 1",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_special_char",
			input:     "us@east",
			wantErr:   true,
			errSubstr: "lowercase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateIpAddress(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_ipv4",
			input:   "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid_ipv4_loopback",
			input:   "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "valid_ipv6",
			input:   "2001:db8::1",
			wantErr: false,
		},
		{
			name:    "valid_ipv6_full",
			input:   "2001:0db8:0000:0000:0000:0000:0000:0001",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_out_of_range_octet",
			input:     "999.999.999.999",
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "invalid_hostname",
			input:     "localhost",
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "invalid_with_port",
			input:     "192.168.1.1:8080",
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "invalid_partial",
			input:     "192.168.1",
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIpAddress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}

func TestValidateXMinioOriginRegion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_region",
			input:   "us-east-1",
			wantErr: false,
		},
		{
			name:    "valid_with_dots",
			input:   "us.east.1",
			wantErr: false,
		},
		{
			name:    "valid_single_char",
			input:   "a",
			wantErr: false,
		},
		{
			name:      "invalid_empty",
			input:     "",
			wantErr:   true,
			errSubstr: "between",
		},
		{
			name:      "invalid_uppercase",
			input:     "US-EAST-1",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_space",
			input:     "us east 1",
			wantErr:   true,
			errSubstr: "lowercase",
		},
		{
			name:      "invalid_special_char",
			input:     "us@east",
			wantErr:   true,
			errSubstr: "lowercase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateXMinioOriginRegion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
		})
	}
}
