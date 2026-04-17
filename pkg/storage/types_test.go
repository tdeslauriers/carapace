package storage

import (
	"strings"
	"testing"
	"time"
)

// validRecord returns a fully-populated, valid Record for use as a base in tests.
func validRecord() Record {
	return Record{
		EventVersion: "2.1",
		EventSource:  "minio:s3",
		EventTimeRaw: time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339),
		EventName:    "s3:ObjectCreated:Put",
		S3: S3Entity{
			SchemaVersion: "1.0",
			Configuration: "MyConfig",
			Bucket: Bucket{
				Name: "my-bucket",
				OwnerIdentity: UserIdentity{
					PrincipalId: "pixie",
				},
				ARN: "arn:aws:s3:::my-bucket",
			},
			Object: S3Object{
				Key:          "uploads/photo.jpg",
				Size:         1024,
				ETag:         "d41d8cd98f00b204e9800998ecf8427e",
				Sequencer:    "0055AED6DCD90C26",
				ContentType:  "image/jpeg",
				VersionId:    "v1.0",
				StorageClass: "STANDARD",
			},
		},
		AwsRegion:          "us-east-1",
		SourceIPAddress:    "192.168.1.1",
		UserIdentity:       UserIdentity{PrincipalId: "pixie"},
		XMinioOriginRegion: "us-east-1",
	}
}

// --- S3Object ---
func TestS3ObjectValidate(t *testing.T) {
	tests := []struct {
		name      string
		obj       S3Object
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_key_only",
			obj: S3Object{
				Key: "uploads/photo.jpg",
			},
			wantErr: false,
		},
		{
			name: "valid_fully_populated",
			obj: S3Object{
				Key:          "uploads/photo.jpg",
				Size:         1024,
				ETag:         "d41d8cd98f00b204e9800998ecf8427e",
				Sequencer:    "0055AED6DCD90C26",
				ContentType:  "image/jpeg",
				VersionId:    "v1.0",
				StorageClass: "STANDARD",
			},
			wantErr: false,
		},
		{
			name: "invalid_key_too_short",
			obj: S3Object{
				Key: "ab",
			},
			wantErr:   true,
			errSubstr: "key",
		},
		{
			name: "invalid_key_empty",
			obj: S3Object{
				Key: "",
			},
			wantErr:   true,
			errSubstr: "key",
		},
		{
			name: "invalid_size_zero_is_skipped",
			obj: S3Object{
				Key:  "uploads/photo.jpg",
				Size: 0, // optional: zero means not set, should pass
			},
			wantErr: false,
		},
		{
			name: "invalid_size_negative",
			obj: S3Object{
				Key:  "uploads/photo.jpg",
				Size: -1,
			},
			wantErr:   true,
			errSubstr: "size",
		},
		{
			name: "invalid_etag_bad_chars",
			obj: S3Object{
				Key:  "uploads/photo.jpg",
				ETag: "not-valid-etag!",
			},
			wantErr:   true,
			errSubstr: "ETag",
		},
		{
			name: "invalid_sequencer_bad_chars",
			obj: S3Object{
				Key:       "uploads/photo.jpg",
				Sequencer: "bad@sequencer",
			},
			wantErr:   true,
			errSubstr: "sequencer",
		},
		{
			name: "invalid_content_type_no_slash",
			obj: S3Object{
				Key:         "uploads/photo.jpg",
				ContentType: "imagejpeg",
			},
			wantErr:   true,
			errSubstr: "content type",
		},
		{
			name: "invalid_version_id_bad_chars",
			obj: S3Object{
				Key:       "uploads/photo.jpg",
				VersionId: "version@1",
			},
			wantErr:   true,
			errSubstr: "version ID",
		},
		{
			name: "invalid_storage_class_space",
			obj: S3Object{
				Key:          "uploads/photo.jpg",
				StorageClass: "STANDARD IA",
			},
			wantErr:   true,
			errSubstr: "storage class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.obj.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for object key %q", tt.obj.Key)
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

// --- Bucket ---

func TestBucketValidate(t *testing.T) {
	tests := []struct {
		name      string
		bucket    Bucket
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_name_only",
			bucket: Bucket{
				Name: "my-bucket",
			},
			wantErr: false,
		},
		{
			name: "valid_fully_populated",
			bucket: Bucket{
				Name:          "my-bucket",
				OwnerIdentity: UserIdentity{PrincipalId: "pixie"},
				ARN:           "arn:aws:s3:::my-bucket",
			},
			wantErr: false,
		},
		{
			name: "invalid_bucket_name",
			bucket: Bucket{
				Name: "My_Bucket",
			},
			wantErr:   true,
			errSubstr: "bucket name",
		},
		{
			name: "invalid_owner_identity",
			bucket: Bucket{
				Name:          "my-bucket",
				OwnerIdentity: UserIdentity{PrincipalId: "INVALID123"},
			},
			wantErr:   true,
			errSubstr: "owner identity",
		},
		{
			name: "invalid_arn",
			bucket: Bucket{
				Name: "my-bucket",
				ARN:  "not-an-arn",
			},
			wantErr:   true,
			errSubstr: "ARN",
		},
		{
			name: "valid_empty_arn_skipped",
			bucket: Bucket{
				Name: "my-bucket",
				ARN:  "", // optional
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.bucket.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for bucket %q", tt.bucket.Name)
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

// --- UserIdentity ---

func TestUserIdentityValidate(t *testing.T) {
	tests := []struct {
		name      string
		identity  UserIdentity
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "valid_principal_id",
			identity: UserIdentity{PrincipalId: "pixie"},
			wantErr:  false,
		},
		{
			name:     "valid_empty_skipped",
			identity: UserIdentity{PrincipalId: ""},
			wantErr:  false,
		},
		{
			name:      "invalid_principal_id_uppercase",
			identity:  UserIdentity{PrincipalId: "Pixie"},
			wantErr:   true,
			errSubstr: "principal ID",
		},
		{
			name:      "invalid_principal_id_numbers",
			identity:  UserIdentity{PrincipalId: "pixie123"},
			wantErr:   true,
			errSubstr: "principal ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.identity.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for principal ID %q", tt.identity.PrincipalId)
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

// --- S3Entity ---

func TestS3EntityValidate(t *testing.T) {
	validEntity := S3Entity{
		SchemaVersion: "1.0",
		Configuration: "MyConfig",
		Bucket:        Bucket{Name: "my-bucket"},
		Object:        S3Object{Key: "uploads/photo.jpg"},
	}

	tests := []struct {
		name      string
		entity    S3Entity
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_fully_populated",
			entity:  validEntity,
			wantErr: false,
		},
		{
			name: "valid_optional_fields_omitted",
			entity: S3Entity{
				Bucket: Bucket{Name: "my-bucket"},
				Object: S3Object{Key: "uploads/photo.jpg"},
			},
			wantErr: false,
		},
		{
			name: "invalid_schema_version",
			entity: S3Entity{
				SchemaVersion: "bad version!",
				Bucket:        Bucket{Name: "my-bucket"},
				Object:        S3Object{Key: "uploads/photo.jpg"},
			},
			wantErr:   true,
			errSubstr: "schema version",
		},
		{
			name: "invalid_configuration",
			entity: S3Entity{
				Configuration: "bad config!",
				Bucket:        Bucket{Name: "my-bucket"},
				Object:        S3Object{Key: "uploads/photo.jpg"},
			},
			wantErr:   true,
			errSubstr: "configuration",
		},
		{
			name: "invalid_bucket",
			entity: S3Entity{
				Bucket: Bucket{Name: ""},
				Object: S3Object{Key: "uploads/photo.jpg"},
			},
			wantErr:   true,
			errSubstr: "bucket",
		},
		{
			name: "invalid_object",
			entity: S3Entity{
				Bucket: Bucket{Name: "my-bucket"},
				Object: S3Object{Key: ""},
			},
			wantErr:   true,
			errSubstr: "object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entity.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for entity with schema %q", tt.entity.SchemaVersion)
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

// --- Record ---

func TestRecordValidate(t *testing.T) {
	tests := []struct {
		name      string
		record    Record
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_fully_populated",
			record:  validRecord(),
			wantErr: false,
		},
		{
			name: "valid_all_optional_fields_omitted",
			record: Record{
				S3: S3Entity{
					Bucket: Bucket{Name: "my-bucket"},
					Object: S3Object{Key: "uploads/photo.jpg"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_event_version",
			record: func() Record {
				r := validRecord()
				r.EventVersion = "bad version!"
				return r
			}(),
			wantErr:   true,
			errSubstr: "event version",
		},
		{
			name: "invalid_event_source",
			record: func() Record {
				r := validRecord()
				r.EventSource = "bad source!"
				return r
			}(),
			wantErr:   true,
			errSubstr: "event source",
		},
		{
			name: "invalid_event_time_future",
			record: func() Record {
				r := validRecord()
				r.EventTimeRaw = time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
				return r
			}(),
			wantErr:   true,
			errSubstr: "event time",
		},
		{
			name: "invalid_event_name",
			record: func() Record {
				r := validRecord()
				r.EventName = "s3:ObjectRemoved:Delete"
				return r
			}(),
			wantErr:   true,
			errSubstr: "event name",
		},
		{
			name: "invalid_region",
			record: func() Record {
				r := validRecord()
				r.AwsRegion = "US-EAST-1"
				return r
			}(),
			wantErr:   true,
			errSubstr: "region",
		},
		{
			name: "invalid_source_ip",
			record: func() Record {
				r := validRecord()
				r.SourceIPAddress = "999.999.999.999"
				return r
			}(),
			wantErr:   true,
			errSubstr: "source IP",
		},
		{
			name: "invalid_user_identity",
			record: func() Record {
				r := validRecord()
				r.UserIdentity = UserIdentity{PrincipalId: "INVALID"}
				return r
			}(),
			wantErr:   true,
			errSubstr: "user identity",
		},
		{
			name: "invalid_xminio_origin_region",
			record: func() Record {
				r := validRecord()
				r.XMinioOriginRegion = "US-EAST-1"
				return r
			}(),
			wantErr:   true,
			errSubstr: "x-minio-origin-region",
		},
		{
			name: "invalid_s3_entity",
			record: func() Record {
				r := validRecord()
				r.S3.Bucket.Name = ""
				return r
			}(),
			wantErr:   true,
			errSubstr: "S3 entity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.record.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error in test %q", tt.name)
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

// --- WebhookPutObject ---

func TestWebhookPutObjectValidate(t *testing.T) {
	validRec := validRecord()

	tests := []struct {
		name      string
		webhook   WebhookPutObject
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid_fully_populated",
			webhook: WebhookPutObject{
				MinioKey:       "uploads/photo.jpg",
				MinioEventName: "s3:ObjectCreated:Put",
				Records:        []Record{validRec},
			},
			wantErr: false,
		},
		{
			name: "valid_optional_fields_omitted",
			webhook: WebhookPutObject{
				Records: []Record{validRec},
			},
			wantErr: false,
		},
		{
			name: "valid_empty_records",
			webhook: WebhookPutObject{
				MinioKey: "uploads/photo.jpg",
			},
			wantErr: false,
		},
		{
			name: "invalid_minio_key",
			webhook: WebhookPutObject{
				MinioKey: "../../etc/passwd",
				Records:  []Record{validRec},
			},
			wantErr:   true,
			errSubstr: "key",
		},
		{
			name: "invalid_minio_event_name",
			webhook: WebhookPutObject{
				MinioKey:       "uploads/photo.jpg",
				MinioEventName: "s3:ObjectRemoved:Delete",
				Records:        []Record{validRec},
			},
			wantErr:   true,
			errSubstr: "event name",
		},
		{
			name: "invalid_record",
			webhook: WebhookPutObject{
				Records: []Record{
					func() Record {
						r := validRecord()
						r.S3.Bucket.Name = ""
						return r
					}(),
				},
			},
			wantErr:   true,
			errSubstr: "record at index 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.webhook.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error in test %q", tt.name)
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
