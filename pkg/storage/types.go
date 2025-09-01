package storage

import (
	"fmt"
	"net/url"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Config holds the configuration for connecting to an object storage service.
type Config struct {
	Url       string
	Bucket    string
	AccessKey string
	SecretKey string
}

// ObjectStorage is an interface that defines methods for interacting with object storage services.
// It can be implemented by various object storage clients, such as MinIO, AWS S3, etc.
type ObjectStorage interface {

	// GetSignedUrl generates a signed URL for accessing an object in the storage service.
	GetSignedUrl(objectKey string) (*url.URL, error)

	// GetPreSignedPutUrl generates a pre-signed URL for uploading an object to the storage service.
	GetPreSignedPutUrl(objectKey string) (*url.URL, error)

	// MoveObject moves an object from one location to another within the storage service
	MoveObject(src, dst string) error
}

// WebhookPutObject represents the payload received from a MinIO webhook notification for object creation events.
// MinIO mostly follows AWS S3's event schema, but may include convenience
// top-level fields like Key and EventName.
type WebhookPutObject struct {
	// MinIO convenience (not part of AWS schema)
	MinioKey       string `json:"Key,omitempty"`
	MinioEventName string `json:"EventName,omitempty"`

	Records []Record `json:"Records"`
}

// Validate checks if the WebhookPutObject's fields are valid/well-formed.
func (w *WebhookPutObject) Validate() error {

	// validate key if it is set
	if w.MinioKey != "" {
		if err := validate.ValidateKey(w.MinioKey); err != nil {
			return fmt.Errorf("invalid key in webhook payload: %v", err)
		}
	}

	// validate event name if it is set
	if w.MinioEventName != "" {
		if err := validate.ValidateEventName(w.MinioEventName); err != nil {
			return fmt.Errorf("invalid event name in webhook payload: %v", err)
		}
	}

	// validate each record
	for i, record := range w.Records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("invalid record at index %d in webhook payload: %v", i, err)
		}
	}

	return nil
}

// Record represents a single event record in the MinIO webhook notification payload.
type Record struct {
	EventVersion string `json:"eventVersion,omitempty"`
	EventSource  string `json:"eventSource,omitempty"` // e.g., "minio:s3"
	EventTimeRaw string `json:"eventTime,omitempty"`   // RFC3339
	EventName    string `json:"eventName,omitempty"`   // e.g., "s3:ObjectCreated:Put"

	S3 S3Entity `json:"s3"`

	// Common optional fields seen in S3/MinIO payloads
	RequestParameters  map[string]any `json:"requestParameters,omitempty"`
	ResponseElements   map[string]any `json:"responseElements,omitempty"`
	AwsRegion          string         `json:"awsRegion,omitempty"`
	SourceIPAddress    string         `json:"sourceIPAddress,omitempty"`
	UserIdentity       UserIdentity   `json:"userIdentity,omitempty"`
	XMinioOriginRegion string         `json:"x-minio-origin-region,omitempty"`
}

// Validate checks if the Record's fields are valid/well-formed.
func (r *Record) Validate() error {

	// validate event version if it is set
	if r.EventVersion != "" {
		if err := validate.ValidateEventVersion(r.EventVersion); err != nil {
			return fmt.Errorf("invalid event version in record: %v", err)
		}
	}

	// validate event source if it is set
	if r.EventSource != "" {
		if err := validate.ValidateEventSource(r.EventSource); err != nil {
			return fmt.Errorf("invalid event source in record: %v", err)
		}
	}

	// validate event time if it is set
	if r.EventTimeRaw != "" {
		if err := validate.ValidateEventTime(r.EventTimeRaw); err != nil {
			return fmt.Errorf("invalid event time in record: %v", err)
		}
	}

	// validate event name if it is set
	if r.EventName != "" {
		if err := validate.ValidateEventName(r.EventName); err != nil {
			return fmt.Errorf("invalid event name in record: %v", err)
		}
	}

	// validate S3 entity
	if err := r.S3.Validate(); err != nil {
		return fmt.Errorf("invalid S3 entity in record: %v", err)
	}

	// validate region if it is set
	if r.AwsRegion != "" {
		if err := validate.ValidateRegion(r.AwsRegion); err != nil {
			return fmt.Errorf("invalid AWS region in record: %v", err)
		}
	}

	// validate source IP address if it is set
	if r.SourceIPAddress != "" {
		if err := validate.ValidateIpAddress(r.SourceIPAddress); err != nil {
			return fmt.Errorf("invalid source IP address in record: %v", err)
		}
	}

	// validate user identity if it is set
	if err := r.UserIdentity.Validate(); err != nil {
		return fmt.Errorf("invalid user identity in record: %v", err)
	}

	// validate x-minio-origin-region if it is set
	if r.XMinioOriginRegion != "" {
		if err := validate.ValidateXMinioOriginRegion(r.XMinioOriginRegion); err != nil {
			return fmt.Errorf("invalid x-minio-origin-region in record: %v", err)
		}
	}

	return nil
}

// UserIdentity represents the identity of the user who initiated the event.
type UserIdentity struct {
	PrincipalId string `json:"principalId,omitempty"`
}

// Validate checks if the UserIdentity's fields are valid/well-formed.
func (u *UserIdentity) Validate() error {

	// check principal ID if it is set
	if u.PrincipalId != "" {
		if err := validate.ValidatePrincipalId(u.PrincipalId); err != nil {
			return fmt.Errorf("invalid principal ID in user identity: %v", err)
		}
	}

	return nil
}

// S3Entity represents the S3-specific details of the event.
type S3Entity struct {
	SchemaVersion string   `json:"s3SchemaVersion,omitempty"`
	Configuration string   `json:"configurationId,omitempty"`
	Bucket        Bucket   `json:"bucket"`
	Object        S3Object `json:"object"`
}

// Validate checks if the S3Entity's fields are valid/well-formed.
func (s *S3Entity) Validate() error {

	// validate schema version if it is set
	if s.SchemaVersion != "" {
		if err := validate.ValidateSchemaVersion(s.SchemaVersion); err != nil {
			return fmt.Errorf("invalid schema version in S3 entity: %v", err)
		}
	}

	// validate configuration  if it is set
	if s.Configuration != "" {
		if err := validate.ValidateConfiguration(s.Configuration); err != nil {
			return fmt.Errorf("invalid configuration ID in S3 entity: %v", err)
		}
	}

	// validate bucket
	if err := s.Bucket.Validate(); err != nil {
		return fmt.Errorf("invalid bucket in S3 entity: %v", err)
	}

	// validate object
	if err := s.Object.Validate(); err != nil {
		return fmt.Errorf("invalid object in S3 entity: %v", err)
	}

	return nil
}

// Bucket represents the S3 bucket involved in the event.
type Bucket struct {
	Name          string       `json:"name"`
	OwnerIdentity UserIdentity `json:"ownerIdentity,omitempty"`
	ARN           string       `json:"arn,omitempty"`
}

// Validate checks if the Bucket's fields are valid/well-formed.
func (b *Bucket) Validate() error {

	// check bucket name
	if err := validate.ValidateBucketName(b.Name); err != nil {
		return fmt.Errorf("invalid bucket name in bucket: %v", err)
	}

	// validate owner identity if it is set
	if err := b.OwnerIdentity.Validate(); err != nil {
		return fmt.Errorf("invalid owner identity in bucket: %v", err)
	}

	// check ARN if it is set
	if b.ARN != "" {
		if err := validate.ValidateArn(b.ARN); err != nil {
			return fmt.Errorf("invalid ARN in bucket: %v", err)
		}
	}

	return nil

}

// S3Object represents the S3 object involved in the event.
type S3Object struct {
	Key          string `json:"key"`
	Size         int64  `json:"size,omitempty"`
	ETag         string `json:"eTag,omitempty"`
	Sequencer    string `json:"sequencer,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
	VersionId    string `json:"versionId,omitempty"`
	StorageClass string `json:"storageClass,omitempty"`
}

// Validate checks if the S3Object's fields are valid/well-formed.
func (o *S3Object) Validate() error {

	// check object key
	if len(o.Key) < validate.KeyMinLength || len(o.Key) > validate.KeyMaxLength {
		return fmt.Errorf("invalid object key length in object: must be between %d and %d characters", validate.KeyMinLength, validate.KeyMaxLength)
	}

	// check size if it is set
	if o.Size != 0 {
		if err := validate.ValidateSize(o.Size); err != nil {
			return fmt.Errorf("invalid size in object: %v", err)
		}
	}

	// check ETag if it is set
	if o.ETag != "" {
		if err := validate.ValidateEtag(o.ETag); err != nil {
			return fmt.Errorf("invalid ETag in object: %v", err)
		}
	}

	// check sequencer if it is set
	if o.Sequencer != "" {
		if err := validate.ValidateSequencer(o.Sequencer); err != nil {
			return fmt.Errorf("invalid sequencer in object: %v", err)
		}
	}

	// check content type if it is set
	if o.ContentType != "" {
		if err := validate.ValidateContentType(o.ContentType); err != nil {
			return fmt.Errorf("invalid content type in object: %v", err)
		}
	}

	// check version ID if it is set
	if o.VersionId != "" {
		if err := validate.ValidateVersionId(o.VersionId); err != nil {
			return fmt.Errorf("invalid version ID in object: %v", err)
		}
	}

	// storage class is optional and may be empty
	if o.StorageClass != "" {
		if err := validate.ValidateStorageClass(o.StorageClass); err != nil {
			return fmt.Errorf("invalid storage class in object: %v", err)
		}
	}

	return nil
}
