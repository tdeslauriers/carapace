package storage

import "net/url"

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
	TopLevelKey       string `json:"Key,omitempty"`
	TopLevelEventName string `json:"EventName,omitempty"`

	Records []Record `json:"Records"`
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

// UserIdentity represents the identity of the user who initiated the event.
type UserIdentity struct {
	PrincipalID string `json:"principalId,omitempty"`
}

// S3Entity represents the S3-specific details of the event.
type S3Entity struct {
	SchemaVersion string   `json:"s3SchemaVersion,omitempty"`
	Configuration string   `json:"configurationId,omitempty"`
	Bucket        Bucket   `json:"bucket"`
	Object        S3Object `json:"object"`
}

// Bucket represents the S3 bucket involved in the event.
type Bucket struct {
	Name          string       `json:"name"`
	OwnerIdentity UserIdentity `json:"ownerIdentity,omitempty"`
	ARN           string       `json:"arn,omitempty"`
}

// S3Object represents the S3 object involved in the event.
type S3Object struct {
	Key          string `json:"key"`
	Size         int64  `json:"size,omitempty"`
	ETag         string `json:"eTag,omitempty"`
	Sequencer    string `json:"sequencer,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
	VersionID    string `json:"versionId,omitempty"`
	StorageClass string `json:"storageClass,omitempty"`
}
