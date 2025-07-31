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
