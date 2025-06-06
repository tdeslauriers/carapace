package storage

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// New creates a new instance of the ObjectStorage interface.
func New(config Config, tls *tls.Config, expiry time.Duration) (ObjectStorage, error) {

	// tlsClient
	// needed to add CA of minio endpoint cert
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tls,
		},
	}

	// initialize MinIO client with the provided configuration
	minioClient, err := minio.New(config.Url, &minio.Options{
		Creds:     credentials.NewStaticV4(config.AccessKey, config.SecretKey, ""),
		Secure:    true,
		Transport: client.Transport,
	})
	if err != nil {
		return nil, err
	}

	return &minioStorage{
		ctx:    context.Background(),
		client: minioClient,
		bucket: config.Bucket,
		expiry: expiry,
	}, nil
}

var _ ObjectStorage = (*minioStorage)(nil)

// minioClient is a concrete implementation of the ObjectStorage interface for MinIO.
type minioStorage struct {
	ctx    context.Context
	client *minio.Client
	bucket string
	expiry time.Duration
}

// GetSignedUrl is the concrete impl of the interface method which
// generates a signed URL for accessing an object in the MinIO storage service.
func (m *minioStorage) GetSignedUrl(objectKey string) (*url.URL, error) {

	// fetches a signed URL for the specified object key with the defined expiry duration
	signedUrl, err := m.client.PresignedGetObject(m.ctx, m.bucket, objectKey, m.expiry, nil)
	if err != nil {
		return nil, err
	}

	// return the signed URL as a string
	return signedUrl, nil
}
