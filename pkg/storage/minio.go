package storage

import (
	"context"
	"crypto/tls"
	"fmt"
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

	// check if the object key exists in the bucket
	if _, err := m.client.StatObject(m.ctx, m.bucket, objectKey, minio.StatObjectOptions{}); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("object '%s' does not exist in bucket '%s'", objectKey, m.bucket)
		}
		return nil, fmt.Errorf("failed to stat storage object '%s': %v", objectKey, err)
	}

	// fetches a signed URL for the specified object key with the defined expiry duration
	// NOTE: this client method does not check if the object exists, it will return a signed URL regardless
	signedUrl, err := m.client.PresignedGetObject(m.ctx, m.bucket, objectKey, m.expiry, nil)
	if err != nil {
		return nil, err
	}

	// return the signed URL as a string
	return signedUrl, nil
}

func (m *minioStorage) GetPreSignedPutUrl(objectKey string) (*url.URL, error) {

	// fetches a signed URL for the specified object key with the defined expiry duration
	signedUrl, err := m.client.PresignedPutObject(m.ctx, m.bucket, objectKey, m.expiry)
	if err != nil {
		return nil, err
	}

	// return the signed URL as a string
	return signedUrl, nil
}

// MoveObject is a the concrete implementation of the ObjectStorage interface method
// which moves an object from one location to another in the MinIO storage service.
// Note: this is similiar to a linux mv command, which rather than moving the object, effectively renames it.
// Impl: it copies the object to the new location/namespace and then removes the original object.
func (m *minioStorage) MoveObject(src, dst string) error {

	// check that the current object key and the new object key are not the same
	if src == dst {
		return nil // no need to move if the keys are the same
	}

	srcOpts := minio.CopySrcOptions{
		Bucket: m.bucket,
		Object: src,
	}

	dstOpts := minio.CopyDestOptions{
		Bucket: m.bucket,
		Object: dst,
	}

	// copy the object from the source to the destination
	_, err := m.client.CopyObject(m.ctx, dstOpts, srcOpts)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return fmt.Errorf("source object '%s' does not exist in object storage", src)
		} else {
			return fmt.Errorf("failed to copy object from '%s' to '%s': %v", src, dst, err)
		}
	}

	// remove the original object after copying
	err = m.client.RemoveObject(m.ctx, m.bucket, src, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to remove original object '%s' after copying to '%s': %v", src, dst, err)
	}

	return nil
}
