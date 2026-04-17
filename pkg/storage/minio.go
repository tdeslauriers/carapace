package storage

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/validate"
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
		client: minioClient,
		bucket: config.Bucket,
		expiry: expiry,

		logger: slog.Default().
			With(slog.String(util.ComponentKey, util.ComponentStorage)).
			With(slog.String(util.FrameworkKey, util.FrameworkCarapace)).
			With(slog.String(util.PackageKey, util.PackageStorage)),
	}, nil
}

var _ ObjectStorage = (*minioStorage)(nil)

// minioClient is a concrete implementation of the ObjectStorage interface for MinIO.
type minioStorage struct {
	client *minio.Client
	bucket string
	expiry time.Duration

	logger *slog.Logger
}

// WithObject is the concrete implementation of the ObjectStorage interface method
// which retrieves an object (ie, a file) as a stream from the MinIO storage service
// and allows the caller to inject an operation like reading exif data, etc.
// NOTE: minio.Object is an open http stream
func (m *minioStorage) WithObject(ctx context.Context, key string, fn func(r ReadSeekCloser) error) error {

	if err := validate.ValidateKey(key); err != nil {
		return fmt.Errorf("invalid object key: %v", err)
	}

	// check the object exists in the bucket by stat'ing it
	if _, err := m.client.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{}); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return fmt.Errorf("object '%s' does not exist in bucket '%s'", key, m.bucket)
		}
		return fmt.Errorf("failed to stat storage object '%s': %v", key, err)
	}

	// get the object from the bucket
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to get storage object '%s': %v", key, err)
	}

	defer obj.Close()

	// call the provided function with the object stream
	return fn(obj)
}

// GetSignedUrl is the concrete impl of the interface method which
// generates a signed URL for accessing an object in the MinIO storage service.
func (m *minioStorage) GetSignedUrl(ctx context.Context, objectKey string) (*url.URL, error) {

	if err := validate.ValidateKey(objectKey); err != nil {
		return nil, fmt.Errorf("invalid object key: %v", err)
	}

	// check if the object key exists in the bucket
	if _, err := m.client.StatObject(ctx, m.bucket, objectKey, minio.StatObjectOptions{}); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("object '%s' does not exist in bucket '%s'", objectKey, m.bucket)
		}
		return nil, fmt.Errorf("failed to stat storage object '%s': %v", objectKey, err)
	}

	// fetches a signed URL for the specified object key with the defined expiry duration
	// NOTE: this client method does not check if the object exists, it will return a signed URL regardless
	signedUrl, err := m.client.PresignedGetObject(ctx, m.bucket, objectKey, m.expiry, nil)
	if err != nil {
		return nil, err
	}

	// return the signed URL as a string
	return signedUrl, nil
}

// GetPreSignedPutUrl is the concrete impl of the interface method which
// generates a pre-signed URL for uploading an object to the MinIO storage service.
func (m *minioStorage) GetPreSignedPutUrl(ctx context.Context, objectKey string) (*url.URL, error) {

	// validate the object key before attempting to generate a signed URL
	if err := validate.ValidateKey(objectKey); err != nil {
		return nil, fmt.Errorf("invalid object key: %v", err)
	}

	// fetches a signed URL for the specified object key with the defined expiry duration
	signedUrl, err := m.client.PresignedPutObject(ctx, m.bucket, objectKey, m.expiry)
	if err != nil {
		return nil, err
	}

	// return the signed URL as a string
	return signedUrl, nil
}

// MoveObject is a the concrete implementation of the ObjectStorage interface method
// which moves an object from one location to another in the MinIO storage service.
// Note: outcome is similiar to a linux mv command, which rather than moving the object, effectively renames it.
// Impl: it copies the object to the new location/namespace and then removes the original object.
func (m *minioStorage) MoveObject(ctx context.Context, src, dst string) error {

	if err := validate.ValidateKey(src); err != nil {
		return fmt.Errorf("invalid source object key: %v", err)
	}

	if err := validate.ValidateKey(dst); err != nil {
		return fmt.Errorf("invalid destination object key: %v", err)
	}

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
	_, err := m.client.CopyObject(ctx, dstOpts, srcOpts)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return fmt.Errorf("source object '%s' does not exist in object storage", src)
		}

		return fmt.Errorf("failed to copy object from '%s' to '%s': %v", src, dst, err)
	}

	// remove the original object after copying
	err = m.client.RemoveObject(ctx, m.bucket, src, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to remove original object '%s' after succcessfully copying it to '%s': %v", src, dst, err)
	}

	return nil
}

// func PutObject is a the concrete implementation of the ObjectStorage interface method
// which uploads an object to the MinIO storage service.
func (m *minioStorage) PutObject(ctx context.Context, key string, data []byte, contentType string) error {

	opts := minio.PutObjectOptions{
		ContentType: contentType,
	}

	// upload the object to the bucket
	_, err := m.client.PutObject(
		ctx,
		m.bucket,
		key,
		bytes.NewReader(data),
		int64(len(data)),
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to put object '%s' to bucket '%s': %v", key, m.bucket, err)
	}

	return nil
}
