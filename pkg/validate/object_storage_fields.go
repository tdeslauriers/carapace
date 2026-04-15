package validate

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// fields that are part of s3 event notifications and common in S3/MinIO payloads
const (
	KeyMinLength = 3
	KeyMaxLength = 1024

	EventNameMinLength = 3
	EventNameMaxLength = 120

	EventVersionMinLength = 1
	EventVersionMaxLength = 64
	EventVersionRegex     = `^[a-zA-Z0-9\.\-_]+$`

	EventSourceMinLength = 3
	EventSourceMaxLength = 64
	EventSourceRegex     = `^[a-zA-Z0-9\.\-_:]+$` // e.g., "aws:s3" or "minio:s3"

	PrincipalIDMinLength = 3
	PrincipalIDMaxLength = 64         // service names are typically short
	PrincipalRegex       = `^[a-z]+$` // just letters like "pixie" or "junk" --> not aws spec!

	BucketNameMinLength = 3
	BucketNameMaxLength = 63
	BucketNameRegex     = `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` // per AWS

	ArnMinLength = 20
	ArnMaxLength = 2048
	ArnRegex     = `^arn:([a-z0-9-]+):([a-z0-9-]+):([a-z0-9-]*):([0-9]{0,12}):(.+)$` // per AWS

	SchemaVersionMinLength = 1
	SchemaVersionMaxLength = 64
	SchemaVersionRegex     = `^[a-zA-Z0-9\.\-_]+$`

	ConfigurationMinLength = 3
	ConfigurationMaxLength = 64
	ConfigurationRegex     = `^[a-zA-Z0-9\.\-_]+$`

	S3ObjectSizeMin = 1                      // 1 byte
	S3ObjectSizeMax = 5 * 1024 * 1024 * 1024 // 5 TB

	EtagMinLength = 2
	EtagMaxLength = 255
	EtagRegex     = `^[a-fA-F0-9\-]+$`

	SequencerMinLength = 1
	SequencerMaxLength = 128
	SequencerRegex     = `^[a-zA-Z0-9]+$`

	ContentTypeMinLength = 3
	ContentTypeMaxLength = 255
	ContentTypeRegex     = `^[a-zA-Z0-9\.\-_]+\/[a-zA-Z0-9\.\-_]+$` // basic check for type/subtype format like "text/plain" or "application/json"

	VersionIdMinLength = 1
	VersionIdMaxLength = 255
	VersionIdRegex     = `^[a-zA-Z0-9\.\-_]+$`

	StorageClassMinLength = 3
	StorageClassMaxLength = 64
	StorageClassRegex     = `^[a-zA-Z0-9\.\-_]+$`

	RegionMinLength = 1
	RegionMaxLength = 64
	RegionRegex     = `^[a-z0-9\.\-_]+$`

	IpAddressMinLength = 7  // IPv4 min length
	IpAddressMaxLength = 45 // IPv6 max length

	XMinioOriginRegionMinLength = 1
	XMinioOriginRegionMaxLength = 64
	XMinioOriginRegionRegex     = `^[a-z0-9\.\-_]+$`
)

var (
	principalRegex          = regexp.MustCompile(PrincipalRegex)
	bucketNameRegex         = regexp.MustCompile(BucketNameRegex)
	arnRegex                = regexp.MustCompile(ArnRegex)
	schemaVersionRegex      = regexp.MustCompile(SchemaVersionRegex)
	configurationRegex      = regexp.MustCompile(ConfigurationRegex)
	etagRegex               = regexp.MustCompile(EtagRegex)
	sequencerRegex          = regexp.MustCompile(SequencerRegex)
	contentTypeRegex        = regexp.MustCompile(ContentTypeRegex)
	versionIdRegex          = regexp.MustCompile(VersionIdRegex)
	storageClassRegex       = regexp.MustCompile(StorageClassRegex)
	regionRegex             = regexp.MustCompile(RegionRegex)
	xMinioOriginRegionRegex = regexp.MustCompile(XMinioOriginRegionRegex)
	eventVersionRegex       = regexp.MustCompile(EventVersionRegex)
	eventSourceRegex        = regexp.MustCompile(EventSourceRegex)

	// allowedS3Events is a package-level var to avoid rebuilding the map on every call.
	allowedS3Events = map[string]bool{
		"s3:ObjectCreated:Put":                     true,
		"s3:ObjectCreated:Post":                    true,
		"s3:ObjectCreated:Copy":                    true,
		"s3:ObjectCreated:CompleteMultipartUpload": true,
	}
)

func IsAllowedEvent(eventName string) bool {
	return allowedS3Events[eventName]
}

func ValidateKey(key string) error {
	key = strings.TrimSpace(key)
	if TooShort(key, KeyMinLength) || TooLong(key, KeyMaxLength) {
		return fmt.Errorf("key must be between %d and %d characters in length", KeyMinLength, KeyMaxLength)
	}

	return nil
}

// ValidateEventName checks if the provided event name is valid.
func ValidateEventName(eventName string) error {
	eventName = strings.TrimSpace(eventName)
	if TooShort(eventName, EventNameMinLength) || TooLong(eventName, EventNameMaxLength) {
		return fmt.Errorf("event name must be between %d and %d characters in length", EventNameMinLength, EventNameMaxLength)
	}

	if !IsAllowedEvent(eventName) {
		return fmt.Errorf("event name %s is not allowed", eventName)
	}

	return nil
}

func ValidatePrincipalId(principalId string) error {
	principalId = strings.TrimSpace(principalId)
	if TooShort(principalId, PrincipalIDMinLength) || TooLong(principalId, PrincipalIDMaxLength) {
		return fmt.Errorf("principal ID must be between %d and %d characters in length", PrincipalIDMinLength, PrincipalIDMaxLength)
	}

	if !principalRegex.MatchString(principalId) {
		return fmt.Errorf("principal ID must only contain lowercase letters (a-z)")
	}

	return nil
}

// ValidateBucketName checks if the provided bucket name is valid.
func ValidateBucketName(bucketName string) error {
	bucketName = strings.TrimSpace(bucketName)
	if TooShort(bucketName, BucketNameMinLength) || TooLong(bucketName, BucketNameMaxLength) {
		return fmt.Errorf("bucket name must be between %d and %d characters in length", BucketNameMinLength, BucketNameMaxLength)
	}

	if !bucketNameRegex.MatchString(bucketName) {
		return fmt.Errorf("bucket name must only contain lowercase letters (a-z), numbers (0-9), dots (.), and hyphens (-). It cannot start or end with a hyphen or dot, nor have consecutive dots or hyphens")
	}

	return nil
}

// ValidateArn checks if the provided ARN is valid.
func ValidateArn(arn string) error {
	arn = strings.TrimSpace(arn)
	if TooShort(arn, ArnMinLength) || TooLong(arn, ArnMaxLength) {
		return fmt.Errorf("ARN must be between %d and %d characters in length", ArnMinLength, ArnMaxLength)
	}

	if !arnRegex.MatchString(arn) {
		return fmt.Errorf("invalid ARN format")
	}

	return nil
}

// ValidateSize checks if the provided size is within the allowed S3 object size range.
func ValidateSize(size int64) error {

	if size < S3ObjectSizeMin || size > S3ObjectSizeMax {
		return fmt.Errorf("object size must be between %d bytes and %d bytes", S3ObjectSizeMin, S3ObjectSizeMax)
	}

	return nil
}

// ValidateEtag checks if the provided ETag is valid.
func ValidateEtag(etag string) error {
	etag = strings.TrimSpace(etag)
	if TooShort(etag, EtagMinLength) || TooLong(etag, EtagMaxLength) {
		return fmt.Errorf("ETag must be between %d and %d characters in length", EtagMinLength, EtagMaxLength)
	}

	if !etagRegex.MatchString(etag) {
		return fmt.Errorf("ETag must only contain hexadecimal characters (0-9, a-f, A-F) and hyphens (-)")
	}

	return nil
}

// ValidateSequencer checks if the provided sequencer is valid.
func ValidateSequencer(sequencer string) error {
	sequencer = strings.TrimSpace(sequencer)
	if TooShort(sequencer, SequencerMinLength) || TooLong(sequencer, SequencerMaxLength) {
		return fmt.Errorf("sequencer must be between %d and %d characters in length", SequencerMinLength, SequencerMaxLength)
	}

	if !sequencerRegex.MatchString(sequencer) {
		return fmt.Errorf("sequencer must only contain alphanumeric characters (a-z, A-Z, 0-9)")
	}

	return nil
}

// ValidateContentType checks if the provided content type is valid.
func ValidateContentType(contentType string) error {
	contentType = strings.TrimSpace(contentType)
	if TooShort(contentType, ContentTypeMinLength) || TooLong(contentType, ContentTypeMaxLength) {
		return fmt.Errorf("content type must be between %d and %d characters in length", ContentTypeMinLength, ContentTypeMaxLength)
	}

	// basic check for content type format (e.g., "text/plain", "application/json")
	if !contentTypeRegex.MatchString(contentType) {
		return fmt.Errorf("invalid content type format")
	}

	return nil
}

// ValidateVersionId checks if the provided version ID is valid.
func ValidateVersionId(versionId string) error {
	versionId = strings.TrimSpace(versionId)
	if TooShort(versionId, VersionIdMinLength) || TooLong(versionId, VersionIdMaxLength) {
		return fmt.Errorf("version ID must be between %d and %d characters in length", VersionIdMinLength, VersionIdMaxLength)
	}

	if !versionIdRegex.MatchString(versionId) {
		return fmt.Errorf("version ID must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateStorageClass checks if the provided storage class is valid.
func ValidateStorageClass(storageClass string) error {
	storageClass = strings.TrimSpace(storageClass)
	if TooShort(storageClass, StorageClassMinLength) || TooLong(storageClass, StorageClassMaxLength) {
		return fmt.Errorf("storage class must be between %d and %d characters in length", StorageClassMinLength, StorageClassMaxLength)
	}

	if !storageClassRegex.MatchString(storageClass) {
		return fmt.Errorf("storage class must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateSchemaVersion checks if the provided schema version is valid.
func ValidateSchemaVersion(schemaVersion string) error {
	schemaVersion = strings.TrimSpace(schemaVersion)
	if TooShort(schemaVersion, SchemaVersionMinLength) || TooLong(schemaVersion, SchemaVersionMaxLength) {
		return fmt.Errorf("schema version must be between %d and %d characters in length", SchemaVersionMinLength, SchemaVersionMaxLength)
	}

	if !schemaVersionRegex.MatchString(schemaVersion) {
		return fmt.Errorf("schema version must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateConfiguration checks if the provided configuration ID is valid.
func ValidateConfiguration(configuration string) error {
	configuration = strings.TrimSpace(configuration)
	if TooShort(configuration, ConfigurationMinLength) || TooLong(configuration, ConfigurationMaxLength) {
		return fmt.Errorf("configuration must be between %d and %d characters in length", ConfigurationMinLength, ConfigurationMaxLength)
	}

	if !configurationRegex.MatchString(configuration) {
		return fmt.Errorf("configuration must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateEventVersion checks if the provided event version is valid.
func ValidateEventVersion(eventVersion string) error {
	eventVersion = strings.TrimSpace(eventVersion)
	if TooShort(eventVersion, EventVersionMinLength) || TooLong(eventVersion, EventVersionMaxLength) {
		return fmt.Errorf("event version must be between %d and %d characters in length", EventVersionMinLength, EventVersionMaxLength)
	}

	if !eventVersionRegex.MatchString(eventVersion) {
		return fmt.Errorf("event version must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateEventSource checks if the provided event source is valid.
func ValidateEventSource(eventSource string) error {
	eventSource = strings.TrimSpace(eventSource)
	if TooShort(eventSource, EventSourceMinLength) || TooLong(eventSource, EventSourceMaxLength) {
		return fmt.Errorf("event source must be between %d and %d characters in length", EventSourceMinLength, EventSourceMaxLength)
	}

	if !eventSourceRegex.MatchString(eventSource) {
		return fmt.Errorf("event source must only contain alphanumeric characters (a-z, A-Z, 0-9), dots (.), hyphens (-), underscores (_), and colons (:)")
	}

	return nil
}

// ValidateEventTime checks if the provided event time is valid (not in the future and not too old).
func ValidateEventTime(eventTime string) error {
	eventTime = strings.TrimSpace(eventTime)
	parsedTime, err := time.Parse(time.RFC3339, eventTime)
	if err != nil {
		return fmt.Errorf("event time must be in RFC3339 format: %v", err)
	}

	// assign once so both comparisons use the same instant
	now := time.Now().UTC()

	if parsedTime.After(now) {
		return fmt.Errorf("event time cannot be in the future")
	}

	if parsedTime.Before(now.Add(-24 * time.Hour)) {
		return fmt.Errorf("event time cannot be older than 24 hours")
	}

	return nil
}

// ValidateRegion checks if the provided region is valid.
func ValidateRegion(region string) error {
	region = strings.TrimSpace(region)
	if TooShort(region, RegionMinLength) || TooLong(region, RegionMaxLength) {
		return fmt.Errorf("region must be between %d and %d characters in length", RegionMinLength, RegionMaxLength)
	}

	if !regionRegex.MatchString(region) {
		return fmt.Errorf("region must only contain lowercase letters (a-z), numbers (0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}

// ValidateIpAddress checks if the provided IP address is a valid IPv4 or IPv6 address.
// Uses net.ParseIP from the standard library instead of regex to avoid accepting
// structurally valid but numerically invalid addresses like 999.999.999.999.
func ValidateIpAddress(ipAddress string) error {
	ipAddress = strings.TrimSpace(ipAddress)
	if TooShort(ipAddress, IpAddressMinLength) || TooLong(ipAddress, IpAddressMaxLength) {
		return fmt.Errorf("IP address must be between %d and %d characters in length", IpAddressMinLength, IpAddressMaxLength)
	}

	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

// ValidateXMinioOriginRegion checks if the provided x-minio-origin-region is valid.
func ValidateXMinioOriginRegion(originRegion string) error {
	originRegion = strings.TrimSpace(originRegion)
	if TooShort(originRegion, XMinioOriginRegionMinLength) || TooLong(originRegion, XMinioOriginRegionMaxLength) {
		return fmt.Errorf("x-minio-origin-region must be between %d and %d characters in length", XMinioOriginRegionMinLength, XMinioOriginRegionMaxLength)
	}

	if !xMinioOriginRegionRegex.MatchString(originRegion) {
		return fmt.Errorf("x-minio-origin-region must only contain lowercase letters (a-z), numbers (0-9), dots (.), hyphens (-), and underscores (_)")
	}

	return nil
}
