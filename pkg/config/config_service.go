package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// requireEnv looks up a required environment variable, returning an error if absent.
func requireEnv(key string) (string, error) {

	v, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("%s not set", key)
	}

	return v, nil
}

// prefix returns the upper-cased service name with a trailing underscore, e.g. "MYSERVICE_".
func (d SvcDefinition) prefix() string {

	return strings.ToUpper(d.ServiceName) + "_"
}

// validatePort checks that port has the required leading-colon format, e.g. ":8443".
func validatePort(port string) error {

	if len(port) < 2 || port[0] != ':' {
		return fmt.Errorf("invalid port %q: must have leading colon, e.g. :8443", port)
	}

	n, err := strconv.Atoi(port[1:])
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q: must be a valid port number, e.g. :8443", port)
	}

	return nil
}

// validateURL checks that raw is a well-formed URL with an http or https scheme
// and a non-empty host. The scheme check is performed before url.Parse because
// bare host:port values (e.g. "192.168.68.54:9003") are misread by url.Parse
// as relative path references, producing the opaque error "first path segment
// in URL cannot contain colon". Checking the prefix first gives a clear error
// and prevents url.Parse from ever seeing the ambiguous input.
func validateURL(raw string) error {

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return fmt.Errorf("invalid url %q: scheme must be http or https", raw)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}

	if u.Host == "" {
		return fmt.Errorf("invalid url %q: host is empty", raw)
	}

	return nil
}

// Load loads the service configuration from environment variables based on the provided service definition.
func Load(def SvcDefinition) (*Config, error) {

	if def.ServiceName == "" {
		return nil, fmt.Errorf("service name must be provided to definitions, cannot be empty")
	}

	p := def.prefix()

	// client id
	clientID, err := requireEnv(p + "SERVICE_CLIENT_ID")
	if err != nil {
		return nil, err
	}

	// port
	port, err := requireEnv(p + "SERVICE_PORT")
	if err != nil {

		return nil, err
	}

	// validate port format
	if err = validatePort(port); err != nil {

		return nil, err
	}

	// set top level config fields from env vars and service definition
	config := &Config{
		ServiceName:     def.ServiceName,
		Tls:             def.Tls,
		ServiceClientId: clientID,
		ServicePort:     port,
	}

	// if tls is not none, read cert-related env vars into config struct based on s
	// ervice definition requirements
	if def.Tls != NoneTls {
		if err = config.readCerts(def); err != nil {

			return nil, err
		}
	}

	// if database is required, read database-related env vars into config struct based on
	// service definition requirements
	if def.Requires.Db {
		if err = config.databaseEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if s2s client is required, read s2s auth related env vars into config struct based on
	// service definition requirements
	if def.Requires.S2sClient {
		if err = config.s2sAuthEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if user identity is required, read identity service related env vars into config struct based on
	// service definition requirements
	if def.Requires.Identity {
		if err = config.userAuthEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if any jwt keys are required, read jwt related env vars into config struct based on
	// service definition requirements
	if def.Requires.S2sSigningKey ||
		def.Requires.S2sVerifyingKey ||
		def.Requires.UserSigningKey ||
		def.Requires.UserVerifyingKey {

		if err = config.jwtEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if pat generation is required, read pat related env vars into config struct based on
	// service definition requirements
	if def.Requires.PatGenerator {

		pepper, err := requireEnv(p + "PAT_PEPPER")
		if err != nil {

			return nil, err
		}

		config.Pat.Pepper = pepper
	}

	// if oauth redirect is required, read oauth redirect related env vars into config struct based on
	// service definition requirements
	if def.Requires.OauthRedirect {

		// callback url
		callbackURL, err := requireEnv(p + "OAUTH_CALLBACK_URL")
		if err != nil {

			return nil, err
		}

		// validate callback url
		if err = validateURL(callbackURL); err != nil {
			return nil, err
		}

		config.OauthRedirect.CallbackUrl = callbackURL

		// callback client id
		callbackClientID, err := requireEnv(p + "OAUTH_CALLBACK_CLIENT_ID")
		if err != nil {
			return nil, err
		}

		config.OauthRedirect.CallbackClientId = callbackClientID
	}

	// if the task service is required, read task service related env vars into config
	if def.Requires.Tasks {

		if err = config.tasksServiceEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if the gallery service is required, read gallery service related env vars into config
	if def.Requires.Gallery {

		if err = config.galleryServiceEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if object storage is required, read object storage related env vars into config
	if def.Requires.ObjectStorage {

		if err = config.objectStorageEnvVars(def); err != nil {

			return nil, err
		}
	}

	// if profiles service is required, read profiles service related env vars into config
	if def.Requires.Profiles {

		if err = config.profilesServiceEnvVars(def); err != nil {

			return nil, err
		}
	}

	return config, nil
}

// readCerts loads certificate-related environment variables into the config struct based on the service definition.
func (config *Config) readCerts(def SvcDefinition) error {

	p := def.prefix()

	// server cert
	serverCert, err := requireEnv(p + "SERVER_CERT")
	if err != nil {

		return err
	}

	config.Certs.ServerCert = &serverCert

	// server key
	serverKey, err := requireEnv(p + "SERVER_KEY")
	if err != nil {

		return err
	}

	config.Certs.ServerKey = &serverKey

	// s2s client env vars
	if def.Requires.S2sClient || def.Requires.ObjectStorage {

		// client cert -> for mTLS to s2s service
		clientCert, err := requireEnv(p + "CLIENT_CERT")
		if err != nil {

			return err
		}

		config.Certs.ClientCert = &clientCert

		// client key -> for mTLS to s2s service
		clientKey, err := requireEnv(p + "CLIENT_KEY")
		if err != nil {

			return err
		}

		config.Certs.ClientKey = &clientKey
	}

	// db client certs if db is required
	if def.Requires.Db {

		// client for calling db
		dbClientCert, err := requireEnv(p + "DB_CLIENT_CERT")
		if err != nil {

			return err
		}

		config.Certs.DbClientCert = &dbClientCert

		// client key for calling db
		dbClientKey, err := requireEnv(p + "DB_CLIENT_KEY")
		if err != nil {
			return err
		}

		config.Certs.DbClientKey = &dbClientKey
	}

	// if mTLS, s2s client, or object storage is required, a CA cert is needed to
	// verify the cert presented by the service we are calling
	if def.Tls == MutualTls || def.Requires.S2sClient || def.Requires.ObjectStorage {

		// ca cert
		caCert, err := requireEnv(p + "CA_CERT")
		if err != nil {

			return err
		}

		// if mTLS, we need the CA cert to verify incoming calls to the service
		if def.Tls == MutualTls {
			config.Certs.ServerCa = &caCert
		}

		// if s2s client or object storage, CA cert is needed to
		// verify outgoing calls to those services
		if def.Requires.S2sClient || def.Requires.ObjectStorage {
			config.Certs.ClientCa = &caCert
		}
	}

	// if db is required, need a db CA cert to verify the db's cert depending on the db configuration
	if def.Requires.Db {

		dbCaCert, err := requireEnv(p + "DB_CA_CERT")
		if err != nil {

			return err
		}

		config.Certs.DbCaCert = &dbCaCert
	}

	return nil
}

// databaseEnvVars loads database-related environment variables into the config struct based on
// the service definition.
func (config *Config) databaseEnvVars(def SvcDefinition) error {

	p := def.prefix()

	// db url
	url, err := requireEnv(p + "DATABASE_URL")
	if err != nil {

		return err
	}

	config.Database.Url = url

	// db name
	name, err := requireEnv(p + "DATABASE_NAME")
	if err != nil {

		return err
	}

	config.Database.Name = name

	// db username
	username, err := requireEnv(p + "DATABASE_USERNAME")
	if err != nil {

		return err
	}

	config.Database.Username = username

	// db password
	password, err := requireEnv(p + "DATABASE_PASSWORD")
	if err != nil {

		return err
	}

	config.Database.Password = password

	// field level encryption secret
	if def.Requires.AesSecret {

		fieldSecret, err := requireEnv(p + "FIELD_LEVEL_AES_GCM_SECRET")
		if err != nil {

			return err
		}

		config.Database.FieldSecret = fieldSecret
	}

	// blind index secret for encrypted fields with blind indexes in the db schema
	if def.Requires.IndexSecret {

		indexSecret, err := requireEnv(p + "DATABASE_HMAC_INDEX_SECRET")
		if err != nil || indexSecret == "" {

			return fmt.Errorf("%sDATABASE_HMAC_INDEX_SECRET not set", p)
		}

		config.Database.IndexSecret = indexSecret
	}

	return nil
}

// s2sAuthEnvVars loads service-to-service authentication related environment variables into
// the config struct based on the service definition.
func (config *Config) s2sAuthEnvVars(def SvcDefinition) error {

	p := def.prefix()

	// s2s auth url
	url, err := requireEnv(p + "S2S_AUTH_URL")
	if err != nil {

		return err
	}
	if err = validateURL(url); err != nil {

		return err
	}

	config.ServiceAuth.Url = url

	// s2s auth client id and secret for getting tokens to call other services
	clientID, err := requireEnv(p + "S2S_AUTH_CLIENT_ID")
	if err != nil {

		return err
	}

	config.ServiceAuth.ClientId = clientID

	// s2s auth client secret for getting tokens to call other services
	clientSecret, err := requireEnv(p + "S2S_AUTH_CLIENT_SECRET")
	if err != nil {

		return err
	}

	config.ServiceAuth.ClientSecret = clientSecret

	return nil
}

// userAuthEnvVars loads user authentication related environment variables into the config struct based on
// the service definition.
func (config *Config) userAuthEnvVars(def SvcDefinition) error {

	url, err := requireEnv(def.prefix() + "USER_AUTH_URL")
	if err != nil {

		return err
	}
	if err = validateURL(url); err != nil {

		return err
	}

	config.UserAuth.Url = url

	return nil
}

// jwtEnvVars loads JWT signing and verifying keys from environment variables into the config struct based on
// the service definition.
func (config *Config) jwtEnvVars(def SvcDefinition) error {

	p := def.prefix()

	// s2s jwt signing key
	if def.Requires.S2sSigningKey {

		key, err := requireEnv(p + "S2S_JWT_SIGNING_KEY")
		if err != nil {

			return err
		}

		config.Jwt.S2sSigningKey = key
	}

	// s2s jwt verifying key
	if def.Requires.S2sVerifyingKey {

		key, err := requireEnv(p + "S2S_JWT_VERIFYING_KEY")
		if err != nil {

			return err
		}

		config.Jwt.S2sVerifyingKey = key
	}

	// user jwt signing key
	if def.Requires.UserSigningKey {

		key, err := requireEnv(p + "USER_JWT_SIGNING_KEY")
		if err != nil {

			return err
		}

		config.Jwt.UserSigningKey = key
	}

	// user jwt verifying key
	if def.Requires.UserVerifyingKey {

		key, err := requireEnv(p + "USER_JWT_VERIFYING_KEY")
		if err != nil {

			return err
		}

		config.Jwt.UserVerifyingKey = key
	}

	return nil
}

// profilesServiceEnvVars loads environment variables related to the profiles service into
// the config struct based on the service definition.
func (config *Config) profilesServiceEnvVars(def SvcDefinition) error {

	url, err := requireEnv(def.prefix() + "PROFILES_URL")
	if err != nil {

		return err
	}

	// Note: cannot use validate url here because https:// can NOT be on the front of ip address or
	// grpc will append :443 to it even though there will already be a port included.

	config.Profiles.Url = url

	return nil
}

// tasksServiceEnvVars loads environment variables related to the tasks service into
// the config struct based on the service definition.
func (config *Config) tasksServiceEnvVars(def SvcDefinition) error {

	url, err := requireEnv(def.prefix() + "TASKS_URL")
	if err != nil {

		return err
	}

	if err = validateURL(url); err != nil {

		return err
	}

	config.Tasks.Url = url

	return nil
}

// galleryServiceEnvVars loads environment variables related to the gallery service into
// the config struct based on the service definition.
func (config *Config) galleryServiceEnvVars(def SvcDefinition) error {

	url, err := requireEnv(def.prefix() + "GALLERY_URL")
	if err != nil {

		return err
	}

	if err = validateURL(url); err != nil {

		return err
	}

	config.Gallery.Url = url

	return nil
}

// objectStorageEnvVars loads environment variables related to the object storage service into
// the config struct based on the service definition.
func (config *Config) objectStorageEnvVars(def SvcDefinition) error {

	p := def.prefix()

	// object storage url
	url, err := requireEnv(p + "OBJECT_STORAGE_URL")
	if err != nil {

		return err
	}

	if err = validateURL(url); err != nil {

		return err
	}

	config.ObjectStorage.Url = url

	// object storage bucket name
	bucket, err := requireEnv(p + "OBJECT_STORAGE_BUCKET")
	if err != nil {

		return err
	}

	config.ObjectStorage.Bucket = bucket

	// object storage access key
	accessKey, err := requireEnv(p + "OBJECT_STORAGE_ACCESS_KEY")
	if err != nil {

		return err
	}

	config.ObjectStorage.AccessKey = accessKey

	// object storage secret key
	secretKey, err := requireEnv(p + "OBJECT_STORAGE_SECRET_KEY")
	if err != nil {

		return err
	}

	config.ObjectStorage.SecretKey = secretKey

	return nil
}
