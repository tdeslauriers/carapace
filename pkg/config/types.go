package config

// Config is the model that holds all configuration data for service setup.
// It is typically the product of parsing command line flags and args, and is the input for exo cli execution.
type Config struct {
	ServiceName     string
	ServiceClientId string
	ServicePort     string // must have :8443 format with leading colon
	Tls             ServerTls
	Certs           Certs
	Database        Database
	ServiceAuth     ServiceAuth
	UserAuth        UserAuth
	Pat             Pat
	Jwt             Jwt
	OauthRedirect   OauthRedirect
	Tasks           Tasks
	Gallery         Gallery
	ObjectStorage   ObjectStorage
	Profiles        Profiles
}

// Certs is the model that holds server TLS configuration (certificates and keys) to inform service setup.
type Certs struct {
	ServerCert *string
	ServerKey  *string
	ServerCa   *string

	ClientCert *string
	ClientKey  *string
	ClientCa   *string

	DbClientCert *string
	DbClientKey  *string
	DbCaCert     *string
}

// Database is the model that holds database configuration data for services requiring a database.
type Database struct {
	Url         string
	Name        string
	Username    string
	Password    string
	FieldSecret string
	IndexSecret string
}

// ServiceAuth is the model that holds service authentication configuration data for
// services that need to authenticate to other services.
type ServiceAuth struct {
	Url          string
	ClientId     string
	ClientSecret string
}

// UserAuth is the model that holds user authentication configuration data for
// services that need to authenticate users.  This is separate from service auth because
// the data required to authenticate users may be different than the data required to
// authenticate services, and not all services will need both types of authentication.
type UserAuth struct {
	Url string
}

// Tasks is the model that holds tasks service configuration data to inform service setup.
type Tasks struct {
	Url string
}

// Gallery is the model that holds gallery service configuration data.
type Gallery struct {
	Url string
}

// Pat is the model that holds personal access token (pat) configuration (pepper secret) for
// services that need to generate or verify personal access tokens.
type Pat struct {
	Pepper string
}

// Jwt is the model that holds jwt configuration (signing and verifying keys) for
// services that need to generate and/or verify jwt tokens.
type Jwt struct {
	S2sSigningKey   string
	S2sVerifyingKey string

	UserSigningKey   string
	UserVerifyingKey string
}

// OauthRedirect is the model that holds oauth redirect configuration data.
type OauthRedirect struct {
	CallbackUrl      string
	CallbackClientId string
}

// ObjectStorage is the model that holds object storage configuration data.
type ObjectStorage struct {
	Url       string
	Bucket    string // assumes one bucket per service, like one db per service
	AccessKey string // username, effectively
	SecretKey string // password, effectively
}

// Profiles is the model that holds profiles service configuration data.
type Profiles struct {
	Url string
}
