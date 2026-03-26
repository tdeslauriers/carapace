package config

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

type Database struct {
	Url         string
	Name        string
	Username    string
	Password    string
	FieldSecret string
	IndexSecret string
}

type ServiceAuth struct {
	Url          string
	ClientId     string
	ClientSecret string
}

type UserAuth struct {
	Url string
}

// Tasks is the model that holds tasks service configuration data to inform service setup.
type Tasks struct {
	Url string
}

// Gallery is the model that holds gallery service configuration data to inform service setup.
type Gallery struct {
	Url string
}

type Pat struct {
	Pepper string
}

type Jwt struct {
	S2sSigningKey   string
	S2sVerifyingKey string

	UserSigningKey   string
	UserVerifyingKey string
}

// OauthRedirect is the model that holds oauth redirect configuration data to inform service setup.
type OauthRedirect struct {
	CallbackUrl      string
	CallbackClientId string
}

// ObjectStorage is the model that holds object storage configuration data to inform service setup.
type ObjectStorage struct {
	Url       string
	Bucket    string // assumes one bucket per service, like one db per service
	AccessKey string // username, effectively
	SecretKey string // password, effectively
}

// Profiles is the model that holds profiles service configuration data to inform service setup.
type Profiles struct {
	Url string
}
