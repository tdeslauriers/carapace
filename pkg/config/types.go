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
	Jwt             Jwt
	OauthRedirect   OauthRedirect
	Tasks           Tasks
	Gallery         Gallery
	ObjectStorage   ObjectStorage
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

type Tasks struct {
	Url string
}

type Gallery struct {
	Url string
}

type Jwt struct {
	S2sSigningKey   string
	S2sVerifyingKey string

	UserSigningKey   string
	UserVerifyingKey string
}

type OauthRedirect struct {
	CallbackUrl      string
	CallbackClientId string
}

type ObjectStorage struct {
	Url       string
	Bucket    string // assumes one bucket per service, like one db per service
	AccessKey string // username, effectively
	SecretKey string // password, effectively
}
