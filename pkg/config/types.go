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
	FieldKey    string
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
