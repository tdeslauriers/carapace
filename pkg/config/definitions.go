package config

// ServerTls is a string type that indicates the type of TLS configuration for a service.
type ServerTls string

const (
	StandardTls ServerTls = "standard"
	MutualTls   ServerTls = "mutual"
)

// Config is a struct that holds service configuration data to inform service setup.
type SvcDefinition struct {
	ServiceName string
	Tls         ServerTls
	Requires    Requires
}

// Requires is a list of service requirements meant to inform service configuration.
type Requires struct {
	// S2sClient indicates that the service requires a client certificate and s2s authentication
	S2sClient bool

	// Db indicates that the service requires a database connection and credentials
	Db          bool
	IndexSecret bool
	AesSecret   bool

	S2sSigningKey bool
	// S2sVerifyingKey indicates that the service requires a verifying key for s2s JWTs
	S2sVerifyingKey bool

	// Identity indicates that the service requires making requests to the identity service
	Identity       bool
	UserSigningKey bool
	// UserVerifyingKey indicates that the service requires a verifying key for user JWTs
	UserVerifyingKey bool

	// OauthRedirect indicates that the service requires oauth client id and redirect url
	OauthRedirect bool

	// Tasks indicates that the service requires making requests to the tasks service
	Tasks bool
}
