package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Name        string
	Certs       Certs
	Database    Database
	ServiceAuth ServiceAuth
	UserAuth    UserAuth
	Jwt         Jwt
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

func Load(def SvcDefinition) (*Config, error) {
	config := &Config{Name: def.name}

	// read in for all services
	err := config.readCerts(def)
	if err != nil {
		return nil, err
	}

	// read in env vars for database
	if def.requires.db {
		err = config.databaseEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in service auth env vars
	if def.requires.client {
		err = config.serviceAuthEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in user auth url env var
	if def.requires.userAuthUrl {
		err = config.userAuthUrlEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in jwt env vars
	if def.requires.s2sSigningKey || def.requires.s2sVerifyingKey || def.requires.userSigningKey || def.requires.userVerifyingKey {
		err = config.JwtEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

func (config *Config) readCerts(def SvcDefinition) error {

	var serviceName string
	if def.name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.name))
	}

	// read in certificates from environment variables
	// server
	// server cert
	envServerCert, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_CERT not set", serviceName))
	}

	config.Certs.ServerCert = &envServerCert

	// server key
	envServerKey, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_KEY not set", serviceName))
	}

	config.Certs.ServerKey = &envServerKey

	// client
	if def.requires.client {

		// client cert
		envClientCert, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_CERT", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sCLIENT_CERT not set", serviceName))
		}

		config.Certs.ClientCert = &envClientCert

		// client key
		envClientKey, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sCLIENT_KEY not set", serviceName))
		}

		config.Certs.ClientKey = &envClientKey
	}

	// db client
	if def.requires.db {

		// db client cert
		envDbClientCert, ok := os.LookupEnv(fmt.Sprintf("%sDB_CLIENT_CERT", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sDB_CLIENT_CERT not set", serviceName))
		}

		config.Certs.DbClientCert = &envDbClientCert

		// db client key
		envDbClientKey, ok := os.LookupEnv(fmt.Sprintf("%sDB_CLIENT_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sDB_CLIENT_KEY not set", serviceName))
		}
		config.Certs.DbClientKey = &envDbClientKey
	}

	// ca cert
	if def.tlsType == MutualTls || def.requires.client || def.requires.db {
		envCaCert, ok := os.LookupEnv(fmt.Sprintf("%sCA_CERT", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sCA_CERT not set", serviceName))
		}

		if def.tlsType == MutualTls {
			config.Certs.ServerCa = &envCaCert
		}

		if def.requires.client {
			config.Certs.ClientCa = &envCaCert
		}

		if def.requires.db {
			config.Certs.DbCaCert = &envCaCert
		}
	}

	return nil
}

func (config *Config) databaseEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.name))
	}

	// db env vars
	// url
	envDbUrl, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_URL not set", serviceName))
	}
	config.Database.Url = envDbUrl

	// database name
	envDbName, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_NAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_NAME not set", serviceName))
	}
	config.Database.Name = envDbName

	// database username
	envDbUsername, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_USERNAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_USERNAME not set", serviceName))
	}
	config.Database.Username = envDbUsername

	// database password
	envDbPassword, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_PASSWORD", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_PASSWORD not set", serviceName))
	}
	config.Database.Password = envDbPassword

	// field level encryption key
	if def.requires.aesKey {
		envFieldsKey, ok := os.LookupEnv(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY not set", serviceName))
		}
		config.Database.FieldKey = envFieldsKey
	}

	// index key
	if def.requires.indexKey {
		envIndexSecret, ok := os.LookupEnv(fmt.Sprintf("%sINDEX_SECRET", serviceName))
		if ok {
			config.Database.IndexSecret = envIndexSecret
		}
	}

	return nil
}

func (config *Config) serviceAuthEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.name))
	}

	envRanUrl, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_URL not set", serviceName))
	}

	envRanClientId, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID not set", serviceName))
	}

	envRanClientSecret, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET not set", serviceName))
	}

	config.ServiceAuth.Url = envRanUrl
	config.ServiceAuth.ClientId = envRanClientId
	config.ServiceAuth.ClientSecret = envRanClientSecret

	return nil
}

func (config *Config) userAuthUrlEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.name))

	}

	envUserAuthUrl, ok := os.LookupEnv(fmt.Sprintf("%sUSER_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sUSER_AUTH_URL not set", serviceName))
	}

	config.UserAuth.Url = envUserAuthUrl

	return nil
}

func (config *Config) JwtEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.name))
	}

	// signing key
	if def.requires.s2sSigningKey {

		envS2sSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_S2S_JWT_SIGNING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sS2S_S2S_JWT_SIGNING_KEY not set", serviceName))
		}
		config.Jwt.S2sSigningKey = envS2sSigningKey
	}

	// verifying key
	if def.requires.s2sVerifyingKey {

		envS2sVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_JWT_VERIFYING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sS2S_JWT_VERIFYING_KEY not set", serviceName))
		}
		config.Jwt.S2sVerifyingKey = envS2sVerifyingKey
	}

	// user signing key
	if def.requires.userSigningKey {

		envUserSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_JWT_SIGNING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sUSER_JWT_SIGNING_KEY not set", serviceName))
		}
		config.Jwt.UserSigningKey = envUserSigningKey
	}

	// user verifying key
	if def.requires.userVerifyingKey {

		envUserVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_JWT_VERIFYING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sUSER_JWT_VERIFYING_KEY not set", serviceName))
		}
		config.Jwt.UserVerifyingKey = envUserVerifyingKey
	}

	return nil
}
