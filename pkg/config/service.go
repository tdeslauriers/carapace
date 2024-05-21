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

func Load(name string) (*Config, error) {
	config := &Config{Name: name}

	// read in and set certs for all services
	err := config.readCerts()
	if err != nil {
		return nil, err
	}

	// read in and set env vars for database
	err = config.databaseEnvVars()
	if err != nil {
		return nil, err
	}

	// read in and set service auth env vars
	err = config.serviceAuthEnvVars()
	if err != nil {
		return nil, err
	}

	// read in and set service auth env vars
	err = config.userAuthEnvVars()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (config *Config) readCerts() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}

	// read in certificates from environment variables
	// server cert
	envServerCert, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_CERT not set", serviceName))
	}

	envServerKey, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_KEY not set", serviceName))
	}

	// client cert
	envClientCert, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCLIENT_CERT not set", serviceName))
	}

	envClientKey, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCLIENT_KEY not set", serviceName))
	}

	// db client cert
	envDbClientCert, ok := os.LookupEnv(fmt.Sprintf("%sDB_CLIENT_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDB_CLIENT_CERT not set", serviceName))
	}

	envDbClientKey, ok := os.LookupEnv(fmt.Sprintf("%sDB_CLIENT_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDB_CLIENT_KEY not set", serviceName))
	}

	// ca cert
	envCaCert, ok := os.LookupEnv(fmt.Sprintf("%sCA_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCA_CERT not set", serviceName))
	}

	config.Certs.ServerCert = &envServerCert
	config.Certs.ServerKey = &envServerKey
	config.Certs.ServerCa = &envCaCert

	config.Certs.ClientCert = &envClientCert
	config.Certs.ClientKey = &envClientKey
	config.Certs.ClientCa = &envCaCert

	config.Certs.DbClientCert = &envDbClientCert
	config.Certs.DbClientKey = &envDbClientKey
	config.Certs.DbCaCert = &envCaCert

	return nil
}

func (config *Config) databaseEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}

	// db env vars
	envDbUrl, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_URL not set", serviceName))
	}

	envDbName, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_NAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_NAME not set", serviceName))
	}

	envDbUsername, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_USERNAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_USERNAME not set", serviceName))
	}

	envDbPassword, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_PASSWORD", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_PASSWORD not set", serviceName))
	}

	envFieldsKey, ok := os.LookupEnv(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY not set", serviceName))
	}

	envIndexSecret, ok := os.LookupEnv(fmt.Sprintf("%sINDEX_SECRET", serviceName))

	config.Database.FieldKey = envFieldsKey
	config.Database.Url = envDbUrl
	config.Database.Password = envDbPassword
	config.Database.Name = envDbName
	config.Database.Username = envDbUsername

	// not all services use an index secret
	if ok {
		config.Database.IndexSecret = envIndexSecret
	}

	return nil
}

func (config *Config) serviceAuthEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
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

func (config *Config) userAuthEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))

	}

	envUserAuthUrl, ok := os.LookupEnv(fmt.Sprintf("%sUSER_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sUSER_AUTH_URL not set", serviceName))
	}

	config.UserAuth.Url = envUserAuthUrl

	return nil
}

func (config *Config) JwtEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}

	envS2sSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_SIGNING_KEY", serviceName))
	if ok {
		config.Jwt.S2sSigningKey = envS2sSigningKey
	}

	envS2sVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_VERIFYING_KEY", serviceName))
	if ok {
		config.Jwt.S2sVerifyingKey = envS2sVerifyingKey
	}

	envUserSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_SIGNING_KEY", serviceName))
	if ok {
		config.Jwt.UserSigningKey = envUserSigningKey
	}

	envUserVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_VERIFYING_KEY", serviceName))
	if ok {
		config.Jwt.UserVerifyingKey = envUserVerifyingKey
	}

	return nil
}
