package config

import (
	"fmt"
	"os"
	"strings"
)

func Load(def SvcDefinition) (*Config, error) {

	if def.ServiceName == "" {
		return nil, fmt.Errorf("service name must be provided to definitions, cannot be empty")
	}

	config := &Config{
		ServiceName: def.ServiceName,
		Tls:         def.Tls,
	}

	// read in service client id
	envClientId, ok := os.LookupEnv(fmt.Sprintf("%s_SERVICE_CLIENT_ID", strings.ToUpper(def.ServiceName)))
	if !ok {
		return nil, fmt.Errorf("%s_SERVICE_CLIENT_ID not set", strings.ToUpper(def.ServiceName))
	}
	config.ServiceClientId = envClientId

	// read in service port
	envPort, ok := os.LookupEnv(fmt.Sprintf("%s_SERVICE_PORT", strings.ToUpper(def.ServiceName)))
	if !ok {
		return nil, fmt.Errorf(fmt.Sprintf("%s_SERVICE_PORT not set", strings.ToUpper(def.ServiceName)))
	}
	config.ServicePort = envPort

	// read in for all services
	err := config.readCerts(def)
	if err != nil {
		return nil, err
	}

	// read in env vars for database
	if def.Requires.Db {
		err = config.databaseEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in service auth env vars
	if def.Requires.S2sClient {
		err = config.s2sAuthEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in user auth url env var
	if def.Requires.Identity {
		err = config.userAuthEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in jwt env vars
	if def.Requires.S2sSigningKey || def.Requires.S2sVerifyingKey || def.Requires.UserSigningKey || def.Requires.UserVerifyingKey {
		err = config.JwtEnvVars(def)
		if err != nil {
			return nil, err
		}
	}

	// read in oauth redirect env vars
	if def.Requires.OauthRedirect {
		envOauthCallbackUrl, ok := os.LookupEnv(fmt.Sprintf("%s_OAUTH_CALLBACK_URL", strings.ToUpper(def.ServiceName)))
		if !ok {
			return nil, fmt.Errorf(fmt.Sprintf("%s_OAUTH_CALLBACK_URL not set", strings.ToUpper(def.ServiceName)))
		}
		config.OauthRedirect.CallbackUrl = envOauthCallbackUrl

		envOauthCallbackClientId, ok := os.LookupEnv(fmt.Sprintf("%s_OAUTH_CALLBACK_CLIENT_ID", strings.ToUpper(def.ServiceName)))
		if !ok {
			return nil, fmt.Errorf(fmt.Sprintf("%s_OAUTH_CALLBACK_CLIENT_ID not set", strings.ToUpper(def.ServiceName)))
		}
		config.OauthRedirect.CallbackClientId = envOauthCallbackClientId
	}

	return config, nil
}

func (config *Config) readCerts(def SvcDefinition) error {

	var serviceName string
	if def.ServiceName != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.ServiceName))
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
	if def.Requires.S2sClient {

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
	if def.Requires.Db {

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

	// ca cert - services
	if def.Tls == MutualTls || def.Requires.S2sClient {
		envCaCert, ok := os.LookupEnv(fmt.Sprintf("%sCA_CERT", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sCA_CERT not set", serviceName))
		}

		if def.Tls == MutualTls {
			config.Certs.ServerCa = &envCaCert
		}

		if def.Requires.S2sClient {
			config.Certs.ClientCa = &envCaCert
		}

	}

	// ca cert - db
	if def.Requires.Db {
		envDbCaCert, ok := os.LookupEnv(fmt.Sprintf("%sDB_CA_CERT", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sDB_CA_CERT not set", serviceName))
		}

		config.Certs.DbCaCert = &envDbCaCert
	}

	return nil
}

func (config *Config) databaseEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.ServiceName != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.ServiceName))
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
	if def.Requires.AesSecret {
		envFieldsKey, ok := os.LookupEnv(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_SECRET", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_SECRET not set", serviceName))
		}
		config.Database.FieldSecret = envFieldsKey
	}

	// index key
	if def.Requires.IndexSecret {
		envIndexSecret, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_HMAC_INDEX_SECRET", serviceName))
		if ok && envIndexSecret != "" {
			config.Database.IndexSecret = envIndexSecret
		} else {
			return fmt.Errorf(fmt.Sprintf("%sDATABASE_HMAC_INDEX_SECRET not set", serviceName))
		}
	}

	return nil
}

// s2sAuthEnvVars is a helper function that reads in the environment variables for service to service authentication
func (config *Config) s2sAuthEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.ServiceName != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.ServiceName))
	}

	envS2sUrl, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_URL not set", serviceName))
	}

	envS2sClientId, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID not set", serviceName))
	}

	envS2sClientSecret, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET not set", serviceName))
	}

	config.ServiceAuth.Url = envS2sUrl
	config.ServiceAuth.ClientId = envS2sClientId
	config.ServiceAuth.ClientSecret = envS2sClientSecret

	return nil
}

// userAuthEnvVars is a helper function that reads in the environment variables for user authentication
func (config *Config) userAuthEnvVars(def SvcDefinition) error {

	var serviceName string
	if def.ServiceName != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.ServiceName))

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
	if def.ServiceName != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(def.ServiceName))
	}

	// signing key
	if def.Requires.S2sSigningKey {

		envS2sSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_JWT_SIGNING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sS2S_JWT_SIGNING_KEY not set", serviceName))
		}
		config.Jwt.S2sSigningKey = envS2sSigningKey
	}

	// verifying key
	if def.Requires.S2sVerifyingKey {

		envS2sVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sS2S_JWT_VERIFYING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sS2S_JWT_VERIFYING_KEY not set", serviceName))
		}
		config.Jwt.S2sVerifyingKey = envS2sVerifyingKey
	}

	// user signing key
	if def.Requires.UserSigningKey {

		envUserSigningKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_JWT_SIGNING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sUSER_JWT_SIGNING_KEY not set", serviceName))
		}
		config.Jwt.UserSigningKey = envUserSigningKey
	}

	// user verifying key
	if def.Requires.UserVerifyingKey {

		envUserVerifyingKey, ok := os.LookupEnv(fmt.Sprintf("%sUSER_JWT_VERIFYING_KEY", serviceName))
		if !ok {
			return fmt.Errorf(fmt.Sprintf("%sUSER_JWT_VERIFYING_KEY not set", serviceName))
		}
		config.Jwt.UserVerifyingKey = envUserVerifyingKey
	}

	return nil
}
