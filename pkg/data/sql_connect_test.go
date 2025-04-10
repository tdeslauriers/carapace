package data

import (
	"testing"
)

// env vars
const (
	DbServerCaCert  = "DB_SERVER_CA_CERT"
	DbClientCert    = "DB_CLIENT_CERT"
	DbClientKey     = "DB_CLIENT_KEY"
	MariaDbName     = "CARAPACE_MARIADB_NAME"
	MariaDbUrl      = "CARAPACE_MARIADB_URL"
	MariaDbUsername = "CARAPACE_MARIADB_USERNAME"
	MariaDbPassword = "CARAPACE_MARIADB_PASSWORD"
)

func TestDBConnect(t *testing.T) {

	// TODO: re-write tests to use cert generation service

	// // setup
	// // gen client certs
	// // need to use ca installed in maria as rootCA
	// leafClient := sign.CertData{
	// 	CertName:     "db-client",
	// 	Organisation: []string{"Rebel Alliance"},
	// 	CommonName:   "localhost",
	// 	San:          []string{"localhost"},
	// 	SanIps:       []net.IP{net.ParseIP("127.0.0.1")},
	// 	Role:         sign.Client,
	// 	CaCertName:   "ca",
	// }
	// leafClient.GenerateEcdsaCert()

	// // read in db-ca-cert.pem, new db-client .pems to env vars
	// // need to use ca that signed maria's tls leaf certs
	// var envVars [][]string
	// envVars = append(envVars, []string{DbServerCaCert, fmt.Sprintf("%s-cert.pem", "ca")})
	// envVars = append(envVars, []string{DbClientCert, fmt.Sprintf("%s-cert.pem", leafClient.CertName)})
	// envVars = append(envVars, []string{DbClientKey, fmt.Sprintf("%s-key.pem", leafClient.CertName)})

	// // loop thru setting env
	// for _, v := range envVars {

	// 	fileData, _ := os.ReadFile(v[1])
	// 	encodedData := base64.StdEncoding.EncodeToString(fileData)
	// 	if err := os.Setenv(v[0], encodedData); err != nil {
	// 		log.Fatalf("Unable to load env var: %s", v[0])
	// 	}
	// }

	// // configure pki
	// dbPki := &connect.Pki{
	// 	CertFile: os.Getenv(DbClientCert),
	// 	KeyFile:  os.Getenv(DbClientKey),
	// 	CaFiles:  []string{os.Getenv(DbServerCaCert)},
	// }
	// clientConfig, _ := connect.NewTlsClientConfig(dbPki).Build()

	// url := DbUrl{
	// 	Username: os.Getenv(MariaDbUsername),
	// 	Password: os.Getenv(MariaDbPassword),
	// 	Addr:     os.Getenv(MariaDbUrl),
	// 	Name:     os.Getenv(MariaDbName),
	// }

	// dbConnector := NewSqlDbConnector(url, clientConfig)

	// db, err := dbConnector.Connect()
	// if err != nil {
	// 	log.Fatalf("Failed to connect to database: %v", err)
	// }

	// defer db.Close()

	// err = db.Ping()
	// if err != nil {
	// 	t.Fatalf("Failed to ping test database: %v", err)
	// }
}
