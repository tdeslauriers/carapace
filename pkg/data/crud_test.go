package data

import (
	"testing"
)

// env vars in db_connect_test.go

func TestCrud(t *testing.T) {

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

	// conn, _ := NewSqlDbConnector(url, clientConfig).Connect()
	// dao := NewSqlRepository(conn)

	// // insert record
	// id, _ := uuid.NewRandom()
	// sessionToken, _ := uuid.NewRandom()
	// csrf, _ := uuid.NewRandom()
	// created := time.Now()
	// exprires := time.Now().Add(time.Minute * 15)

	// // anonymous struct to avoid circular imports in testing.
	// insert := struct {
	// 	Uuid         string
	// 	SessionToken string
	// 	CsrfToken    string
	// 	CreatedAt    string
	// 	ExpiresAt    string
	// 	Revoked      bool
	// }{
	// 	Uuid:         id.String(),
	// 	SessionToken: sessionToken.String(),
	// 	CsrfToken:    csrf.String(),
	// 	CreatedAt:    created.Format("2006-01-02 15:04:05"),
	// 	ExpiresAt:    exprires.Format("2006-01-02 15:04:05"),
	// 	Revoked:      false,
	// }

	// query := "INSERT INTO uxsession (uuid, session_token, csrf_token, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?)"
	// if err := dao.InsertRecord(query, insert); err != nil {
	// 	t.Logf("Failed to insert session: %v, Error: %v", insert, err)
	// 	t.Fail()
	// }

	// // // anonymous struct to avoid circular imports in testing.
	// var records []struct {
	// 	Uuid         string
	// 	SessionToken string
	// 	CsrfToken    string
	// 	CreatedAt    string
	// 	ExpiresAt    string
	// 	Revoked      bool
	// }
	// query = "SELECT * FROM uxsession WHERE DATE(created_at) = ?"
	// year, month, day := created.Date()
	// err := dao.SelectRecords(query, &records, fmt.Sprintf("%d-%d-%d", year, month, day))
	// if err != nil {
	// 	t.Log(err)
	// 	t.Fail()
	// }
	// t.Log("Select records output:")
	// for _, v := range records {
	// 	t.Logf("%v", v)
	// }

	// var record struct {
	// 	Uuid         string
	// 	SessionToken string
	// 	CsrfToken    string
	// 	CreatedAt    string
	// 	ExpiresAt    string
	// 	Revoked      bool
	// }
	// query = "SELECT * FROM uxsession WHERE uuid = ?"
	// err = dao.SelectRecord(query, &record, id)
	// if err != nil {
	// 	t.Log(err)
	// 	t.Fail()
	// }
	// t.Logf("Select record output:\n%v", record)

	// query = "SELECT EXISTS(SELECT 1 FROM uxsession WHERE uuid = ?) AS record_exists"
	// exists, err := dao.SelectExists(query, "candy")
	// if err != nil {
	// 	t.Logf("Record should exist but was %v: %v", exists, err)
	// 	t.Fail()
	// }
	// t.Logf("exists: %t", exists)
}
