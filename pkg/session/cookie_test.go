package session

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/diagnostics"
)

func TestCookies(t *testing.T) {

	pki := &connect.Pki{
		CertFile: os.Getenv("SERVER_CERT"),
		KeyFile:  os.Getenv("SERVER_KEY"),
		CaFiles:  []string{os.Getenv("CA_CERT")},
	}

	tls, _ := connect.NewTlsServerConfig("mutual", pki).Build()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", diagnostics.HealthCheckHandler)
	mux.HandleFunc("/cookie", setCookies)

	server := &connect.TlsServer{
		Addr:      ":8444",
		Mux:       mux,
		TlsConfig: tls,
	}
	// dbPki := connect.Pki{
	// 	CertFile: os.Getenv("CLIENT_CERT"),
	// 	KeyFile:  os.Getenv("CLIENT_KEY"),
	// 	CaFiles:  []string{os.Getenv("DB_CA_CERT")},
	// }
	// clientConfig := connect.ClientConfig{Config: &dbPki}

	// url := data.DbUrl{
	// 	Username: os.Getenv("CARAPACE_MARIADB_USERNAME"),
	// 	Password: os.Getenv("CARAPACE_MARIADB_PASSWORD"),
	// 	Addr:     os.Getenv("CARAPACE_MARIADB_URL"),
	// 	Name:     os.Getenv("CARAPACE_MARIADB_NAME"),
	// }

	// dbConnector := &data.SqlDbConnector{
	// 	TlsConfig:     clientConfig,
	// 	ConnectionUrl: url.Build(),
	// }

	go func() {

		if err := server.Initialize(); err != http.ErrServerClosed {
			t.Log("Failed to start Server: ", err)
			t.Fail()
		}
	}()

	var client http.Client
	req, err := http.NewRequest("GET", "http://localhost:8444/cookie", nil)
	if err != nil {
		t.Fail()
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fail()
	}
	defer res.Body.Close()

	cookies := res.Cookies()
	for _, cookie := range cookies {
		t.Logf("Cookie: %s = %s\n", cookie.Name, cookie.Value)
	}

}

func setCookies(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "Test_Cookie_Secure",
		Value:    "ce480e9d-dd09-47cf-b18e-212732d0c5a0",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	cookie2 := http.Cookie{
		Name:    "Test_Cookie_Insecure",
		Value:   "dark_mode",
		Expires: time.Now().Add(365 * 24 * time.Hour),
	}
	http.SetCookie(w, &cookie2)

	w.Write([]byte("Setting cookies."))
}
