package config

import (
	"strings"
	"testing"
)

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		wantErr bool
	}{
		{name: "valid :8443", port: ":8443"},
		{name: "valid :8080", port: ":8080"},
		{name: "valid :80", port: ":80"},
		{name: "valid :1", port: ":1"},
		{name: "valid :65535", port: ":65535"},
		{name: "no leading colon", port: "8443", wantErr: true},
		{name: "colon only", port: ":", wantErr: true},
		{name: "empty string", port: "", wantErr: true},
		{name: "port zero", port: ":0", wantErr: true},
		{name: "port out of range high", port: ":65536", wantErr: true},
		{name: "port not numeric r2d2", port: ":r2d2", wantErr: true},
		{name: "negative port", port: ":-1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePort(%q) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "valid https coruscant", raw: "https://coruscant.empire.gov:8443"},
		{name: "valid http tatooine", raw: "http://tatooine.outer.rim:9000"},
		{name: "valid localhost dev", raw: "http://localhost:8080"},
		{name: "valid ip address", raw: "https://192.168.1.100:9000"},
		{name: "valid ipv6", raw: "http://[::1]:8080"},
		{name: "valid k8s fqdn", raw: "http://jedi-temple.jedis.svc.cluster.local:8080"},
		{name: "valid k8s short service name", raw: "http://deathstar:9000"},
		{name: "valid k8s cross-namespace", raw: "http://deathstar.empire:8443"},
		{name: "no scheme hostname and port", raw: "deathstar:8080", wantErr: true},
		{name: "wrong scheme ftp", raw: "ftp://coruscant.empire.gov:8443", wantErr: true},
		{name: "https empty host", raw: "https://", wantErr: true},
		{name: "empty string", raw: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	const (
		serverCert   = "DEATHSTAR-SERVER-CERT-PLACEHOLDER"
		serverKey    = "DEATHSTAR-SERVER-KEY-PLACEHOLDER"
		clientCert   = "FALCON-CLIENT-CERT-PLACEHOLDER"
		clientKey    = "FALCON-CLIENT-KEY-PLACEHOLDER"
		caCert       = "GALACTIC-CA-CERT-PLACEHOLDER"
		dbClientCert = "JEDI-DB-CLIENT-CERT-PLACEHOLDER"
		dbClientKey  = "JEDI-DB-CLIENT-KEY-PLACEHOLDER"
		dbCaCert     = "JEDI-DB-CA-CERT-PLACEHOLDER"
	)

	tests := []struct {
		name        string
		def         SvcDefinition
		env         map[string]string
		wantErr     bool
		errContains string
		check       func(t *testing.T, cfg *Config)
	}{
		// --- missing / invalid basic fields ---
		{
			name:        "empty service name",
			def:         SvcDefinition{},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "service name must be provided",
		},
		{
			name:        "missing service client id",
			def:         SvcDefinition{ServiceName: "deathstar", Tls: NoneTls},
			env:         map[string]string{},
			wantErr:     true,
			errContains: "DEATHSTAR_SERVICE_CLIENT_ID not set",
		},
		{
			name: "missing service port",
			def:  SvcDefinition{ServiceName: "deathstar", Tls: NoneTls},
			env: map[string]string{
				"DEATHSTAR_SERVICE_CLIENT_ID": "grand-moff-tarkin",
			},
			wantErr:     true,
			errContains: "DEATHSTAR_SERVICE_PORT not set",
		},
		{
			name: "invalid port no leading colon",
			def:  SvcDefinition{ServiceName: "deathstar", Tls: NoneTls},
			env: map[string]string{
				"DEATHSTAR_SERVICE_CLIENT_ID": "grand-moff-tarkin",
				"DEATHSTAR_SERVICE_PORT":      "8443",
			},
			wantErr:     true,
			errContains: "invalid port",
		},
		{
			name: "invalid port out of range",
			def:  SvcDefinition{ServiceName: "deathstar", Tls: NoneTls},
			env: map[string]string{
				"DEATHSTAR_SERVICE_CLIENT_ID": "grand-moff-tarkin",
				"DEATHSTAR_SERVICE_PORT":      ":99999",
			},
			wantErr:     true,
			errContains: "invalid port",
		},

		// --- NoneTls minimal ---
		{
			name: "NoneTls minimal config",
			def:  SvcDefinition{ServiceName: "deathstar", Tls: NoneTls},
			env: map[string]string{
				"DEATHSTAR_SERVICE_CLIENT_ID": "grand-moff-tarkin",
				"DEATHSTAR_SERVICE_PORT":      ":8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.ServiceName != "deathstar" {
					t.Errorf("ServiceName = %q, want deathstar", cfg.ServiceName)
				}
				if cfg.ServiceClientId != "grand-moff-tarkin" {
					t.Errorf("ServiceClientId = %q, want grand-moff-tarkin", cfg.ServiceClientId)
				}
				if cfg.ServicePort != ":8443" {
					t.Errorf("ServicePort = %q, want :8443", cfg.ServicePort)
				}
				if cfg.Tls != NoneTls {
					t.Errorf("Tls = %q, want %q", cfg.Tls, NoneTls)
				}
				if cfg.Certs.ServerCert != nil {
					t.Error("ServerCert should be nil for NoneTls")
				}
			},
		},

		// --- StandardTls certs ---
		{
			name: "StandardTls missing server cert",
			def:  SvcDefinition{ServiceName: "falcon", Tls: StandardTls},
			env: map[string]string{
				"FALCON_SERVICE_CLIENT_ID": "han-solo",
				"FALCON_SERVICE_PORT":      ":8080",
			},
			wantErr:     true,
			errContains: "FALCON_SERVER_CERT not set",
		},
		{
			name: "StandardTls success",
			def:  SvcDefinition{ServiceName: "falcon", Tls: StandardTls},
			env: map[string]string{
				"FALCON_SERVICE_CLIENT_ID": "han-solo",
				"FALCON_SERVICE_PORT":      ":8080",
				"FALCON_SERVER_CERT":       serverCert,
				"FALCON_SERVER_KEY":        serverKey,
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Certs.ServerCert == nil || *cfg.Certs.ServerCert != serverCert {
					t.Errorf("ServerCert = %v, want %q", cfg.Certs.ServerCert, serverCert)
				}
				if cfg.Certs.ServerKey == nil || *cfg.Certs.ServerKey != serverKey {
					t.Errorf("ServerKey = %v, want %q", cfg.Certs.ServerKey, serverKey)
				}
				if cfg.Certs.ServerCa != nil {
					t.Error("ServerCa should be nil for StandardTls without S2sClient")
				}
			},
		},

		// --- MutualTls ---
		{
			name: "MutualTls sets ServerCa",
			def:  SvcDefinition{ServiceName: "executor", Tls: MutualTls},
			env: map[string]string{
				"EXECUTOR_SERVICE_CLIENT_ID": "darth-vader",
				"EXECUTOR_SERVICE_PORT":      ":8443",
				"EXECUTOR_SERVER_CERT":       serverCert,
				"EXECUTOR_SERVER_KEY":        serverKey,
				"EXECUTOR_CA_CERT":           caCert,
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Certs.ServerCa == nil || *cfg.Certs.ServerCa != caCert {
					t.Errorf("ServerCa = %v, want %q", cfg.Certs.ServerCa, caCert)
				}
				if cfg.Certs.ClientCa != nil {
					t.Error("ClientCa should be nil without S2sClient")
				}
			},
		},

		// --- S2sClient ---
		{
			name: "S2sClient missing auth url",
			def: SvcDefinition{
				ServiceName: "falcon",
				Tls:         StandardTls,
				Requires:    Requires{S2sClient: true},
			},
			env: map[string]string{
				"FALCON_SERVICE_CLIENT_ID": "han-solo",
				"FALCON_SERVICE_PORT":      ":8080",
				"FALCON_SERVER_CERT":       serverCert,
				"FALCON_SERVER_KEY":        serverKey,
				"FALCON_CLIENT_CERT":       clientCert,
				"FALCON_CLIENT_KEY":        clientKey,
				"FALCON_CA_CERT":           caCert,
			},
			wantErr:     true,
			errContains: "FALCON_S2S_AUTH_URL not set",
		},
		{
			name: "S2sClient invalid auth url",
			def: SvcDefinition{
				ServiceName: "falcon",
				Tls:         StandardTls,
				Requires:    Requires{S2sClient: true},
			},
			env: map[string]string{
				"FALCON_SERVICE_CLIENT_ID": "han-solo",
				"FALCON_SERVICE_PORT":      ":8080",
				"FALCON_SERVER_CERT":       serverCert,
				"FALCON_SERVER_KEY":        serverKey,
				"FALCON_CLIENT_CERT":       clientCert,
				"FALCON_CLIENT_KEY":        clientKey,
				"FALCON_CA_CERT":           caCert,
				"FALCON_S2S_AUTH_URL":      "mos-eisley-cantina",
			},
			wantErr:     true,
			errContains: "invalid url",
		},
		{
			name: "S2sClient success",
			def: SvcDefinition{
				ServiceName: "falcon",
				Tls:         StandardTls,
				Requires:    Requires{S2sClient: true},
			},
			env: map[string]string{
				"FALCON_SERVICE_CLIENT_ID":      "han-solo",
				"FALCON_SERVICE_PORT":           ":8080",
				"FALCON_SERVER_CERT":            serverCert,
				"FALCON_SERVER_KEY":             serverKey,
				"FALCON_CLIENT_CERT":            clientCert,
				"FALCON_CLIENT_KEY":             clientKey,
				"FALCON_CA_CERT":                caCert,
				"FALCON_S2S_AUTH_URL":           "https://mos-eisley.outer.rim:8443",
				"FALCON_S2S_AUTH_CLIENT_ID":     "chewie",
				"FALCON_S2S_AUTH_CLIENT_SECRET": "wookiee-secret",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.ServiceAuth.Url != "https://mos-eisley.outer.rim:8443" {
					t.Errorf("ServiceAuth.Url = %q", cfg.ServiceAuth.Url)
				}
				if cfg.ServiceAuth.ClientId != "chewie" {
					t.Errorf("ServiceAuth.ClientId = %q", cfg.ServiceAuth.ClientId)
				}
				if cfg.ServiceAuth.ClientSecret != "wookiee-secret" {
					t.Errorf("ServiceAuth.ClientSecret = %q", cfg.ServiceAuth.ClientSecret)
				}
				if cfg.Certs.ClientCa == nil || *cfg.Certs.ClientCa != caCert {
					t.Errorf("ClientCa = %v, want %q", cfg.Certs.ClientCa, caCert)
				}
			},
		},

		// --- Database ---
		{
			name: "database missing url",
			def: SvcDefinition{
				ServiceName: "jedi",
				Tls:         StandardTls,
				Requires:    Requires{Db: true},
			},
			env: map[string]string{
				"JEDI_SERVICE_CLIENT_ID": "master-yoda",
				"JEDI_SERVICE_PORT":      ":8443",
				"JEDI_SERVER_CERT":       serverCert,
				"JEDI_SERVER_KEY":        serverKey,
				"JEDI_DB_CLIENT_CERT":    dbClientCert,
				"JEDI_DB_CLIENT_KEY":     dbClientKey,
				"JEDI_DB_CA_CERT":        dbCaCert,
			},
			wantErr:     true,
			errContains: "JEDI_DATABASE_URL not set",
		},
		{
			name: "database basic success",
			def: SvcDefinition{
				ServiceName: "jedi",
				Tls:         StandardTls,
				Requires:    Requires{Db: true},
			},
			env: map[string]string{
				"JEDI_SERVICE_CLIENT_ID": "master-yoda",
				"JEDI_SERVICE_PORT":      ":8443",
				"JEDI_SERVER_CERT":       serverCert,
				"JEDI_SERVER_KEY":        serverKey,
				"JEDI_DB_CLIENT_CERT":    dbClientCert,
				"JEDI_DB_CLIENT_KEY":     dbClientKey,
				"JEDI_DB_CA_CERT":        dbCaCert,
				"JEDI_DATABASE_URL":      "jedi-temple-db.coruscant:5432",
				"JEDI_DATABASE_NAME":     "jedi_archives",
				"JEDI_DATABASE_USERNAME": "master-yoda",
				"JEDI_DATABASE_PASSWORD": "may-the-force-be-with-you",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Database.Url != "jedi-temple-db.coruscant:5432" {
					t.Errorf("Database.Url = %q", cfg.Database.Url)
				}
				if cfg.Database.Name != "jedi_archives" {
					t.Errorf("Database.Name = %q", cfg.Database.Name)
				}
				if cfg.Database.Username != "master-yoda" {
					t.Errorf("Database.Username = %q", cfg.Database.Username)
				}
				if cfg.Database.Password != "may-the-force-be-with-you" {
					t.Errorf("Database.Password = %q", cfg.Database.Password)
				}
			},
		},
		{
			name: "database with AES and index secrets",
			def: SvcDefinition{
				ServiceName: "jedi",
				Tls:         StandardTls,
				Requires:    Requires{Db: true, AesSecret: true, IndexSecret: true},
			},
			env: map[string]string{
				"JEDI_SERVICE_CLIENT_ID":          "master-yoda",
				"JEDI_SERVICE_PORT":               ":8443",
				"JEDI_SERVER_CERT":                serverCert,
				"JEDI_SERVER_KEY":                 serverKey,
				"JEDI_DB_CLIENT_CERT":             dbClientCert,
				"JEDI_DB_CLIENT_KEY":              dbClientKey,
				"JEDI_DB_CA_CERT":                 dbCaCert,
				"JEDI_DATABASE_URL":               "jedi-temple-db.coruscant:5432",
				"JEDI_DATABASE_NAME":              "jedi_archives",
				"JEDI_DATABASE_USERNAME":          "master-yoda",
				"JEDI_DATABASE_PASSWORD":          "may-the-force-be-with-you",
				"JEDI_FIELD_LEVEL_AES_GCM_SECRET": "kyber-crystal-aes-256-secret-key",
				"JEDI_DATABASE_HMAC_INDEX_SECRET": "force-sensitive-index-hmac-key",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Database.FieldSecret != "kyber-crystal-aes-256-secret-key" {
					t.Errorf("Database.FieldSecret = %q", cfg.Database.FieldSecret)
				}
				if cfg.Database.IndexSecret != "force-sensitive-index-hmac-key" {
					t.Errorf("Database.IndexSecret = %q", cfg.Database.IndexSecret)
				}
			},
		},
		{
			name: "database index secret set but empty",
			def: SvcDefinition{
				ServiceName: "jedi",
				Tls:         StandardTls,
				Requires:    Requires{Db: true, IndexSecret: true},
			},
			env: map[string]string{
				"JEDI_SERVICE_CLIENT_ID":          "master-yoda",
				"JEDI_SERVICE_PORT":               ":8443",
				"JEDI_SERVER_CERT":                serverCert,
				"JEDI_SERVER_KEY":                 serverKey,
				"JEDI_DB_CLIENT_CERT":             dbClientCert,
				"JEDI_DB_CLIENT_KEY":              dbClientKey,
				"JEDI_DB_CA_CERT":                 dbCaCert,
				"JEDI_DATABASE_URL":               "jedi-temple-db.coruscant:5432",
				"JEDI_DATABASE_NAME":              "jedi_archives",
				"JEDI_DATABASE_USERNAME":          "master-yoda",
				"JEDI_DATABASE_PASSWORD":          "may-the-force-be-with-you",
				"JEDI_DATABASE_HMAC_INDEX_SECRET": "",
			},
			wantErr:     true,
			errContains: "JEDI_DATABASE_HMAC_INDEX_SECRET not set",
		},

		// --- Identity / UserAuth ---
		{
			name: "identity invalid url",
			def: SvcDefinition{
				ServiceName: "padme",
				Tls:         StandardTls,
				Requires:    Requires{Identity: true},
			},
			env: map[string]string{
				"PADME_SERVICE_CLIENT_ID": "senator-amidala",
				"PADME_SERVICE_PORT":      ":8443",
				"PADME_SERVER_CERT":       serverCert,
				"PADME_SERVER_KEY":        serverKey,
				"PADME_USER_AUTH_URL":     "naboo-palace",
			},
			wantErr:     true,
			errContains: "invalid url",
		},
		{
			name: "identity success",
			def: SvcDefinition{
				ServiceName: "padme",
				Tls:         StandardTls,
				Requires:    Requires{Identity: true},
			},
			env: map[string]string{
				"PADME_SERVICE_CLIENT_ID": "senator-amidala",
				"PADME_SERVICE_PORT":      ":8443",
				"PADME_SERVER_CERT":       serverCert,
				"PADME_SERVER_KEY":        serverKey,
				"PADME_USER_AUTH_URL":     "https://naboo.galactic-senate.gov:8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.UserAuth.Url != "https://naboo.galactic-senate.gov:8443" {
					t.Errorf("UserAuth.Url = %q", cfg.UserAuth.Url)
				}
			},
		},

		// --- JWT keys ---
		{
			name: "missing s2s verifying key",
			def: SvcDefinition{
				ServiceName: "holocron",
				Tls:         StandardTls,
				Requires:    Requires{S2sVerifyingKey: true},
			},
			env: map[string]string{
				"HOLOCRON_SERVICE_CLIENT_ID": "jedi-order",
				"HOLOCRON_SERVICE_PORT":      ":8443",
				"HOLOCRON_SERVER_CERT":       serverCert,
				"HOLOCRON_SERVER_KEY":        serverKey,
			},
			wantErr:     true,
			errContains: "HOLOCRON_S2S_JWT_VERIFYING_KEY not set",
		},
		{
			name: "all JWT keys success",
			def: SvcDefinition{
				ServiceName: "holocron",
				Tls:         StandardTls,
				Requires: Requires{
					S2sSigningKey:    true,
					S2sVerifyingKey:  true,
					UserSigningKey:   true,
					UserVerifyingKey: true,
				},
			},
			env: map[string]string{
				"HOLOCRON_SERVICE_CLIENT_ID":      "jedi-order",
				"HOLOCRON_SERVICE_PORT":           ":8443",
				"HOLOCRON_SERVER_CERT":            serverCert,
				"HOLOCRON_SERVER_KEY":             serverKey,
				"HOLOCRON_S2S_JWT_SIGNING_KEY":    "qui-gon-s2s-signing-key",
				"HOLOCRON_S2S_JWT_VERIFYING_KEY":  "mace-windu-s2s-verifying-key",
				"HOLOCRON_USER_JWT_SIGNING_KEY":   "anakin-user-signing-key",
				"HOLOCRON_USER_JWT_VERIFYING_KEY": "padme-user-verifying-key",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Jwt.S2sSigningKey != "qui-gon-s2s-signing-key" {
					t.Errorf("Jwt.S2sSigningKey = %q", cfg.Jwt.S2sSigningKey)
				}
				if cfg.Jwt.S2sVerifyingKey != "mace-windu-s2s-verifying-key" {
					t.Errorf("Jwt.S2sVerifyingKey = %q", cfg.Jwt.S2sVerifyingKey)
				}
				if cfg.Jwt.UserSigningKey != "anakin-user-signing-key" {
					t.Errorf("Jwt.UserSigningKey = %q", cfg.Jwt.UserSigningKey)
				}
				if cfg.Jwt.UserVerifyingKey != "padme-user-verifying-key" {
					t.Errorf("Jwt.UserVerifyingKey = %q", cfg.Jwt.UserVerifyingKey)
				}
			},
		},

		// --- PAT generator ---
		{
			name: "pat generator missing pepper",
			def: SvcDefinition{
				ServiceName: "cantina",
				Tls:         StandardTls,
				Requires:    Requires{PatGenerator: true},
			},
			env: map[string]string{
				"CANTINA_SERVICE_CLIENT_ID": "wuher-barkeep",
				"CANTINA_SERVICE_PORT":      ":8443",
				"CANTINA_SERVER_CERT":       serverCert,
				"CANTINA_SERVER_KEY":        serverKey,
			},
			wantErr:     true,
			errContains: "CANTINA_PAT_PEPPER not set",
		},
		{
			name: "pat generator success",
			def: SvcDefinition{
				ServiceName: "cantina",
				Tls:         StandardTls,
				Requires:    Requires{PatGenerator: true},
			},
			env: map[string]string{
				"CANTINA_SERVICE_CLIENT_ID": "wuher-barkeep",
				"CANTINA_SERVICE_PORT":      ":8443",
				"CANTINA_SERVER_CERT":       serverCert,
				"CANTINA_SERVER_KEY":        serverKey,
				"CANTINA_PAT_PEPPER":        "mos-eisley-cantina-pepper",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Pat.Pepper != "mos-eisley-cantina-pepper" {
					t.Errorf("Pat.Pepper = %q", cfg.Pat.Pepper)
				}
			},
		},

		// --- OAuth redirect ---
		{
			name: "oauth redirect invalid callback url",
			def: SvcDefinition{
				ServiceName: "senate",
				Tls:         StandardTls,
				Requires:    Requires{OauthRedirect: true},
			},
			env: map[string]string{
				"SENATE_SERVICE_CLIENT_ID":        "chancellor-palpatine",
				"SENATE_SERVICE_PORT":             ":8443",
				"SENATE_SERVER_CERT":              serverCert,
				"SENATE_SERVER_KEY":               serverKey,
				"SENATE_OAUTH_CALLBACK_URL":       "holonet-senate-gov",
				"SENATE_OAUTH_CALLBACK_CLIENT_ID": "jar-jar-binks",
			},
			wantErr:     true,
			errContains: "invalid url",
		},
		{
			name: "oauth redirect success",
			def: SvcDefinition{
				ServiceName: "senate",
				Tls:         StandardTls,
				Requires:    Requires{OauthRedirect: true},
			},
			env: map[string]string{
				"SENATE_SERVICE_CLIENT_ID":        "chancellor-palpatine",
				"SENATE_SERVICE_PORT":             ":8443",
				"SENATE_SERVER_CERT":              serverCert,
				"SENATE_SERVER_KEY":               serverKey,
				"SENATE_OAUTH_CALLBACK_URL":       "https://holonet.senate.gov:443/oauth/callback",
				"SENATE_OAUTH_CALLBACK_CLIENT_ID": "jar-jar-binks",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.OauthRedirect.CallbackUrl != "https://holonet.senate.gov:443/oauth/callback" {
					t.Errorf("OauthRedirect.CallbackUrl = %q", cfg.OauthRedirect.CallbackUrl)
				}
				if cfg.OauthRedirect.CallbackClientId != "jar-jar-binks" {
					t.Errorf("OauthRedirect.CallbackClientId = %q", cfg.OauthRedirect.CallbackClientId)
				}
			},
		},

		// --- downstream service URLs ---
		{
			name: "tasks service success",
			def: SvcDefinition{
				ServiceName: "r2d2",
				Tls:         StandardTls,
				Requires:    Requires{Tasks: true},
			},
			env: map[string]string{
				"R2D2_SERVICE_CLIENT_ID": "artoo-detoo",
				"R2D2_SERVICE_PORT":      ":8443",
				"R2D2_SERVER_CERT":       serverCert,
				"R2D2_SERVER_KEY":        serverKey,
				"R2D2_TASKS_URL":         "https://tasks.rebel-base.svc.cluster.local:8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Tasks.Url != "https://tasks.rebel-base.svc.cluster.local:8443" {
					t.Errorf("Tasks.Url = %q", cfg.Tasks.Url)
				}
			},
		},
		{
			name: "gallery service success",
			def: SvcDefinition{
				ServiceName: "r2d2",
				Tls:         StandardTls,
				Requires:    Requires{Gallery: true},
			},
			env: map[string]string{
				"R2D2_SERVICE_CLIENT_ID": "artoo-detoo",
				"R2D2_SERVICE_PORT":      ":8443",
				"R2D2_SERVER_CERT":       serverCert,
				"R2D2_SERVER_KEY":        serverKey,
				"R2D2_GALLERY_URL":       "https://gallery.rebel-base.svc.cluster.local:8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Gallery.Url != "https://gallery.rebel-base.svc.cluster.local:8443" {
					t.Errorf("Gallery.Url = %q", cfg.Gallery.Url)
				}
			},
		},
		{
			name: "object storage success",
			def: SvcDefinition{
				ServiceName: "r2d2",
				Tls:         StandardTls,
				Requires:    Requires{ObjectStorage: true},
			},
			env: map[string]string{
				"R2D2_SERVICE_CLIENT_ID":         "artoo-detoo",
				"R2D2_SERVICE_PORT":              ":8443",
				"R2D2_SERVER_CERT":               serverCert,
				"R2D2_SERVER_KEY":                serverKey,
				"R2D2_CLIENT_CERT":               clientCert,
				"R2D2_CLIENT_KEY":                clientKey,
				"R2D2_CA_CERT":                   caCert,
				"R2D2_OBJECT_STORAGE_URL":        "https://minio.rebel-base.svc.cluster.local:9000",
				"R2D2_OBJECT_STORAGE_BUCKET":     "deathstar-plans",
				"R2D2_OBJECT_STORAGE_ACCESS_KEY": "c3po-access-key",
				"R2D2_OBJECT_STORAGE_SECRET_KEY": "golden-droid-secret",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.ObjectStorage.Url != "https://minio.rebel-base.svc.cluster.local:9000" {
					t.Errorf("ObjectStorage.Url = %q", cfg.ObjectStorage.Url)
				}
				if cfg.ObjectStorage.Bucket != "deathstar-plans" {
					t.Errorf("ObjectStorage.Bucket = %q", cfg.ObjectStorage.Bucket)
				}
				if cfg.ObjectStorage.AccessKey != "c3po-access-key" {
					t.Errorf("ObjectStorage.AccessKey = %q", cfg.ObjectStorage.AccessKey)
				}
				if cfg.ObjectStorage.SecretKey != "golden-droid-secret" {
					t.Errorf("ObjectStorage.SecretKey = %q", cfg.ObjectStorage.SecretKey)
				}
			},
		},
		{
			name: "profiles service success",
			def: SvcDefinition{
				ServiceName: "r2d2",
				Tls:         StandardTls,
				Requires:    Requires{Profiles: true},
			},
			env: map[string]string{
				"R2D2_SERVICE_CLIENT_ID": "artoo-detoo",
				"R2D2_SERVICE_PORT":      ":8443",
				"R2D2_SERVER_CERT":       serverCert,
				"R2D2_SERVER_KEY":        serverKey,
				"R2D2_PROFILES_URL":      "https://profiles.rebel-base.svc.cluster.local:8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Profiles.Url != "https://profiles.rebel-base.svc.cluster.local:8443" {
					t.Errorf("Profiles.Url = %q", cfg.Profiles.Url)
				}
			},
		},

		// --- full kitchen sink ---
		{
			name: "full config galactic republic",
			def: SvcDefinition{
				ServiceName: "republic",
				Tls:         MutualTls,
				Requires: Requires{
					S2sClient:        true,
					Db:               true,
					AesSecret:        true,
					IndexSecret:      true,
					S2sSigningKey:    true,
					S2sVerifyingKey:  true,
					Identity:         true,
					UserSigningKey:   true,
					UserVerifyingKey: true,
					PatGenerator:     true,
					OauthRedirect:    true,
					Tasks:            true,
					Gallery:          true,
					ObjectStorage:    true,
					Profiles:         true,
				},
			},
			env: map[string]string{
				"REPUBLIC_SERVICE_CLIENT_ID":          "obi-wan-kenobi",
				"REPUBLIC_SERVICE_PORT":               ":7654",
				"REPUBLIC_SERVER_CERT":                serverCert,
				"REPUBLIC_SERVER_KEY":                 serverKey,
				"REPUBLIC_CLIENT_CERT":                clientCert,
				"REPUBLIC_CLIENT_KEY":                 clientKey,
				"REPUBLIC_CA_CERT":                    caCert,
				"REPUBLIC_DB_CLIENT_CERT":             dbClientCert,
				"REPUBLIC_DB_CLIENT_KEY":              dbClientKey,
				"REPUBLIC_DB_CA_CERT":                 dbCaCert,
				"REPUBLIC_DATABASE_URL":               "bespin-db.cloud.city:5432",
				"REPUBLIC_DATABASE_NAME":              "jedi_archives",
				"REPUBLIC_DATABASE_USERNAME":          "master-yoda",
				"REPUBLIC_DATABASE_PASSWORD":          "may-the-force-be-with-you",
				"REPUBLIC_FIELD_LEVEL_AES_GCM_SECRET": "kyber-crystal-aes-256-key",
				"REPUBLIC_DATABASE_HMAC_INDEX_SECRET": "force-sensitive-hmac-index",
				"REPUBLIC_S2S_AUTH_URL":               "https://coruscant-auth.jedi.svc.cluster.local:8443",
				"REPUBLIC_S2S_AUTH_CLIENT_ID":         "jedi-council",
				"REPUBLIC_S2S_AUTH_CLIENT_SECRET":     "clone-army-secret",
				"REPUBLIC_USER_AUTH_URL":              "https://senate.coruscant.gov:8443",
				"REPUBLIC_S2S_JWT_SIGNING_KEY":        "qui-gon-s2s-signing",
				"REPUBLIC_S2S_JWT_VERIFYING_KEY":      "mace-windu-s2s-verify",
				"REPUBLIC_USER_JWT_SIGNING_KEY":       "anakin-user-signing",
				"REPUBLIC_USER_JWT_VERIFYING_KEY":     "padme-user-verify",
				"REPUBLIC_PAT_PEPPER":                 "midichlorian-pepper",
				"REPUBLIC_OAUTH_CALLBACK_URL":         "https://holonet.republic.gov:443/oauth/callback",
				"REPUBLIC_OAUTH_CALLBACK_CLIENT_ID":   "chancellor-palpatine",
				"REPUBLIC_TASKS_URL":                  "https://tasks.republic.svc.cluster.local:8443",
				"REPUBLIC_GALLERY_URL":                "https://gallery.republic.svc.cluster.local:8443",
				"REPUBLIC_OBJECT_STORAGE_URL":         "https://minio.republic.svc.cluster.local:9000",
				"REPUBLIC_OBJECT_STORAGE_BUCKET":      "republic-archives",
				"REPUBLIC_OBJECT_STORAGE_ACCESS_KEY":  "c3po-access-key",
				"REPUBLIC_OBJECT_STORAGE_SECRET_KEY":  "r2d2-secret-key",
				"REPUBLIC_PROFILES_URL":               "https://profiles.republic.svc.cluster.local:8443",
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.ServiceName != "republic" {
					t.Errorf("ServiceName = %q", cfg.ServiceName)
				}
				if cfg.ServiceClientId != "obi-wan-kenobi" {
					t.Errorf("ServiceClientId = %q", cfg.ServiceClientId)
				}
				if cfg.ServicePort != ":7654" {
					t.Errorf("ServicePort = %q", cfg.ServicePort)
				}
				if cfg.Tls != MutualTls {
					t.Errorf("Tls = %q", cfg.Tls)
				}
				// certs
				if cfg.Certs.ServerCert == nil || *cfg.Certs.ServerCert != serverCert {
					t.Errorf("ServerCert = %v", cfg.Certs.ServerCert)
				}
				if cfg.Certs.ServerKey == nil || *cfg.Certs.ServerKey != serverKey {
					t.Errorf("ServerKey = %v", cfg.Certs.ServerKey)
				}
				if cfg.Certs.ServerCa == nil || *cfg.Certs.ServerCa != caCert {
					t.Errorf("ServerCa = %v", cfg.Certs.ServerCa)
				}
				if cfg.Certs.ClientCert == nil || *cfg.Certs.ClientCert != clientCert {
					t.Errorf("ClientCert = %v", cfg.Certs.ClientCert)
				}
				if cfg.Certs.ClientKey == nil || *cfg.Certs.ClientKey != clientKey {
					t.Errorf("ClientKey = %v", cfg.Certs.ClientKey)
				}
				if cfg.Certs.ClientCa == nil || *cfg.Certs.ClientCa != caCert {
					t.Errorf("ClientCa = %v", cfg.Certs.ClientCa)
				}
				if cfg.Certs.DbClientCert == nil || *cfg.Certs.DbClientCert != dbClientCert {
					t.Errorf("DbClientCert = %v", cfg.Certs.DbClientCert)
				}
				if cfg.Certs.DbClientKey == nil || *cfg.Certs.DbClientKey != dbClientKey {
					t.Errorf("DbClientKey = %v", cfg.Certs.DbClientKey)
				}
				if cfg.Certs.DbCaCert == nil || *cfg.Certs.DbCaCert != dbCaCert {
					t.Errorf("DbCaCert = %v", cfg.Certs.DbCaCert)
				}
				// database
				if cfg.Database.Url != "bespin-db.cloud.city:5432" {
					t.Errorf("Database.Url = %q", cfg.Database.Url)
				}
				if cfg.Database.Name != "jedi_archives" {
					t.Errorf("Database.Name = %q", cfg.Database.Name)
				}
				if cfg.Database.Username != "master-yoda" {
					t.Errorf("Database.Username = %q", cfg.Database.Username)
				}
				if cfg.Database.Password != "may-the-force-be-with-you" {
					t.Errorf("Database.Password = %q", cfg.Database.Password)
				}
				if cfg.Database.FieldSecret != "kyber-crystal-aes-256-key" {
					t.Errorf("Database.FieldSecret = %q", cfg.Database.FieldSecret)
				}
				if cfg.Database.IndexSecret != "force-sensitive-hmac-index" {
					t.Errorf("Database.IndexSecret = %q", cfg.Database.IndexSecret)
				}
				// service auth
				if cfg.ServiceAuth.Url != "https://coruscant-auth.jedi.svc.cluster.local:8443" {
					t.Errorf("ServiceAuth.Url = %q", cfg.ServiceAuth.Url)
				}
				if cfg.ServiceAuth.ClientId != "jedi-council" {
					t.Errorf("ServiceAuth.ClientId = %q", cfg.ServiceAuth.ClientId)
				}
				if cfg.ServiceAuth.ClientSecret != "clone-army-secret" {
					t.Errorf("ServiceAuth.ClientSecret = %q", cfg.ServiceAuth.ClientSecret)
				}
				// user auth
				if cfg.UserAuth.Url != "https://senate.coruscant.gov:8443" {
					t.Errorf("UserAuth.Url = %q", cfg.UserAuth.Url)
				}
				// jwt
				if cfg.Jwt.S2sSigningKey != "qui-gon-s2s-signing" {
					t.Errorf("Jwt.S2sSigningKey = %q", cfg.Jwt.S2sSigningKey)
				}
				if cfg.Jwt.S2sVerifyingKey != "mace-windu-s2s-verify" {
					t.Errorf("Jwt.S2sVerifyingKey = %q", cfg.Jwt.S2sVerifyingKey)
				}
				if cfg.Jwt.UserSigningKey != "anakin-user-signing" {
					t.Errorf("Jwt.UserSigningKey = %q", cfg.Jwt.UserSigningKey)
				}
				if cfg.Jwt.UserVerifyingKey != "padme-user-verify" {
					t.Errorf("Jwt.UserVerifyingKey = %q", cfg.Jwt.UserVerifyingKey)
				}
				// pat
				if cfg.Pat.Pepper != "midichlorian-pepper" {
					t.Errorf("Pat.Pepper = %q", cfg.Pat.Pepper)
				}
				// oauth
				if cfg.OauthRedirect.CallbackUrl != "https://holonet.republic.gov:443/oauth/callback" {
					t.Errorf("OauthRedirect.CallbackUrl = %q", cfg.OauthRedirect.CallbackUrl)
				}
				if cfg.OauthRedirect.CallbackClientId != "chancellor-palpatine" {
					t.Errorf("OauthRedirect.CallbackClientId = %q", cfg.OauthRedirect.CallbackClientId)
				}
				// downstream services
				if cfg.Tasks.Url != "https://tasks.republic.svc.cluster.local:8443" {
					t.Errorf("Tasks.Url = %q", cfg.Tasks.Url)
				}
				if cfg.Gallery.Url != "https://gallery.republic.svc.cluster.local:8443" {
					t.Errorf("Gallery.Url = %q", cfg.Gallery.Url)
				}
				if cfg.ObjectStorage.Url != "https://minio.republic.svc.cluster.local:9000" {
					t.Errorf("ObjectStorage.Url = %q", cfg.ObjectStorage.Url)
				}
				if cfg.ObjectStorage.Bucket != "republic-archives" {
					t.Errorf("ObjectStorage.Bucket = %q", cfg.ObjectStorage.Bucket)
				}
				if cfg.ObjectStorage.AccessKey != "c3po-access-key" {
					t.Errorf("ObjectStorage.AccessKey = %q", cfg.ObjectStorage.AccessKey)
				}
				if cfg.ObjectStorage.SecretKey != "r2d2-secret-key" {
					t.Errorf("ObjectStorage.SecretKey = %q", cfg.ObjectStorage.SecretKey)
				}
				if cfg.Profiles.Url != "https://profiles.republic.svc.cluster.local:8443" {
					t.Errorf("Profiles.Url = %q", cfg.Profiles.Url)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := Load(tt.def)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}
