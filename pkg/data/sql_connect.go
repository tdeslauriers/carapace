package data

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

// DbUrl holds the parameters needed to build a database connection URL.
type DbUrl struct {
	Username string
	Password string
	Addr     string
	Name     string // database name
}

// Build constructs the database connection URL string.
func (url *DbUrl) Build() string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", url.Username, url.Password, url.Addr, url.Name)
}

// SqlDbConnector defines the interface for SQL database connection
type SqlDbConnector interface {

	// Connect establishes a connection to the MariaDB/MySQL database including
	// TLS configuration and setting the pool parameters to 25 max open/idle connections
	// and a max connection lifetime of 5 minutes.
	Connect() (*sql.DB, error)
}

// NewSqlDbConnector creates a new instance of SqlDbConnector for MariaDB/MySQL databases.
func NewSqlDbConnector(url DbUrl, tlsConfig *tls.Config) SqlDbConnector {
	return &mariaDbConnector{
		TlsConfig:     tlsConfig,
		ConnectionUrl: url.Build(),
	}
}

var _ SqlDbConnector = (*mariaDbConnector)(nil)

// mariaDbConnector holds the parameters needed to connect to a MariaDB/MySQL database.
type mariaDbConnector struct {
	TlsConfig     *tls.Config
	ConnectionUrl string
}

// Connect is the concrete implementation of the interface method which
// establishes a connection to the MariaDB/MySQL database including
// TLS configuration and setting the pool parameters to 25 max open/idle connections
// and a max connection lifetime of 5 minutes.
func (c *mariaDbConnector) Connect() (*sql.DB, error) {

	// register tls => "custom" key comes from mysql lib
	if err := mysql.RegisterTLSConfig("custom", c.TlsConfig); err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", c.ConnectionUrl+"?tls=custom")
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
