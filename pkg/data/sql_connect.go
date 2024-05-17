package data

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

type DbUrl struct {
	Username string
	Password string
	Addr     string
	Name     string // database name
}

func (url *DbUrl) Build() string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s", url.Username, url.Password, url.Addr, url.Name)
}

type SqlDbConnector interface {
	Connect() (*sql.DB, error)
}

func NewSqlDbConnector(url DbUrl, tlsConfig *tls.Config) SqlDbConnector {
	return &mariaDbConnector{
		TlsConfig:     tlsConfig,
		ConnectionUrl: url.Build(),
	}
}

var _ SqlDbConnector = (*mariaDbConnector)(nil)

type mariaDbConnector struct {
	TlsConfig     *tls.Config
	ConnectionUrl string
}

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
