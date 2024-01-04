package data

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/go-sql-driver/mysql"
	"github.com/tdeslauriers/carapace/connect"
)

type SqlDbConnector interface {
	Connect() (*sql.DB, error)
	// SelectRecords(table string, sqlParams string, results interface{}) error
	// InsertRecord(table string, insert interface{}) error
}

type MariaDbConnector struct {
	TlsConfig     connect.ClientConfig
	ConnectionUrl string
}

type DbUrl struct {
	Username string
	Password string
	Addr     string
	Name     string // database name
}

func (url *DbUrl) Build() string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s", url.Username, url.Password, url.Addr, url.Name)
}

func (conn *MariaDbConnector) Connect() (*sql.DB, error) {
	tlsConfig, err := conn.TlsConfig.Build()
	if err != nil {
		log.Fatalf("Unable to create TLS Config for Db Connection: %v", err)
	}

	// register tls => "custom" key comes from mysql lib
	if err := mysql.RegisterTLSConfig("custom", tlsConfig); err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", conn.ConnectionUrl+"?tls=custom")
	if err != nil {
		return nil, err
	}

	return db, nil
}
