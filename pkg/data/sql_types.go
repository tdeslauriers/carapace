package data

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"
)

// Selector defines the interface for SQL select operations.
// It exists to be passed to the select many/select one functions
// so mocking/testing can be conducted easily.  |
// Actual usage should pass the *sql.DB or *sql.Tx types since those
// inherently implement these methods.
type Selector interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// Execer defines the interface for SQL select operations.
// It exists to be passed to the select many/select one functions
// so mocking/testing can be conducted easily.  |
// Actual usage should pass the *sql.DB or *sql.Tx types since those
// inherently implement these methods.
type Execer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Prepare(query string) (*sql.Stmt, error)
}

// used to handle custom time scanning from sql to UTC
type CustomTime struct {
	time.Time
}

// Scan implements the sql.Scanner interface
func (ct *CustomTime) Scan(value interface{}) error {
	var t time.Time
	switch v := value.(type) {
	case []byte:
		var err error
		t, err = time.Parse("2006-01-02 15:04:05", string(v))
		if err != nil {
			return err
		}
	case string:
		var err error
		t, err = time.Parse("2006-01-02 15:04:05", v)
		if err != nil {
			return err
		}
	case time.Time:
		t = v
	default:
		return errors.New("unsupported data type")
	}
	ct.Time = t.UTC()
	return nil
}

// Value implements the driver.Valuer interface
func (ct CustomTime) Value() (driver.Value, error) {
	// return a driver.Value representation of CustomTime
	if ct.IsZero() {
		return nil, nil // Use NULL for zero time
	}
	return ct.UTC().Format("2006-01-02 15:04:05"), nil
}
