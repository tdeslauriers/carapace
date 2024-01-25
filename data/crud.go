package data

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"time"
)

type SqlRepository interface {
	SelectRecords(query string, records interface{}, args ...interface{}) error
	SelectRecord(query string, record interface{}, args ...interface{}) error
	InsertRecord(query string, record interface{}) error
	UpdateRecord(query string, args ...interface{}) error
	DeleteRecord(query string, args ...interface{}) error
}

type MariaDbRepository struct {
	SqlDb SqlDbConnector
}

func (dao *MariaDbRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {

	// connect to db
	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// execute query
	rows, err := db.Query(query, args...)
	if err != nil {
		return fmt.Errorf("unable to execute select records query: %v", err)
	}
	defer rows.Close()

	// reflect records type
	v := reflect.ValueOf(records)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("records must be a pointer to a slice")
	}

	slice := v.Elem()
	recordType := v.Elem().Type().Elem()

	// loop thru rows/results, map row to record type, append to slice
	for rows.Next() {
		record := reflect.New(recordType).Elem()
		fields := make([]interface{}, record.NumField())
		for i := 0; i < record.NumField(); i++ {
			fields[i] = record.Field(i).Addr().Interface()
		}

		if err := rows.Scan(fields...); err != nil {
			return err
		}

		slice.Set(reflect.Append(slice, record))
	}

	return rows.Err()
}

func (dao *MariaDbRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	// connect to db
	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("unable to connect to sql database")
	}

	// execute query
	row := db.QueryRow(query, args...)

	// map row to record types, fields
	rec := reflect.ValueOf(record).Elem() // get concrete type
	fields := make([]interface{}, rec.NumField())
	for i := 0; i < rec.NumField(); i++ {
		fields[i] = rec.Field(i).Addr().Interface()
	}

	if err := row.Scan(fields...); err != nil {
		return err
	}

	return row.Err()
}

func (dao *MariaDbRepository) InsertRecord(query string, record interface{}) error {

	// connect to db
	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// map record interface to prepared statement args
	insert := reflect.ValueOf(record)
	if insert.Kind() != reflect.Struct {
		return fmt.Errorf("insert record must be of type struct")
	}

	fields := make([]interface{}, insert.NumField())
	for i := 0; i < insert.NumField(); i++ {
		fields[i] = insert.Field(i).Interface()

		// If the field is of type CustomTime, call its Value method
		if ct, ok := fields[i].(CustomTime); ok {
			timeValue, err := ct.Value()
			if err != nil {
				return err
			}
			fields[i] = timeValue
		}
	}

	// create prepared statement
	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// execute prepared statement
	_, err = stmt.Exec(fields...)
	if err != nil {
		return err
	}

	return nil
}

func (dao *MariaDbRepository) UpdateRecord(query string, args ...interface{}) error {

	// connect to db
	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// prepared statement
	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare update statement: %v", err)
	}
	defer stmt.Close()

	// execute the statement with the provided arguments
	_, err = stmt.Exec(args...)
	if err != nil {
		return fmt.Errorf("failed to execute update query: %v", err)
	}

	return nil
}

func (dao *MariaDbRepository) DeleteRecord(query string, args ...interface{}) error {

	// connect to db
	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// prepared statement
	stmt, err := db.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare delete statement: %v", err)
	}
	defer stmt.Close()

	// execute
	_, err = stmt.Exec(args...)
	if err != nil {
		return fmt.Errorf("failed to execute delete query: %v", err)
	}

	return nil
}

type CustomTime struct {
	time.Time
}

// implements the sql.Scanner interface
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
	ct.Time = t
	return nil
}

func (ct CustomTime) Value() (driver.Value, error) {
	// return a driver.Value representation of CustomTime
	if ct.IsZero() {
		return nil, nil // Use NULL for zero time
	}
	return ct.UTC().Format("2006-01-02 15:04:05"), nil
}
