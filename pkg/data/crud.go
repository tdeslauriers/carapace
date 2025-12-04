package data

import (
	"database/sql"
	"fmt"
	"reflect"
)

func NewSqlRepository(db *sql.DB) SqlRepository {
	return &mariadbRepository{
		db: db,
	}
}

// SqlRepository defines the interface for the generic SQL functions to
// ingest as parameters so that mocking tests can be created.
type SqlRepository interface {
	SelectRecords(query string, records interface{}, args ...interface{}) error
	SelectRecord(query string, record interface{}, args ...interface{}) error
	SelectExists(query string, args ...interface{}) (bool, error)
	InsertRecord(query string, record interface{}) error
	UpdateRecord(query string, args ...interface{}) error
	DeleteRecord(query string, args ...interface{}) error
	Close() error
}

var _ SqlRepository = (*mariadbRepository)(nil)

type mariadbRepository struct {
	db *sql.DB
}

func (r *mariadbRepository) Close() error {
	if err := r.db.Close(); err != nil {
		return fmt.Errorf("failed to close db connection: %v", err)
	}
	return nil
}

func (r *mariadbRepository) SelectRecords(query string, records interface{}, args ...interface{}) error {

	// execute query
	rows, err := r.db.Query(query, args...)
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

func (r *mariadbRepository) SelectRecord(query string, record interface{}, args ...interface{}) error {

	// execute query
	row := r.db.QueryRow(query, args...)

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

func (r *mariadbRepository) SelectExists(query string, args ...interface{}) (bool, error) {

	var exists bool
	err := r.db.QueryRow(query, args...).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *mariadbRepository) InsertRecord(query string, record interface{}) error {

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
	stmt, err := r.db.Prepare(query)
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

func (r *mariadbRepository) UpdateRecord(query string, args ...interface{}) error {

	// prepared statement
	stmt, err := r.db.Prepare(query)
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

func (r *mariadbRepository) DeleteRecord(query string, args ...interface{}) error {

	// prepared statement
	stmt, err := r.db.Prepare(query)
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
