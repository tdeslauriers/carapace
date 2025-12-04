package data

import (
	"fmt"
	"reflect"
)

// SelectRecords executes a select query and maps the results to the generic type defined records slice.
func SelectRecords[T any](db Selector, query string, args ...interface{}) ([]T, error) {

	// execute query
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed execute select records query: %v", err)
	}
	defer rows.Close()

	// instantiate generic slice for type return
	var results []T

	// loop thru rows/results, map row to record type, append to slice
	for rows.Next() {
		var record T

		// reflect the record type
		// reflection is needed to process the rows.Scan(...) function dynamically
		v := reflect.ValueOf(&record).Elem()
		fields := make([]interface{}, v.NumField())
		for i := 0; i < v.NumField(); i++ {
			fields[i] = v.Field(i).Addr().Interface()
		}

		if err := rows.Scan(fields...); err != nil {
			return nil, fmt.Errorf("failed to scan row into record: %v", err)
		}

		results = append(results, record)
	}

	return results, rows.Err()
}

// SelectOneRecord executes a select query and maps the result to the generic type defined record.
func SelectOneRecord[T any](db Selector, query string, args ...interface{}) (T, error) {

	// instantiate generic record for type return
	var record T

	// execute query
	row := db.QueryRow(query, args...)

	// reflect the record type
	// reflection is needed to process the rows.Scan(...) function dynamically
	v := reflect.ValueOf(&record).Elem()
	fields := make([]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		fields[i] = v.Field(i).Addr().Interface()
	}

	if err := row.Scan(fields...); err != nil {
		return record, fmt.Errorf("failed to scan row into record: %v", err)
	}

	return record, nil
}

// SelectExists executes a select query to determine if records exist.
func SelectExists(db Selector, query string, args ...interface{}) (bool, error) {

	var exists bool

	// execute query
	err := db.QueryRow(query, args...).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// InsertRecord executes an insert query using the provided record struct as
// the source for the column field insertion values.
func InsertRecord[T any](db Execer, query string, record T) error {

	// reflection is needed to process the record struct dynamically
	insert := reflect.ValueOf(record)

	// ensure parameter is a struct
	if insert.Kind() != reflect.Struct {
		return fmt.Errorf("insert record must be of type struct")
	}

	// build args slice from struct fields
	fields := make([]interface{}, insert.NumField())
	for i := 0; i < insert.NumField(); i++ {
		fields[i] = insert.Field(i).Interface()

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

// UpdateRecord executes an update query with the provided arguments.
func UpdateRecord(db Execer, query string, args ...interface{}) error {

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

// Delete Record executes a delete query with the provided arguments.
func DeleteRecord(db Execer, query string, args ...interface{}) error {

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
