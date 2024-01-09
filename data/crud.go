package data

import (
	"fmt"
	"reflect"
)

type SqlRepository interface {
	SelectRecords(query string, records interface{}, args ...interface{}) error
	SelectRecord(query string, record interface{}, args ...interface{}) error
	InsertRecord(query string, record interface{}) error
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
		return err
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

	// create prepared statement
	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// map record interface to prepared statement args
	insert := reflect.ValueOf(record)
	if insert.Kind() != reflect.Struct {
		return fmt.Errorf("insert record must be of type struct")
	}

	fields := make([]interface{}, insert.NumField())
	for i := 0; i < insert.NumField(); i++ {
		fields[i] = insert.Field(i).Interface()
	}

	// execute prepared statement
	_, err = stmt.Exec(fields...)
	if err != nil {
		return err
	}

	return nil
}
