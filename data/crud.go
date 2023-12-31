package data

import (
	"database/sql"
	"fmt"
	"log"
	"reflect"
	"strings"
)

type SqlRepository interface {
	Connect() (*sql.DB, error)
	SelectRecords(table string, sqlParams string, results interface{}) error
	InsertRecord(table string, insert interface{}) error
}

type Repository struct {
	SqlDb SqlDbConnector
}

func (dao *Repository) SelectRecords(table string, sqlParams string, results interface{}) error {

	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// get fields
	v := reflect.ValueOf(results)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("results param of select func must be a pointer to a slice")
	}
	elemType := v.Elem().Type().Elem()

	var columns []string
	for i := 0; i < elemType.NumField(); i++ {
		columns = append(columns, elemType.Field(i).Tag.Get("db"))
	}

	// build query
	query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), table)
	log.Print(query)

	// params (if applicable)
	if len(sqlParams) > 0 {
		query += sqlParams
	}

	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		result := reflect.New(elemType).Elem()
		scanArgs := make([]interface{}, len(columns))
		for i := range scanArgs {
			scanArgs[i] = result.Field(i).Addr().Interface()
		}
		err := rows.Scan(scanArgs...)
		if err != nil {
			log.Print(err)
		}

		v.Elem().Set(reflect.Append(v.Elem(), result))

	}

	return rows.Err()
}

func (dao *Repository) InsertRecord(table string, insert interface{}) error {

	db, err := dao.SqlDb.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to sql database: %v", err)
	}
	defer db.Close()

	// build query
	query := fmt.Sprintf("INSERT INTO %s (", table)

	inserts := structToMap(insert)
	keys := make([]string, len(inserts))
	values := make([]interface{}, len(inserts))
	i := 0
	for k, v := range inserts {
		keys[i] = k
		values[i] = v
		i++
	}

	query += strings.Join(keys, ", ")
	query += fmt.Sprintf(") VALUES (%s)", strings.Repeat("?, ", len(keys))[0:len(keys)*3-2])

	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(values...)
	if err != nil {
		return err
	}

	return nil
}

func structToMap(s interface{}) map[string]interface{} {

	result := make(map[string]interface{})

	v := reflect.ValueOf(s)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		result[t.Field(i).Tag.Get("db")] = v.Field(i).Interface()
	}

	return result
}
