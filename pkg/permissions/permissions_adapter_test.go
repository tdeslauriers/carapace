package permissions

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// Adapter tests verify SQL query structure and error propagation at the DB boundary.
//
// Success paths for SelectOneRecord-based methods (FindBySlugIndex) require
// constructing a real *sql.Row, which is not possible without a registered driver.
// Those end-to-end paths are covered by the service-level tests via mockRepo.

func TestFindAll_Adapter(t *testing.T) {
	tests := []struct {
		name       string
		queryErr   error
		wantErr    bool
		errSubstr  string
		checkQuery func(*testing.T, string)
	}{
		{
			name:      "query_error_propagated",
			queryErr:  errors.New("db connection refused"),
			wantErr:   true,
			errSubstr: "db connection refused",
		},
		{
			name:     "correct_table_and_columns_in_query",
			queryErr: errors.New("stop after capture"),
			wantErr:  true,
			checkQuery: func(t *testing.T, q string) {
				for _, col := range []string{
					"FROM permission",
					"uuid",
					"service_name",
					"permission",
					"name",
					"description",
					"created_at",
					"active",
					"slug",
					"slug_index",
				} {
					if !strings.Contains(q, col) {
						t.Errorf("query missing %q:\n%s", col, q)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			db := &mockSqlDB{
				queryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
					capturedQuery = query
					return nil, tt.queryErr
				},
			}
			repo := &permissionsRepository{sql: db}
			_, err := repo.FindAll()

			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

func TestFindBySlugIndex_Adapter(t *testing.T) {
	// FindBySlugIndex uses SelectOneRecord which calls QueryRow. Creating a
	// *sql.Row with a controlled error requires a registered driver, so we
	// verify that the correct index arg is forwarded instead.
	tests := []struct {
		name      string
		index     string
		checkArgs func(*testing.T, string, []interface{})
	}{
		{
			name:  "slug_index_passed_as_query_arg",
			index: "expected-blind-index",
			checkArgs: func(t *testing.T, query string, args []interface{}) {
				if !strings.Contains(query, "WHERE slug_index = ?") {
					t.Errorf("query missing WHERE clause:\n%s", query)
				}
				if len(args) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(args))
				}
				if args[0] != "expected-blind-index" {
					t.Errorf("arg[0] = %v, want %q", args[0], "expected-blind-index")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				capturedQuery string
				capturedArgs  []interface{}
			)
			db := &mockSqlDB{
				// QueryRow is called by SelectOneRecord; we capture args then
				// return nil. The subsequent row.Scan() on a nil *sql.Row will
				// panic, so we recover and still validate captured state.
				queryRowFunc: func(query string, args ...interface{}) *sql.Row {
					capturedQuery = query
					capturedArgs = args
					return nil
				},
			}
			repo := &permissionsRepository{sql: db}

			// Recover from the nil-row panic; we only care about captured args.
			func() {
				defer func() { recover() }() //nolint:errcheck
				_, _ = repo.FindBySlugIndex(tt.index)
			}()

			if tt.checkArgs != nil {
				tt.checkArgs(t, capturedQuery, capturedArgs)
			}
		})
	}
}

func TestInsertPermission_Adapter(t *testing.T) {
	record := PermissionRecord{
		Id:          testUUID,
		ServiceName: "pixie",
		Permission:  "enc-READ",
		Name:        "enc-Read Posts",
		Description: "enc-Allows reading posts",
		Active:      true,
		Slug:        "enc-" + testUUID2,
		SlugIndex:   "some-blind-index",
	}

	tests := []struct {
		name       string
		prepareErr error
		wantErr    bool
		errSubstr  string
		checkQuery func(*testing.T, string)
	}{
		{
			name:       "prepare_error_propagated",
			prepareErr: errors.New("too many connections"),
			wantErr:    true,
			errSubstr:  "too many connections",
		},
		{
			name:       "correct_table_and_columns_in_query",
			prepareErr: errors.New("stop after query capture"),
			wantErr:    true,
			checkQuery: func(t *testing.T, q string) {
				for _, expected := range []string{
					"INSERT INTO permission",
					"uuid",
					"service_name",
					"permission",
					"name",
					"description",
					"created_at",
					"active",
					"slug",
					"slug_index",
				} {
					if !strings.Contains(q, expected) {
						t.Errorf("query missing %q:\n%s", expected, q)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			db := &mockSqlDB{
				prepareFunc: func(query string) (*sql.Stmt, error) {
					capturedQuery = query
					return nil, tt.prepareErr
				},
			}
			repo := &permissionsRepository{sql: db}
			err := repo.InsertPermission(record)

			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

func TestUpdatePermission_Adapter(t *testing.T) {
	record := PermissionRecord{
		Permission:  "enc-READ",
		Name:        "enc-Read Posts",
		Description: "enc-Allows reading posts",
		Active:      true,
		SlugIndex:   "some-blind-index",
	}

	tests := []struct {
		name       string
		input      PermissionRecord
		prepareErr error
		wantErr    bool
		errSubstr  string
		checkQuery func(*testing.T, string)
	}{
		{
			name:       "prepare_error_propagated",
			input:      record,
			prepareErr: errors.New("connection pool exhausted"),
			wantErr:    true,
			errSubstr:  "connection pool exhausted",
		},
		{
			name:       "correct_table_and_set_columns_in_query",
			input:      record,
			prepareErr: errors.New("stop after query capture"),
			wantErr:    true,
			checkQuery: func(t *testing.T, q string) {
				for _, expected := range []string{
					"UPDATE permission",
					"permission =",
					"name =",
					"description =",
					"active =",
					"WHERE slug_index =",
				} {
					if !strings.Contains(q, expected) {
						t.Errorf("query missing %q:\n%s", expected, q)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			db := &mockSqlDB{
				prepareFunc: func(query string) (*sql.Stmt, error) {
					capturedQuery = query
					return nil, tt.prepareErr
				},
			}
			repo := &permissionsRepository{sql: db}
			err := repo.UpdatePermission(tt.input)

			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}
