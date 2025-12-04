package data

import (
	"database/sql"
	"errors"
	"testing"
)

// Mock implementations for testing

// mockSelector implements the Selector interface for testing
type mockSelector struct {
	queryFunc    func(query string, args ...interface{}) (*sql.Rows, error)
	queryRowFunc func(query string, args ...interface{}) *sql.Row
}

func (m *mockSelector) Query(query string, args ...interface{}) (*sql.Rows, error) {
	if m.queryFunc != nil {
		return m.queryFunc(query, args...)
	}
	return nil, errors.New("queryFunc not implemented")
}

func (m *mockSelector) QueryRow(query string, args ...interface{}) *sql.Row {
	if m.queryRowFunc != nil {
		return m.queryRowFunc(query, args...)
	}
	return nil
}

// mockExecer implements the Execer interface for testing
type mockExecer struct {
	execFunc    func(query string, args ...interface{}) (sql.Result, error)
	prepareFunc func(query string) (*sql.Stmt, error)
}

func (m *mockExecer) Exec(query string, args ...interface{}) (sql.Result, error) {
	if m.execFunc != nil {
		return m.execFunc(query, args...)
	}
	return nil, errors.New("execFunc not implemented")
}

func (m *mockExecer) Prepare(query string) (*sql.Stmt, error) {
	if m.prepareFunc != nil {
		return m.prepareFunc(query)
	}
	return nil, errors.New("prepareFunc not implemented")
}

// Test structs
type User struct {
	ID       int
	Username string
	Email    string
	Active   bool
}

type Product struct {
	ID    int
	Name  string
	Price float64
}

// TestSelectRecords tests the SelectRecords generic function
func TestSelectRecords(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		args          []interface{}
		mockQueryFunc func(query string, args ...interface{}) (*sql.Rows, error)
		expectError   bool
		validateError func(*testing.T, error)
		validateCall  func(*testing.T, string, []interface{})
	}{
		{
			name:  "query error is propagated",
			query: "SELECT * FROM users",
			args:  nil,
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				return nil, errors.New("database connection failed")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err == nil {
					t.Error("expected error, got nil")
				}
				expectedMsg := "failed execute select records query"
				if len(err.Error()) < len(expectedMsg) || err.Error()[:len(expectedMsg)] != expectedMsg {
					t.Errorf("expected error to start with %q, got %q", expectedMsg, err.Error())
				}
			},
		},
		{
			name:  "query is passed through correctly",
			query: "SELECT * FROM users WHERE active = ?",
			args:  []interface{}{true},
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				// Return error to prevent trying to iterate over invalid Rows
				return nil, errors.New("test complete")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if capturedQuery != "SELECT * FROM users WHERE active = ?" {
					t.Errorf("expected query %q, got %q", "SELECT * FROM users WHERE active = ?", capturedQuery)
				}
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(bool) != true {
					t.Errorf("expected arg true, got %v", capturedArgs[0])
				}
			},
		},
		{
			name:  "multiple arguments are passed correctly",
			query: "SELECT * FROM users WHERE active = ? AND id > ?",
			args:  []interface{}{true, 100},
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				return nil, errors.New("test complete")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 2 {
					t.Fatalf("expected 2 args, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(bool) != true {
					t.Errorf("expected first arg true, got %v", capturedArgs[0])
				}
				if capturedArgs[1].(int) != 100 {
					t.Errorf("expected second arg 100, got %v", capturedArgs[1])
				}
			},
		},
		{
			name:  "no arguments work correctly",
			query: "SELECT * FROM users",
			args:  nil,
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				return nil, errors.New("test complete")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 0 {
					t.Errorf("expected 0 args, got %d", len(capturedArgs))
				}
			},
		},
		{
			name:  "query with string argument",
			query: "SELECT * FROM users WHERE username = ?",
			args:  []interface{}{"alice"},
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				return nil, errors.New("test complete")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(string) != "alice" {
					t.Errorf("expected arg 'alice', got %v", capturedArgs[0])
				}
			},
		},
		{
			name:  "query with int argument",
			query: "SELECT * FROM users WHERE id = ?",
			args:  []interface{}{42},
			mockQueryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
				return nil, errors.New("test complete")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(int) != 42 {
					t.Errorf("expected arg 42, got %v", capturedArgs[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			var capturedArgs []interface{}

			mock := &mockSelector{
				queryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
					capturedQuery = query
					capturedArgs = args
					return tt.mockQueryFunc(query, args...)
				},
			}

			_, err := SelectRecords[User](mock, tt.query, tt.args...)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
				// Validate the call even if there was an error
				if tt.validateCall != nil {
					tt.validateCall(t, capturedQuery, capturedArgs)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery, capturedArgs)
			}
		})
	}
}

// TestSelectRecords_DifferentTypes tests SelectRecords with different generic types
func TestSelectRecords_DifferentTypes(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{
			name: "User type compiles and calls Query",
			test: func(t *testing.T) {
				queryCalled := false
				mock := &mockSelector{
					queryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
						queryCalled = true
						return nil, errors.New("test complete")
					},
				}
				// Call the function - it will error, but that's ok
				_, _ = SelectRecords[User](mock, "SELECT * FROM users")

				if !queryCalled {
					t.Error("expected Query to be called")
				}
			},
		},
		{
			name: "Product type compiles and calls Query",
			test: func(t *testing.T) {
				queryCalled := false
				mock := &mockSelector{
					queryFunc: func(query string, args ...interface{}) (*sql.Rows, error) {
						queryCalled = true
						return nil, errors.New("test complete")
					},
				}
				// Call the function - it will error, but that's ok
				_, _ = SelectRecords[Product](mock, "SELECT * FROM products")

				if !queryCalled {
					t.Error("expected Query to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestSelectOneRecord tests the SelectOneRecord generic function
func TestSelectOneRecord(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		args         []interface{}
		validateCall func(*testing.T, string, []interface{})
	}{
		{
			name:  "query and arguments are passed correctly",
			query: "SELECT * FROM users WHERE id = ?",
			args:  []interface{}{123},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if capturedQuery != "SELECT * FROM users WHERE id = ?" {
					t.Errorf("expected query %q, got %q", "SELECT * FROM users WHERE id = ?", capturedQuery)
				}
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(int) != 123 {
					t.Errorf("expected arg 123, got %v", capturedArgs[0])
				}
			},
		},
		{
			name:  "query with string argument",
			query: "SELECT * FROM users WHERE username = ?",
			args:  []interface{}{"alice"},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(string) != "alice" {
					t.Errorf("expected arg 'alice', got %v", capturedArgs[0])
				}
			},
		},
		{
			name:  "query with multiple arguments",
			query: "SELECT * FROM users WHERE active = ? AND id > ?",
			args:  []interface{}{true, 50},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 2 {
					t.Fatalf("expected 2 args, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(bool) != true {
					t.Errorf("expected first arg true, got %v", capturedArgs[0])
				}
				if capturedArgs[1].(int) != 50 {
					t.Errorf("expected second arg 50, got %v", capturedArgs[1])
				}
			},
		},
		{
			name:  "query with no arguments",
			query: "SELECT * FROM users LIMIT 1",
			args:  nil,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 0 {
					t.Errorf("expected 0 args, got %d", len(capturedArgs))
				}
			},
		},
		{
			name:  "query with float argument",
			query: "SELECT * FROM products WHERE price < ?",
			args:  []interface{}{99.99},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(float64) != 99.99 {
					t.Errorf("expected arg 99.99, got %v", capturedArgs[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			var capturedArgs []interface{}

			mock := &mockSelector{
				queryRowFunc: func(query string, args ...interface{}) *sql.Row {
					capturedQuery = query
					capturedArgs = args
					// Return nil - this will cause SelectOneRecord to panic when it tries to Scan
					return nil
				},
			}

			// Use defer recover to catch the panic from nil row
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Expected panic from nil row - this is fine
						// We've already captured what we need
					}
				}()
				_, _ = SelectOneRecord[User](mock, tt.query, tt.args...)
			}()

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery, capturedArgs)
			}
		})
	}
}

// TestSelectOneRecord_DifferentTypes tests SelectOneRecord with different generic types
func TestSelectOneRecord_DifferentTypes(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{
			name: "User type compiles and calls QueryRow",
			test: func(t *testing.T) {
				queryCalled := false
				mock := &mockSelector{
					queryRowFunc: func(query string, args ...interface{}) *sql.Row {
						queryCalled = true
						return nil
					},
				}

				// Use defer recover to catch the panic from nil row
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Expected panic from nil row - this is fine
						}
					}()
					_, _ = SelectOneRecord[User](mock, "SELECT * FROM users WHERE id = ?", 1)
				}()

				if !queryCalled {
					t.Error("expected QueryRow to be called")
				}
			},
		},
		{
			name: "Product type compiles and calls QueryRow",
			test: func(t *testing.T) {
				queryCalled := false
				mock := &mockSelector{
					queryRowFunc: func(query string, args ...interface{}) *sql.Row {
						queryCalled = true
						return nil
					},
				}

				// Use defer recover to catch the panic from nil row
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Expected panic from nil row - this is fine
						}
					}()
					_, _ = SelectOneRecord[Product](mock, "SELECT * FROM products WHERE id = ?", 1)
				}()

				if !queryCalled {
					t.Error("expected QueryRow to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

// TestSelectExists tests the SelectExists function
func TestSelectExists(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		args         []interface{}
		validateCall func(*testing.T, string, []interface{})
	}{
		{
			name:  "query and arguments are passed correctly",
			query: "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)",
			args:  []interface{}{"alice"},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				expectedQuery := "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)"
				if capturedQuery != expectedQuery {
					t.Errorf("expected query %q, got %q", expectedQuery, capturedQuery)
				}
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(string) != "alice" {
					t.Errorf("expected arg 'alice', got %v", capturedArgs[0])
				}
			},
		},
		{
			name:  "query with multiple arguments",
			query: "SELECT EXISTS(SELECT 1 FROM users WHERE active = ? AND id > ?)",
			args:  []interface{}{true, 100},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 2 {
					t.Fatalf("expected 2 args, got %d", len(capturedArgs))
				}
			},
		},
		{
			name:  "query with no arguments",
			query: "SELECT EXISTS(SELECT 1 FROM users)",
			args:  nil,
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 0 {
					t.Errorf("expected 0 args, got %d", len(capturedArgs))
				}
			},
		},
		{
			name:  "query with int argument",
			query: "SELECT EXISTS(SELECT 1 FROM products WHERE id = ?)",
			args:  []interface{}{999},
			validateCall: func(t *testing.T, capturedQuery string, capturedArgs []interface{}) {
				if len(capturedArgs) != 1 {
					t.Fatalf("expected 1 arg, got %d", len(capturedArgs))
				}
				if capturedArgs[0].(int) != 999 {
					t.Errorf("expected arg 999, got %v", capturedArgs[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			var capturedArgs []interface{}

			mock := &mockSelector{
				queryRowFunc: func(query string, args ...interface{}) *sql.Row {
					capturedQuery = query
					capturedArgs = args
					// Return nil - this will cause SelectExists to panic when it tries to Scan
					return nil
				},
			}

			// Use defer recover to catch the panic from nil row
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Expected panic from nil row - this is fine
						// We've already captured what we need
					}
				}()
				_, _ = SelectExists(mock, tt.query, tt.args...)
			}()

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery, capturedArgs)
			}
		})
	}
}

// TestInsertRecord tests the InsertRecord generic function
func TestInsertRecord(t *testing.T) {
	tests := []struct {
		name            string
		record          interface{}
		query           string
		mockPrepareFunc func(query string) (*sql.Stmt, error)
		expectError     bool
		validateError   func(*testing.T, error)
		validateCall    func(*testing.T, string)
	}{
		{
			name: "valid user struct",
			record: User{
				ID:       1,
				Username: "alice",
				Email:    "alice@example.com",
				Active:   true,
			},
			query: "INSERT INTO users (id, username, email, active) VALUES (?, ?, ?, ?)",
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true, // We return error from prepare to stop execution
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "INSERT INTO users (id, username, email, active) VALUES (?, ?, ?, ?)"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name: "valid product struct",
			record: Product{
				ID:    100,
				Name:  "Widget",
				Price: 29.99,
			},
			query: "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "INSERT INTO products (id, name, price) VALUES (?, ?, ?)"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:   "non-struct type is rejected",
			record: "not a struct",
			query:  "INSERT INTO users VALUES (?)",
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				t.Error("Prepare should not be called for non-struct")
				return nil, errors.New("should not reach here")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				expected := "insert record must be of type struct"
				if err.Error() != expected {
					t.Errorf("expected error %q, got %q", expected, err.Error())
				}
			},
		},
		{
			name: "prepare error is propagated",
			record: User{
				ID:       1,
				Username: "bob",
				Email:    "bob@example.com",
				Active:   false,
			},
			query: "INSERT INTO users VALUES (?, ?, ?, ?)",
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("prepare failed")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				if err.Error() != "prepare failed" {
					t.Errorf("expected 'prepare failed' error, got %q", err.Error())
				}
			},
		},
		{
			name:   "integer type is rejected",
			record: 42,
			query:  "INSERT INTO test VALUES (?)",
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				t.Error("Prepare should not be called for int")
				return nil, errors.New("should not reach here")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				expected := "insert record must be of type struct"
				if err.Error() != expected {
					t.Errorf("expected error %q, got %q", expected, err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string

			mock := &mockExecer{
				prepareFunc: func(query string) (*sql.Stmt, error) {
					capturedQuery = query
					return tt.mockPrepareFunc(query)
				},
			}

			var err error
			switch v := tt.record.(type) {
			case User:
				err = InsertRecord[User](mock, tt.query, v)
			case Product:
				err = InsertRecord[Product](mock, tt.query, v)
			case string:
				err = InsertRecord[string](mock, tt.query, v)
			case int:
				err = InsertRecord[int](mock, tt.query, v)
			}

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery)
			}
		})
	}
}

// TestUpdateRecord tests the UpdateRecord function
func TestUpdateRecord(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		args            []interface{}
		mockPrepareFunc func(query string) (*sql.Stmt, error)
		expectError     bool
		validateError   func(*testing.T, error)
		validateCall    func(*testing.T, string)
	}{
		{
			name:  "query is passed to prepare",
			query: "UPDATE users SET email = ? WHERE id = ?",
			args:  []interface{}{"new@example.com", 1},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "UPDATE users SET email = ? WHERE id = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "update with single argument",
			query: "UPDATE users SET active = ? WHERE username = ?",
			args:  []interface{}{false, "alice"},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "UPDATE users SET active = ? WHERE username = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "update with multiple set clauses",
			query: "UPDATE users SET email = ?, active = ? WHERE id = ?",
			args:  []interface{}{"updated@example.com", false, 123},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "UPDATE users SET email = ?, active = ? WHERE id = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "prepare error is wrapped",
			query: "UPDATE users SET field = ?",
			args:  []interface{}{"value"},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("database connection lost")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				expectedMsg := "failed to prepare update statement"
				if len(err.Error()) < len(expectedMsg) || err.Error()[:len(expectedMsg)] != expectedMsg {
					t.Errorf("expected error to start with %q, got %q", expectedMsg, err.Error())
				}
			},
		},
		{
			name:  "update with no WHERE clause",
			query: "UPDATE users SET active = ?",
			args:  []interface{}{true},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "UPDATE users SET active = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string

			mock := &mockExecer{
				prepareFunc: func(query string) (*sql.Stmt, error) {
					capturedQuery = query
					return tt.mockPrepareFunc(query)
				},
			}

			err := UpdateRecord(mock, tt.query, tt.args...)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery)
			}
		})
	}
}

// TestDeleteRecord tests the DeleteRecord function
func TestDeleteRecord(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		args            []interface{}
		mockPrepareFunc func(query string) (*sql.Stmt, error)
		expectError     bool
		validateError   func(*testing.T, error)
		validateCall    func(*testing.T, string)
	}{
		{
			name:  "query is passed to prepare",
			query: "DELETE FROM users WHERE id = ?",
			args:  []interface{}{1},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "DELETE FROM users WHERE id = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "delete with string argument",
			query: "DELETE FROM users WHERE username = ?",
			args:  []interface{}{"alice"},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "DELETE FROM users WHERE username = ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "delete with multiple conditions",
			query: "DELETE FROM users WHERE active = ? AND created_at < ?",
			args:  []interface{}{false, "2024-01-01"},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "DELETE FROM users WHERE active = ? AND created_at < ?"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
		{
			name:  "prepare error is wrapped",
			query: "DELETE FROM users WHERE id = ?",
			args:  []interface{}{1},
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("table locked")
			},
			expectError: true,
			validateError: func(t *testing.T, err error) {
				expectedMsg := "failed to prepare delete statement"
				if len(err.Error()) < len(expectedMsg) || err.Error()[:len(expectedMsg)] != expectedMsg {
					t.Errorf("expected error to start with %q, got %q", expectedMsg, err.Error())
				}
			},
		},
		{
			name:  "delete with no WHERE clause",
			query: "DELETE FROM users",
			args:  nil,
			mockPrepareFunc: func(query string) (*sql.Stmt, error) {
				return nil, errors.New("stopping after prepare")
			},
			expectError: true,
			validateCall: func(t *testing.T, capturedQuery string) {
				expected := "DELETE FROM users"
				if capturedQuery != expected {
					t.Errorf("expected query %q, got %q", expected, capturedQuery)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string

			mock := &mockExecer{
				prepareFunc: func(query string) (*sql.Stmt, error) {
					capturedQuery = query
					return tt.mockPrepareFunc(query)
				},
			}

			err := DeleteRecord(mock, tt.query, tt.args...)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.validateError != nil {
					tt.validateError(t, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tt.validateCall != nil {
				tt.validateCall(t, capturedQuery)
			}
		})
	}
}
