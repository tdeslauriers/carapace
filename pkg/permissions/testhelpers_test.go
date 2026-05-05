package permissions

import (
	"database/sql"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// mockCryptor implements data.Cryptor for testing.
type mockCryptor struct {
	encryptFunc func([]byte) (string, error)
	decryptFunc func(string) ([]byte, error)
}

func (m *mockCryptor) EncryptServiceData(d []byte) (string, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(d)
	}
	return string(d), nil
}

func (m *mockCryptor) DecryptServiceData(ciphertext string) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ciphertext)
	}
	return []byte(ciphertext), nil
}

func (m *mockCryptor) EncryptField(_, _ string, ch chan string, _ chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	ch <- ""
}

func (m *mockCryptor) DecryptField(_, _ string, ch chan string, _ chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	ch <- ""
}

var _ data.Cryptor = (*mockCryptor)(nil)

// mockIndexer implements data.Indexer for testing.
type mockIndexer struct {
	indexFunc func(string) (string, error)
}

func (m *mockIndexer) ObtainBlindIndex(input string) (string, error) {
	if m.indexFunc != nil {
		return m.indexFunc(input)
	}
	return "idx-" + input, nil
}

var _ data.Indexer = (*mockIndexer)(nil)

// mockRepo implements PermissionsRepository for testing.
type mockRepo struct {
	findAllFunc         func() ([]PermissionRecord, error)
	findBySlugIndexFunc func(string) (*PermissionRecord, error)
	insertFunc          func(PermissionRecord) error
	updateFunc          func(PermissionRecord) error
}

func (m *mockRepo) FindAll() ([]PermissionRecord, error) {
	if m.findAllFunc != nil {
		return m.findAllFunc()
	}
	return nil, nil
}

func (m *mockRepo) FindBySlugIndex(index string) (*PermissionRecord, error) {
	if m.findBySlugIndexFunc != nil {
		return m.findBySlugIndexFunc(index)
	}
	return nil, nil
}

func (m *mockRepo) InsertPermission(p PermissionRecord) error {
	if m.insertFunc != nil {
		return m.insertFunc(p)
	}
	return nil
}

func (m *mockRepo) UpdatePermission(p PermissionRecord) error {
	if m.updateFunc != nil {
		return m.updateFunc(p)
	}
	return nil
}

var _ PermissionsRepository = (*mockRepo)(nil)

// mockPermCryptor implements PermissionCryptor for testing.
type mockPermCryptor struct {
	decryptFunc func(PermissionRecord) (*PermissionRecord, error)
	encryptFunc func(*PermissionRecord) (*PermissionRecord, error)
}

func (m *mockPermCryptor) DecryptPermission(p PermissionRecord) (*PermissionRecord, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(p)
	}
	return &p, nil
}

func (m *mockPermCryptor) EncryptPermission(p *PermissionRecord) (*PermissionRecord, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(p)
	}
	return p, nil
}

var _ PermissionCryptor = (*mockPermCryptor)(nil)

// mockSqlDB implements the sqlDB interface for testing.
type mockSqlDB struct {
	queryFunc    func(string, ...interface{}) (*sql.Rows, error)
	queryRowFunc func(string, ...interface{}) *sql.Row
	execFunc     func(string, ...interface{}) (sql.Result, error)
	prepareFunc  func(string) (*sql.Stmt, error)
}

func (m *mockSqlDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	if m.queryFunc != nil {
		return m.queryFunc(query, args...)
	}
	return nil, nil
}

func (m *mockSqlDB) QueryRow(query string, args ...interface{}) *sql.Row {
	if m.queryRowFunc != nil {
		return m.queryRowFunc(query, args...)
	}
	return nil
}

func (m *mockSqlDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	if m.execFunc != nil {
		return m.execFunc(query, args...)
	}
	return nil, nil
}

func (m *mockSqlDB) Prepare(query string) (*sql.Stmt, error) {
	if m.prepareFunc != nil {
		return m.prepareFunc(query)
	}
	return nil, nil
}

var _ sqlDB = (*mockSqlDB)(nil)

// mockSqlResult implements sql.Result for testing.
type mockSqlResult struct{}

func (m *mockSqlResult) LastInsertId() (int64, error) { return 0, nil }
func (m *mockSqlResult) RowsAffected() (int64, error) { return 1, nil }
