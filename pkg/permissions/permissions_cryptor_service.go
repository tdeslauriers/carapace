package permissions

import (
	"errors"
	"fmt"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// PermissionCryptor is an interface that defines methods for decrypting and encrypting permission records.
type PermissionCryptor interface {

	// DecryptPermission decrypts a permission record
	DecryptPermission(p PermissionRecord) (*PermissionRecord, error)

	// EncryptPermission encrypts sensitive fields in a permission record
	EncryptPermission(p *PermissionRecord) (*PermissionRecord, error)
}

// NewPermissionCryptor creates a new instance of PermissionCryptor and returns a pointer to the concrete implementation.
func NewPermissionCryptor(c data.Cryptor) PermissionCryptor {
	return &permissionCryptor{
		cryptor: c,
	}
}

var _ PermissionCryptor = (*permissionCryptor)(nil)

// permissionCryptor is the concrete implementation of the PermissionCryptor interface.
type permissionCryptor struct {
	cryptor data.Cryptor // cryptor is the cryptographic service used to encrypt and decrypt
}

// decryptPermission is a method that decrypts sensitive fields  and removes uncessary fields in the permission data model.
func (c *permissionCryptor) DecryptPermission(p PermissionRecord) (*PermissionRecord, error) {

	var (
		wg     sync.WaitGroup
		pmCh   = make(chan string, 1)
		nameCh = make(chan string, 1)
		descCh = make(chan string, 1)
		slugCh = make(chan string, 1)
		errCh  = make(chan error, 4)
	)

	wg.Add(4)
	go c.decrypt("permission", p.Permission, pmCh, errCh, &wg)
	go c.decrypt("name", p.Name, nameCh, errCh, &wg)
	go c.decrypt("description", p.Description, descCh, errCh, &wg)
	go c.decrypt("slug", p.Slug, slugCh, errCh, &wg)

	wg.Wait()
	close(pmCh)
	close(nameCh)
	close(descCh)
	close(slugCh)
	close(errCh)

	// check for errors during decryption
	if len(errCh) > 0 {
		var errs []error
		for e := range errCh {
			errs = append(errs, e)
		}
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
	}

	p.Permission = <-pmCh
	p.Name = <-nameCh
	p.Description = <-descCh
	p.Slug = <-slugCh
	p.SlugIndex = "" // clear slug index as it is not needed in the response

	return &p, nil
}

// decrypt is a helper method that decrypts a field and sends the result to the channel.
func (c *permissionCryptor) decrypt(fieldname, encrpyted string, fieldCh chan string, errCh chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// decrypt service data
	decrypted, err := c.cryptor.DecryptServiceData(encrpyted)
	if err != nil {
		errCh <- fmt.Errorf("failed to decrypt '%s' field: %v", fieldname, err)
	}

	fieldCh <- string(decrypted)
}

// encryptPermission  method that encrypts sensitive fields
// in the permission data model, preparing the record for storage in the database.
func (c *permissionCryptor) EncryptPermission(p *PermissionRecord) (*PermissionRecord, error) {

	var (
		wg     sync.WaitGroup
		pmCh   = make(chan string, 1)
		nameCh = make(chan string, 1)
		descCh = make(chan string, 1)
		slugCh = make(chan string, 1)
		errCh  = make(chan error, 4)
	)

	wg.Add(4)
	go c.encrypt("permission", p.Permission, pmCh, errCh, &wg)
	go c.encrypt("name", p.Name, nameCh, errCh, &wg)
	go c.encrypt("description", p.Description, descCh, errCh, &wg)
	go c.encrypt("slug", p.Slug, slugCh, errCh, &wg)

	wg.Wait()
	close(pmCh)
	close(nameCh)
	close(descCh)
	close(slugCh)
	close(errCh)

	// check for errors during encryption
	if len(errCh) > 0 {
		var errs []error
		for e := range errCh {
			errs = append(errs, e)
		}
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
	}

	encrypted := &PermissionRecord{
		Id:          p.Id,
		ServiceName: p.ServiceName,
		Permission:  <-pmCh,
		Name:        <-nameCh,
		Description: <-descCh,
		CreatedAt:   p.CreatedAt,
		Active:      p.Active,
		Slug:        <-slugCh,
		SlugIndex:   p.SlugIndex, // slug index is not encrypted, is hash
	}

	return encrypted, nil
}

// encrypt is a helper method that encrypts sensitive fields in the permission data model.
func (c *permissionCryptor) encrypt(field, plaintext string, fieldCh chan string, errCh chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// encrypt service data
	encrypted, err := c.cryptor.EncryptServiceData([]byte(plaintext))
	if err != nil {
		errCh <- fmt.Errorf("failed to encrypt '%s' field: %v", field, err)
		return
	}

	fieldCh <- string(encrypted)
}
