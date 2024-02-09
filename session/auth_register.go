package session

import (
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/data"
	"github.com/tdeslauriers/carapace/validate"
	"golang.org/x/crypto/bcrypt"
)

type RegistrationService interface {
	Register(RegisterCmd) error
}

type RegisterCmd struct {
	Username  string `json:"username"` // email address
	Password  string `json:"password"`
	Confirm   string `json:"confirm_password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Birthdate string `json:"bithdate,omitempty"`
}

type MariaAuthRegistrationService struct {
	Dao    data.SqlRepository
	Cipher data.Cryptor
	Indexer data.Indexer
}

func NewAuthRegistrationService(sql data.SqlRepository, ciph data.Cryptor, i data.Indexer) *MariaAuthRegistrationService {
	return &MariaAuthRegistrationService{
		Dao:    sql,
		Cipher: ciph,
		Indexer: i,
	}
}

func (r *MariaAuthRegistrationService) Register(cmd RegisterCmd) error {

	// input validation
	if err := validate.ValidateEmail(cmd.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if err := validate.ValidateName(cmd.Firstname); err != nil {
		return fmt.Errorf("invalid firstname: %v", err)
	}

	if err := validate.ValidateName(cmd.Lastname); err != nil {
		return fmt.Errorf("invalid lastname: %v", err)
	}

	if err := validate.ValidateBirthday(cmd.Birthdate); err != nil {
		return fmt.Errorf("invalid birthday: %v", err)
	}

	if cmd.Password != cmd.Confirm {
		return errors.New("password does not match confirm password")
	}

	if err := validate.ValidatePassword(cmd.Password); err != nil {
		return fmt.Errorf("invalid password: %v", err)
	}

	// create user record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Panicf("unable to create uuid for user registration request: %v", err)
	}

	username, err := r.Cipher.EncyptServiceData(cmd.Username)
	if err != nil {
		log.Panic("unable to field level encrypt user registration username/email: %v", err)
	}

	// create blind index
	index, err := r.Indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		log.Panic("unable to create username blind index: %v", err)
	}

	// bcrypt hash password
	password := bcrypt.

	first, err := r.Cipher.EncyptServiceData(cmd.Firstname)
	if err != nil {
		log.Panic("unable to field level encrypt user registration firstname: %v", err)
	}

	user := AuthAccountData{
		Uuid: id.String(),
		Username: username,
		UserIndex: index,
		Password: ,
		Firstname: first,
	}



	// insert into database

	return nil
}
