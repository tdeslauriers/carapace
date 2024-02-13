package session

import (
	"errors"
	"fmt"
	"log"
	"time"

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
	Dao     data.SqlRepository
	Cipher  data.Cryptor
	Indexer data.Indexer
	S2s     S2STokenProvider
}

func NewAuthRegistrationService(sql data.SqlRepository, ciph data.Cryptor, i data.Indexer, s2s S2STokenProvider) *MariaAuthRegistrationService {
	return &MariaAuthRegistrationService{
		Dao:     sql,
		Cipher:  ciph,
		Indexer: i,
		S2s:     s2s,
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

	// create blind index
	index, err := r.Indexer.ObtainBlindIndex(cmd.Username)
	if err != nil {
		log.Printf("unable to create username blind index: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	// check user does not already exist
	query := "SELECT EXISTS(SELECT 1 from account WHERE user_index = ?) AS record_exists"
	exists, err := r.Dao.SelectExists(query, index)
	if err != nil {
		log.Printf("unable to check if user exists: %v", err)
		return fmt.Errorf("unable to create user record")
	}
	if exists {
		return fmt.Errorf("username unavailable")
	}

	// build user record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Printf("unable to create uuid for user registration request: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	username, err := r.Cipher.EncyptServiceData(cmd.Username)
	if err != nil {
		log.Printf("unable to field level encrypt user registration username/email: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	// bcrypt hash password
	password, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), 13)
	if err != nil {
		log.Printf("unable to generate bcrypt password hash: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	first, err := r.Cipher.EncyptServiceData(cmd.Firstname)
	if err != nil {
		log.Printf("unable to field level encrypt user registration firstname: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	last, err := r.Cipher.EncyptServiceData(cmd.Lastname)
	if err != nil {
		log.Printf("unable to field level encrypt user registration lastname: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	dob, err := r.Cipher.EncyptServiceData(cmd.Birthdate)
	if err != nil {
		log.Printf("unable to field level encrypt user registration dob: %v", err)
		return fmt.Errorf("unable to create user record")
	}

	createdAt := time.Now()

	user := AuthAccountData{
		Uuid:           id.String(),
		Username:       username,
		UserIndex:      index,
		Password:       string(password),
		Firstname:      first,
		Lastname:       last,
		Birthdate:      dob,
		CreatedAt:      createdAt.Format("2006-01-02 15:04:05"),
		Enabled:        true, // this will change to false when email verification built
		AccountExpired: false,
		AccountLocked:  false,
	}

	// insert user into database
	query = "INSERT INTO account (uuid, username, user_index, password, firstname, lastname, birth_date, created_at, enabled, account_expired, account_locked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	if err := r.Dao.InsertRecord(query, user); err != nil {
		log.Printf("unable to enter registeration record into account table in db: %v", err)
		return fmt.Errorf("unable to perst user registration to db")
	}

	// add profile service scopes r, w
	// get token
	r.S2s.GetServiceToken()
	
	

	return nil
}
