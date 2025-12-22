package types

// // UserRegisterCmd is a struct to hold incoming user registration values to a /register endpoint.
// type UserRegisterCmd struct {
// 	Username  string `json:"username"` // email address
// 	Password  string `json:"password,omitempty"`
// 	Confirm   string `json:"confirm_password,omitempty"`
// 	Firstname string `json:"firstname"`
// 	Lastname  string `json:"lastname"`

// 	// Birthdate is an optional user input field,
// 	// as such, it is not included in field level validation.
// 	// Note: It is required by certain services:
// 	// TODO: build service functionality to add when required.
// 	Birthdate string `json:"birthdate,omitempty"`

// 	// ClientId is not consumed by all endpoints in all use cases,
// 	// as such, it is not included in field level validation.
// 	ClientId string `json:"client_id,omitempty"`

// 	// Session is not consumed by all endpoints in all use cases,
// 	// as such, it is not included in field level validation.
// 	Session string `json:"session,omitempty"`

// 	// Csrf is not consumed by all endpoints in all use cases,
// 	// as such, it is not included in field level validation.
// 	Csrf string `json:"csrf,omitempty"`
// }

// // ValidateCmd performs regex checks on user register cmd fields.
// // Note: ClientId, Session, Csrf, and Birthdate are not validated here
// // because they are not required fields in all use cases.
// func (cmd *UserRegisterCmd) ValidateCmd() error {

// 	if err := validate.IsValidEmail(cmd.Username); err != nil {
// 		return fmt.Errorf("invalid username: %v", err)
// 	}

// 	if err := validate.IsValidName(cmd.Firstname); err != nil {
// 		return fmt.Errorf("invalid firstname: %v", err)
// 	}

// 	if err := validate.IsValidName(cmd.Lastname); err != nil {
// 		return fmt.Errorf("invalid lastname: %v", err)
// 	}

// 	if err := validate.IsValidBirthday(cmd.Birthdate); err != nil {
// 		return fmt.Errorf("invalid birthdate: %v", err)
// 	}

// 	if cmd.Password != cmd.Confirm {
// 		return errors.New("password does not match confirm password")
// 	}

// 	if err := validate.IsValidPassword(cmd.Password); err != nil {
// 		return fmt.Errorf("invalid password: %v", err)
// 	}

// 	return nil
// }

// type S2sRegisterCmd struct {
// 	Uuid           string `db:"uuid" json:"client_id,omitempty"`
// 	Password       string `db:"password" json:"client_secret,omitempty"`
// 	Confirm        string `json:"confirm_password,omitempty"`
// 	Name           string `db:"name" json:"name"`
// 	Owner          string `db:"owner" json:"owner"`
// 	CreatedAt      string `db:"created_at" json:"created_at,omitempty"`
// 	Enabled        bool   `db:"enabled"  json:"enabled"`
// 	AccountExpired bool   `db:"acccount_expired" json:"account_expired"`
// 	AccountLocked  bool   `db:"account_locked" json:"account_locked"`
// 	Slug           string `db:"slug" json:"slug,omitempty"`
// }

// func (cmd *S2sRegisterCmd) ValidateCmd() error {

// 	if cmd.Uuid != "" && !validate.IsValidUuid(cmd.Uuid) {
// 		return fmt.Errorf("invalid or not well formatted client id")
// 	}

// 	if valid, err := validate.IsValidServiceName(cmd.Name); !valid {
// 		return fmt.Errorf("invalid client name: %v", err)
// 	}

// 	if err := validate.IsValidName(cmd.Owner); err != nil {
// 		return fmt.Errorf("invalid client owner: %v", err)
// 	}

// 	if cmd.Slug != "" && !validate.IsValidUuid(cmd.Slug) {
// 		return fmt.Errorf("invalid or not well formatted client slug")
// 	}

// 	if err := validate.IsValidPassword(cmd.Password); err != nil {
// 		return fmt.Errorf("invalid client password: %v", err)
// 	}

// 	if cmd.Password != cmd.Confirm {
// 		return errors.New("password does not match confirm password")
// 	}

// 	return nil
// }
