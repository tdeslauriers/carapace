package tasks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Allowance is a struct that represents a user's allowance as it exists in the database.
// It can also be used for json, though the indexes will be omitted.
// Balance is counted in cents to avoid Superman 3 style errors.
type Allowance struct {
	Id           string          `json:"id,omitempty" db:"uuid"`
	Balance      uint64          `json:"balance" db:"balance"`
	Username     string          `json:"username,omitempty" db:"username"`
	UserIndex    string          `json:"user_index,omitempty" db:"user_index"`
	Slug         string          `json:"slug,omitempty" db:"slug"`
	SlugIndex    string          `json:"slug_index,omitempty" db:"slug_index"`
	CreatedAt    data.CustomTime `json:"created_at" db:"created_at"`
	UpdatedAt    data.CustomTime `json:"updated_at" db:"updated_at"`
	IsArchived   bool            `json:"is_archived" db:"is_archived"`
	IsActive     bool            `json:"is_active" db:"is_active"`
	IsCalculated bool            `json:"is_calculated" db:"is_calculated"`
}

func (a *Allowance) ValidateCmd() error {
	if a.Id != "" && !validate.IsValidUuid(a.Id) {
		return fmt.Errorf("invalid or not well formatted allowance id")
	}

	if a.Username != "" {
		if len(a.Username) < validate.EmailMin || len(a.Username) > validate.EmailMax {
			return fmt.Errorf("invalid username: must be greater than %d and less than %d characters long", validate.EmailMin, validate.EmailMax)
		}

		if err := validate.IsValidEmail(a.Username); err != nil {
			return fmt.Errorf("invalid username: %v", err)
		}
	}

	if a.Slug != "" && !validate.IsValidUuid(a.Slug) {
		return fmt.Errorf("invalid or not well formatted slug")
	}

	return nil
}

// UpdateAllowanceCmd is a struct that represents the command to update an allowance in the allownace service.
// It does not represent a data model in the database.
type UpdateAllowanceCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Credit       uint64 `json:"credit"`
	Debit        uint64 `json:"debit"`
	IsArchived   bool   `json:"is_archived"`
	IsActive     bool   `json:"is_active"`
	IsCalculated bool   `json:"is_calculated"`
}

// ValidateCmd validates the UpdateAllowanceCmd struct
// Note: it does not include any business logic validation, only data validation.
func (u *UpdateAllowanceCmd) ValidateCmd() error {
	if u.Csrf != "" {
		if !validate.IsValidUuid(u.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	if u.Credit > 1000000 {
		return fmt.Errorf("invalid credit: must be less than or equal to $10,000, since that is ridiculous")
	}

	if u.Debit > 1000000 {
		return fmt.Errorf("invalid debit: must be less than or equal to $10,000, since that is ridiculous")
	}

	// validation of boolean values is not necessary: business logic will determine if they are valid in service.
	return nil
}

// cadence is a type that represents the cadence of a task template's recurrence.
type Cadence string

// possible cadence values => for unmarrshalling json validation
const (
	Adhoc     Cadence = "ADHOC"
	Daily     Cadence = "DAILY"
	Weekly    Cadence = "WEEKLY"
	Monthly   Cadence = "MONTHLY"
	Quarterly Cadence = "QUARTERLY"
	Anually   Cadence = "ANNUALLY"
)

// customr unmarshaler for cadence type so that it errors on invalid values
func (c *Cadence) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case string(Adhoc), string(Daily), string(Weekly), string(Monthly), string(Quarterly), string(Anually):
		*c = Cadence(s)
		return nil
	default:
		return fmt.Errorf("invalid cadence: %q", s)
	}
}

// IsValidCadence checks if a cadence is valid
// redundant if the custom unmarshaler is used on a json payload, but that isnt guaranteed.
func (c *Cadence) IsValidCadence() error {
	switch *c {
	case Adhoc, Daily, Weekly, Monthly, Quarterly, Anually:
		return nil
	default:
		return fmt.Errorf("invalid cadence: %q", *c)
	}
}

// Category is a type that represents the category of a task template, such as "work" or "home".
type Category string

const (
	Bills  Category = "BILLS"
	Car    Category = "CAR"
	Dev    Category = "DEV"
	Health Category = "HEALTH"
	House  Category = "HOUSE"
	Kids   Category = "KIDS"
	Pets   Category = "PETS"
	Sports Category = "SPORTS"
	Study  Category = "STUDY"
	Work   Category = "WORK"
	Yard   Category = "YARD"
	Other  Category = "OTHER"
)

// UnmarshalJSON is a custom unmarshaler for the Category type so that it errors on invalid values.
func (c *Category) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case string(Bills), string(Car), string(Dev), string(Health), string(House), string(Kids),
		string(Pets), string(Sports), string(Study), string(Work), string(Yard), string(Other):
		*c = Category(s)
		return nil
	default:
		return fmt.Errorf("invalid category: %q", s)
	}
}

// IsValidCategory checks if a category is valid
// redundant if the custom unmarshaler is used on a json payload, but that isnt guaranteed.
func (c *Category) IsValidCategory() error {
	switch *c {
	case Bills, Car, Dev, Health, House, Kids, Pets, Sports, Study, Work, Yard, Other:
		return nil
	default:
		return fmt.Errorf("invalid category: %q", *c)
	}
}

// TaskTemplate is a struct for a json model meant to update/insert task templates.
// It is not a database model and is a subset of the db record fields.
type TemplateCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Name        string   `json:"name"`
	Description string   `json:"description"`
	Cadence     Cadence  `json:"cadence"`
	Category    Category `json:"category"`
	IsArchived  bool     `json:"is_archived"`

	Assignees []string `json:"assignees"` // email addresses/usernames
}

// ValidateCmd validates the TemplateCmd struct
// Note: it does not include any business logic validation, only data validation.
func (t *TemplateCmd) ValidateCmd() error {

	// csrf
	if t.Csrf != "" {
		if !validate.IsValidUuid(t.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	// name
	if len(strings.TrimSpace(t.Name)) < 2 || len(strings.TrimSpace(t.Name)) > 64 {
		return fmt.Errorf("name is a required field and must be between 2 and 64 characters in length")
	}

	// description
	if len(strings.TrimSpace(t.Description)) < 2 || len(strings.TrimSpace(t.Description)) > 255 {
		return fmt.Errorf("description is a required field and must be between 2 and 255 characters in length")
	}

	// cadence
	if len(t.Cadence) == 0 {
		return fmt.Errorf("cadence is a required field")
	}

	if err := t.Cadence.IsValidCadence(); err != nil {
		return err
	}

	// category
	if len(t.Category) == 0 {
		return fmt.Errorf("category is a required field")
	}

	if err := t.Category.IsValidCategory(); err != nil {
		return err
	}

	// assignees
	if len(t.Assignees) == 0 {
		return fmt.Errorf("assignees is a required field")
	}

	for _, a := range t.Assignees {
		if err := validate.IsValidEmail(a); err != nil {
			return fmt.Errorf("invalid assignee: %v", err)
		}
	}

	return nil
}

// Template is a struct that represents a task template as in json
// not it includes a slice of assignees, which is not in the db model.
type Template struct {
	Id          string          `json:"id,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Cadence     Cadence         `json:"cadence"`
	Category    Category        `json:"category"`
	Slug        string          `json:"slug,omitempty"`
	CreatedAt   data.CustomTime `json:"created_at"`
	IsArchived  bool            `json:"is_archived"`
	Assignees   []profile.User     `json:"assignees"`
}
