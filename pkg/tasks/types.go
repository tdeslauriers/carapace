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

	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Cadence      Cadence  `json:"cadence"`
	Category     Category `json:"category"`
	IsCalculated bool     `json:"is_calculated"`
	IsArchived   bool     `json:"is_archived"`

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
	Id           string          `json:"id,omitempty"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Cadence      Cadence         `json:"cadence"`
	Category     Category        `json:"category"`
	IsCalculated bool            `json:"is_calculated"`
	Slug         string          `json:"slug,omitempty"`
	CreatedAt    data.CustomTime `json:"created_at"`
	IsArchived   bool            `json:"is_archived"`
	Assignees    []profile.User  `json:"assignees"`
}

// Task is a model that represents a task as in json
// It is a composite object of fields from task and task template models.
// It also includes a slice of assignees.
type Task struct {
	Id             string          `json:"id,omitempty"`    // Tasks record uuid
	Name           string          `json:"name"`            // Task template name
	Description    string          `json:"description"`     // Task template description
	Cadence        Cadence         `json:"cadence"`         // Task template cadence
	Category       Category        `json:"category"`        // Task template category
	CreatedAt      data.CustomTime `json:"created_at"`      // Task record created at
	IsComplete     bool            `json:"is_complete"`     // Task record field
	IsSatisfactory bool            `json:"is_satisfactory"` // Task record field
	IsProactive    bool            `json:"is_proactive"`    // Task record field
	Slug           string          `json:"slug,omitempty"`  // Task record slug
	IsArchived     bool            `json:"is_archived"`     // Task record field
	Assignees      profile.User    `json:"assignees"`       // Task assignee via xref (only one person per task record)
}

// TaskRecord

// TaskQueryParams is a map of keys that represents the allowed query parameters for a task template.
var TaskQueryParams map[string]struct{} = map[string]struct{}{
	"view":            {},
	"assignee":        {},
	"name":            {},
	"cadence":         {},
	"category":        {},
	"is_complete":     {},
	"is_satisfactory": {},
	"is_proactive":    {},
	"is_archived":     {},
}

// TaskViews is a map of keys that represents the allowed views for a task template.
var TaskViews map[string]struct{} = map[string]struct{}{
	"today": {},
}

// AssigneeCodes is map of keys that represents the allowed assignee shorthand for a task template.
// Note: assignee can also be a username or a user slug (for the allowance table).
var AssigneeCodes map[string]struct{} = map[string]struct{}{
	"me":  {},
	"all": {},
}

// ValidateQueryParams is a function that validates the query parameters for a task template.
// It is used to validate the query parameters passed in the request.
func ValidateQueryParams(params map[string][]string) error {

	// check if params exist: redundant check, but it is a good practice
	if len(params) == 0 {
		return fmt.Errorf("no query parameters provided")
	}

	// check if params are valid
	for k := range params {
		if _, ok := TaskQueryParams[k]; !ok {
			return fmt.Errorf("invalid query parameter: %s", k)
		}
	}

	// check if view exists, and if so, is it valid
	if view, ok := params["view"]; ok {

		// check if view is empty
		if len(view) <= 0 {
			return fmt.Errorf("view parameter is not allowed to be empty if submitted")
		}

		// check if slice has more than one value
		if len(view) > 1 {
			return fmt.Errorf("view parameter must be a single value")
		}

		// dont need to split the values to check for multiple values because
		// no views will ever have commas in them, so it will fail the key check below anyway.

		// check if view is valid
		if _, ok := TaskViews[strings.TrimSpace(strings.ToLower(view[0]))]; !ok {
			return fmt.Errorf("invalid view parameter: %s", view)
		}
	}

	// check if assignee exists, and if so, is it valid
	if assignee, ok := params["assignee"]; ok {

		// loop the values, and seperate any multiple values into single values
		var assigneeList []string
		for _, a := range assignee {
			assigneeList = append(assigneeList, strings.TrimSpace(strings.ToLower(a)))
		}

		for _, a := range assigneeList {
			// check if assignee is empty
			if len(a) <= 0 {
				return fmt.Errorf("assignee parameter is not allowed to be empty if submitted")
			}

			// check if assignee is valid
			_, ok := AssigneeCodes[a]
			emailErr := validate.IsValidEmail(a)
			if !ok && emailErr != nil && !validate.IsValidUuid(a) {
				return fmt.Errorf("invalid assignee parameter: %s", a)
			}
		}
	}

	// check if name exists, and if so, is it valid
	if name, ok := params["name"]; ok {
		// check if name is empty
		if len(name) <= 0 {
			return fmt.Errorf("name parameter is not allowed to be empty if submitted")
		}

		if len(name) > 1 {

			// seperate any multiple values into single values
			var nameList []string
			for _, n := range name {
				nameList = append(nameList, strings.TrimSpace(strings.ToLower(n)))
			}
			// check if name is valid
			for _, n := range nameList {
				if len(n) < 2 || len(n) > 64 {
					return fmt.Errorf("name parameter must be between 2 and 64 characters in length")
				}

				if err := validate.IsValidName(n); err != nil {
					return fmt.Errorf("invalid name parameter: %v", err)
				}
			}
		}
	}

	// check if cadence exists, and if so, is it valid
	if cadence, ok := params["cadence"]; ok {
		// check if cadence is empty
		if len(cadence) <= 0 {
			return fmt.Errorf("cadence parameter is not allowed to be empty if submitted")
		}

		// artificially declare cadence param(s) a Cadence type to use Cadence.IsValidCadence()
		for _, c := range cadence {
			test := Cadence(strings.TrimSpace(strings.ToUpper(c)))
			if (&test).IsValidCadence() != nil {
				return fmt.Errorf("invalid cadence parameter: %s", c)
			}
		}
	}

	// check if category exists, and if so, is it valid
	if category, ok := params["category"]; ok {
		// check if category is empty
		if len(category) <= 0 {
			return fmt.Errorf("category parameter is not allowed to be empty if submitted")
		}

		// artificially declare category param(s) a Category type to use Category.IsValidCategory()
		for _, c := range category {
			test := Category(strings.TrimSpace(strings.ToUpper(c)))
			if (&test).IsValidCategory() != nil {
				return fmt.Errorf("invalid category parameter: %s", c)
			}
		}
	}

	// check if is_complete exists, and if so, is it valid
	if isComplete, ok := params["is_complete"]; ok {
		// check if is_complete is empty
		if len(isComplete) <= 0 {
			return fmt.Errorf("is_complete parameter is not allowed to be empty if submitted")
		}

		// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
		if len(isComplete) > 1 {
			return fmt.Errorf("is_complete parameter must be a single value")
		}
		// check if is_complete is a boolean
		isComplete[0] = strings.TrimSpace(strings.ToLower(isComplete[0]))
		if isComplete[0] != "true" && isComplete[0] != "false" {
			return fmt.Errorf("invalid is_complete parameter: %s", isComplete[0])
		}
	}

	// check if is_satisfactory exists, and if so, is it valid
	if isSatisfactory, ok := params["is_satisfactory"]; ok {
		// check if is_satisfactory is empty
		if len(isSatisfactory) <= 0 {
			return fmt.Errorf("is_satisfactory parameter is not allowed to be empty if submitted")
		}

		// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
		if len(isSatisfactory) > 1 {
			return fmt.Errorf("is_satisfactory parameter must be a single value")
		}
		// check if is_satisfactory is a boolean
		isSatisfactory[0] = strings.TrimSpace(strings.ToLower(isSatisfactory[0]))
		if isSatisfactory[0] != "true" && isSatisfactory[0] != "false" {
			return fmt.Errorf("invalid is_satisfactory parameter: %s", isSatisfactory[0])
		}
	}

	// check if is_proactive exists, and if so, is it valid
	if isProactive, ok := params["is_proactive"]; ok {
		// check if is_proactive is empty
		if len(isProactive) <= 0 {
			return fmt.Errorf("is_proactive parameter is not allowed to be empty if submitted")
		}

		// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
		if len(isProactive) > 1 {
			return fmt.Errorf("is_proactive parameter must be a single value")
		}
		// check if is_proactive is a boolean
		isProactive[0] = strings.TrimSpace(strings.ToLower(isProactive[0]))
		if isProactive[0] != "true" && isProactive[0] != "false" {
			return fmt.Errorf("invalid is_proactive parameter: %s", isProactive[0])
		}
	}

	// check if is_archived exists, and if so, is it valid
	if isArchived, ok := params["is_archived"]; ok {
		// check if is_archived is empty
		if len(isArchived) <= 0 {
			return fmt.Errorf("is_archived parameter is not allowed to be empty if submitted")
		}

		// cannot be more than one value because that is the same as "all", or "any" ==> unnecessary param
		if len(isArchived) > 1 {
			return fmt.Errorf("is_archived parameter must be a single value")
		}
		// check if is_archived is a boolean
		isArchived[0] = strings.TrimSpace(strings.ToLower(isArchived[0]))
		if isArchived[0] != "true" && isArchived[0] != "false" {
			return fmt.Errorf("invalid is_archived parameter: %s", isArchived[0])
		}
	}

	return nil
}
