package tasks

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

type Allowance struct {
	Id           string          `json:"id,omitempty" db:"uuid"`
	Balance      float64         `json:"balance" db:"balance"`
	Username     string          `json:"username,omitempty" db:"username"`
	UserIndex    string          `json:"user_index,omitempty" db:"user_index"`
	Slug         string          `json:"slug,omitempty" db:"slug"`
	SlugIndex    string          `json:"slug_index,omitempty" db:"slug_index"`
	CreatedAt    data.CustomTime `json:"created_at" db:"created_at"`
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

	if a.Balance < 0 {
		return fmt.Errorf("invalid balance: must be greater than or equal to 0")
	}

	return nil
}
