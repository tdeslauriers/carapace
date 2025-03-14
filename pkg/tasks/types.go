package tasks

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Allowance is a struct that represents a user's allowance as it exists in the database.
// It can also be used for json, though the indexes will be omitted.
// Balance is counted in cents to avoid Superman 3 style errors.
type Allowance struct {
	Id           string          `json:"id,omitempty" db:"uuid"`
	Balance      int64           `json:"balance" db:"balance"`
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

	if a.Balance < 0 {
		return fmt.Errorf("invalid balance: must be greater than or equal to 0")
	}

	return nil
}

// UpdateAllowanceCmd is a struct that represents the command to update an allowance in the allownace service.
// It does not represent a data model in the database.
type UpdateAllowanceCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Credit       int64 `json:"credit"`
	Debit        int64 `json:"debit"`
	IsArchived   bool  `json:"is_archived"`
	IsActive     bool  `json:"is_active"`
	IsCalculated bool  `json:"is_calculated"`
}

// ValidateCmd validates the UpdateAllowanceCmd struct
// Note: it does not include any business logic validation, only data validation.
func (u *UpdateAllowanceCmd) ValidateCmd() error {
	if u.Csrf != "" {
		if !validate.IsValidUuid(u.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	if u.Credit < 0 {
		return fmt.Errorf("invalid credit: must be greater than or equal to 0")
	}

	if u.Credit > 10000 {
		return fmt.Errorf("invalid credit: must be less than or equal to 10,000, since that is ridiculous")
	}

	if u.Debit < 0 {
		return fmt.Errorf("invalid debit: must be greater than or equal to 0")
	}

	if u.Debit > 10000 {
		return fmt.Errorf("invalid debit: must be less than or equal to 10,000, since that is ridiculous")
	}

	// validation of boolean values is not necessary: business logic will determine if they are valid in service.
	return nil
}
