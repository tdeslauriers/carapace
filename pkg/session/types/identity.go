package types

import (
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// IdentityClient is a struct for identity client data, NOT the same as S2S client data:
// ie, https://deslauriers.com instead of the s2s shaw service
type IdentityClient struct {
	Uuid          string          `db:"uuid" json:"uuid"`
	ClientId      string          `db:"client_id" json:"client_id"`
	ClientName    string          `db:"client_name" json:"client_name"`
	Description   string          `db:"description" json:"description"`
	CreatedAt     data.CustomTime `db:"created_at" json:"created_at"`
	Enabled       bool            `db:"enabled" json:"enabled"`
	ClientExpired bool            `db:"client_expired" json:"client_expired"`
	ClientLocked  bool            `db:"client_locked" json:"client_locked"`
}

// UserAccountClientXref is a model struct xref table joining user accounts and identity clients tables.
type UserAccountClientXref struct {
	Id        int    `db:"id" json:"id"`
	AccountId string `db:"account_uuid" json:"account_uuid"`
	ClientId  string `db:"client_uuid" json:"client_uuid"`
	CreatedAt string `db:"created_at" json:"created_at"`
}

// UserAccount is a model struct for user account table data.
type UserAccount struct {
	Uuid           string `db:"uuid" json:"uuid,omitempty"`
	Username       string `db:"username" json:"username"`
	UserIndex      string `db:"user_index" json:"user_index,omitempty"`
	Password       string `db:"password" json:"password,omitempty"`
	Firstname      string `db:"firstname" json:"firstname"`
	Lastname       string `db:"lastname" json:"lastname"`
	Birthdate      string `db:"birth_date" json:"birth_date,omitempty"` // string because field encrypted in db
	Slug           string `db:"slug" json:"slug,omitempty"`
	SlugIndex      string `db:"slug_index" json:"slug_index,omitempty"`
	CreatedAt      string `db:"created_at" json:"created_at"`
	Enabled        bool   `db:"enabled"  json:"enabled,omitempty"`
	AccountExpired bool   `db:"acccount_expired" json:"account_expired,omitempty"`
	AccountLocked  bool   `db:"account_locked" json:"account_locked,omitempty"`
}

// Scope is a model for the scope table data, NOT jwt string object in the jwt package.
type Scope struct {
	Uuid        string `db:"uuid" json:"scope_id"`
	ServiceName string `db:"service_name" json:"service_name"`
	Scope       string `db:"scope" json:"scope"`
	Name        string `db:"name"  json:"name"`
	Description string `db:"description" json:"description"`
	CreatedAt   string `db:"created_at" json:"created_at"`
	Active      bool   `db:"active" json:"active"`
}

// AccountScopeXref is a model struct xref table joining user accounts and scopes tables.
type AccountScopeXref struct {
	Id          int    `db:"id" json:"id"`
	AccountUuid string `db:"account_uuid" json:"account_uuid"`
	ScopeUuid   string `db:"scope_uuid" json:"scope_uuid"`
	CreatedAt   string `db:"created_at" json:"created_at"`
}

// BuildAudiences is a helper func to build audience []string from a string of space-delimited scope string values, eg., "w:service:* r:service:*"
// Note: it is included in this package because it refers directly to the Scope struct in this package.
func BuildAudiences(scopes string) (audiences []string) {

	var services []string

	// split scopes by space
	scps := strings.Split(scopes, " ")

	// iterate over each scope and split by : to get the service name
	for _, scope := range scps {
		chunk := strings.Split(scope, ":") // splits scope by : -> w:service:*
		services = append(services, chunk[1])
	}

	// build unique (no duplicates) list of services
	uniqueServices := make(map[string]struct{}, 0) // ie, one of each value
	for _, service := range services {
		if _, ok := uniqueServices[service]; !ok {
			uniqueServices[service] = struct{}{}
			audiences = append(audiences, service)
		}
	}

	return audiences
}
