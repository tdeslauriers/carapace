package types

import "github.com/tdeslauriers/carapace/pkg/jwt"

// AuthService is an interface for authentication services that validates credentials, gets user scopes, and mints authorization tokens
type AuthService interface {
	// ValidateCredentials validates credentials provided by client, whether s2s or user
	ValidateCredentials(id, secret string) error

	// GetScopes gets scopes specific to a service for a given identifier.
	// 'user' parameter can be a username or a client id.
	GetScopes(user, service string) ([]Scope, error)

	// MintToken builds and signs a jwt token for a given subject, and scopes.
	// It does not validate or perform checks on these values, it assumes they are valid.
	// 'scopes' parameter is a space-delimited string of scopes, not a slice of Scope objects.
	MintToken(subject, scopes string) (*jwt.Token, error)
}

// UserAuthService is an interface for user authentication services
// and contains the AuthService interface and the RefreshService interface
type UserAuthService interface {
	AuthService
	RefreshService[UserRefresh]
}

// S2sAuthService is an interface for service-to-service authentication services
// and contains the AuthService interface and the RefreshService interface
type S2sAuthService interface {
	AuthService
	RefreshService[S2sRefresh]
}
