package types

import "github.com/tdeslauriers/carapace/pkg/jwt"

// s2s login service -> validates incoming login
type AuthService interface {
	// ValidateCredentials validates credentials provided by client, whether s2s or user
	ValidateCredentials(id, secret string) error

	// GetUserScopes gets scopes specific to a service for a given identifier
	GetUserScopes(uuid, service string) ([]Scope, error)

	// MintAuthzToken builds and signs a jwt token for a given subject and service
	MintAuthzToken(subject, service string) (*jwt.JwtToken, error) // assumes valid creds
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
