package provider

import "github.com/tdeslauriers/carapace/pkg/data"

// S2sCredentials is a struct for providing credentials to s2s token provider services during config/service setup
type S2sCredentials struct {
	ClientId     string
	ClientSecret string
}

// S2sAuthorization is a data model struct for service-to-service authorization data
// including the service token, refresh token, and expiration times
type S2sAuthorization struct {
	Jti            string          `json:"jti" db:"uuid"` // gen'd by s2s service at token creation
	ServiceName    string          `json:"service_name" db:"service_name"`
	ServiceToken   string          `json:"service_token" db:"service_token"`
	TokenExpires   data.CustomTime `json:"token_expires" db:"service_expires"`
	RefreshToken   string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
}

// UserAuthorization is the data model struct for user authorization data
// including the access token, id token, refresh tokens, and expiration times
type UserAuthorization struct {
	Jti                string          `json:"jti"` // no db tag because not stored in db: blind index
	AccessToken        string          `json:"access_token" db:"access_token"`
	TokenType          string          `json:"token_type" db:"token_type"`
	AccessTokenExpires data.CustomTime `json:"access_expires" db:"access_expires"`
	Refresh            string          `json:"refresh_token" db:"refresh_token"`
	RefreshExpires     data.CustomTime `json:"refresh_expires" db:"refresh_expires"`
	IdToken            string          `json:"id_token" db:"id_token"`
	IdTokenExpires     data.CustomTime `json:"id_expires" db:"id_expires"`
}
