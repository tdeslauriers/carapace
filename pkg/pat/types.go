package pat

import "fmt"

// IntrospectCmd is a model used as a command to submit a PAT token for introspection
type IntrospectCmd struct {
	Token string `json:"token"`
}

// Validate checks if the introspect command is valid/well-formed
// It is a sanity check of the token length only.
func (cmd *IntrospectCmd) Validate() error {

	// quick sanity check of token length
	if len(cmd.Token) < 64 || len(cmd.Token) > 128 {
		return fmt.Errorf("invalid pat token length")
	}

	return nil
}

// IntrospectResponse is a model used as a response from a PAT token introspection
// it will contain a string slice of scopes associated with the PAT token
// ClientId and Exp are optional fields in the spec, not included at this time
type IntrospectResponse struct {
	Active      bool   `json:"active"`                // all tokens returned here are active or inactive no matter what the reaason
	Scope       string `json:"scope,omitempty"`       // string with a space delimited list of scopes
	Sub         string `json:"sub,omitempty"`         // client id associated with the token
	ServiceName string `json:"client_name,omitempty"` // cleint name associated with the token (convenience field added by me)
	Iss         string `json:"iss,omitempty"`         // issueing service name
}

// AuthorizedService is a model representing a service and it's id that have passed authorization checks
type AuthorizedService struct {
	ServiceId    string `json:"service_id"`
	ServiceName  string `json:"service_name"`
	AuthorizedBy string `json:"authorized_by,omitempty"` // the service that issued the token
}
