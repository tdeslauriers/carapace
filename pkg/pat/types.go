package pat

import "fmt"

// InstrospectCmd is a model used as a command to submit a PAT token for introspection
type InstrospectCmd struct {
	Token string `json:"token"`
}

// Validate checks if the introspect command is valid/well-formed
// It is a sanity check of the token length only.
func (cmd *InstrospectCmd) Validate() error {

	// quick sanity check of token length
	if len(cmd.Token) < 64 || len(cmd.Token) > 128 {
		return fmt.Errorf("invalid pat token length")
	}

	return nil
}

// InstrospectResponse is a model used as a response from a PAT token introspection
// it will contain a string slice of scopes associated with the PAT token
type InstrospectResponse struct {
	ServiceId   string   `json:"service_id"`
	ServiceName string   `json:"service_name"`
	PatActive   bool     `json:"pat_active"`
	PatRevoked  bool     `json:"pat_revoked"`
	PatExpired  bool     `json:"pat_expired"`
	Scopes      []string `json:"scopes"`
}

// AuthorizedService is a model representing a service and it's id that have passed authorization checks
type AuthorizedService struct {
	ServiceId   string `json:"service_id"`
	ServiceName string `json:"service_name"`
}
