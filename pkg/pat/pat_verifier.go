package pat

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tdeslauriers/carapace/internal/util"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// Verifier is an interface that defines methods for consuming services to verify Personal Access Tokens (PATs).
type Verifier interface {

	// GetPatScopes takes in a PAT token string and returns the associated scopes from the upstream auth service
	GetPatScopes(ctx context.Context, token string) (IntrospectResponse, error)

	// ValidateScopes checks if the scopes associated with a pat token contain at least one of the required scopes.
	ValidateScopes(ctx context.Context, requiredScopes []string, token string) (bool, error)

	// BuildAuthorized builds a AuthorizedService struct of a service and its id that have passed authorization
	// checks from an set/slice of required scopes and a pat token string.
	BuildAuthorized(ctx context.Context, requiredScopes []string, token string) (AuthorizedService, error)
}

// NewVerifier creates a new Verifier interface with and returns and underlying concrete implementation.
func NewVerifier(authSvcName string, c *connect.S2sCaller, p provider.S2sTokenProvider) Verifier {
	return &verifier{
		authSvcName: authSvcName,
		auth:        c,
		tkn:         p,

		logger: slog.Default().
			With(slog.String(util.FrameworkKey, util.FrameworkCarapace)).
			With(slog.String(util.PackageKey, util.PackagePat)).
			With(slog.String(util.ComponentKey, util.ComponentPatVerifier)),
	}
}

var _ Verifier = (*verifier)(nil)

// verifier is the concrete implementation of the Verifier interface.
type verifier struct {
	authSvcName string                    // ie, iam vs s2s authentication service
	auth        *connect.S2sCaller        // could be s2s or iam so leaving prop name generic
	tkn         provider.S2sTokenProvider // need an s2s token to call the /introspect endpoint

	logger *slog.Logger
}

// GetScopes is the concrete implementation of the interface method which
// takes in a PAT token string and returns the associated scopes from the upstream auth service
// so that a service endpoint can validate if the token is real, unexpired, and has the required scopes/permissions.
func (v *verifier) GetPatScopes(ctx context.Context, token string) (IntrospectResponse, error) {
	return v.getScopes(ctx, token)
}

// getScopes is a helper method that calls the /introspect endpoint of the upstream auth service
// to validate the provided PAT token and retrieve its associated scopes.
func (v *verifier) getScopes(ctx context.Context, token string) (IntrospectResponse, error) {

	// quick sanity check of token length
	if len(token) < 64 || len(token) > 128 {
		return IntrospectResponse{}, fmt.Errorf("invalid pat token length")
	}

	// get a service token to call the introspect endpoint
	s2sToken, err := v.tkn.GetServiceToken(ctx, v.authSvcName)
	if err != nil {
		return IntrospectResponse{}, fmt.Errorf("failed to get service token for %s: %v", v.authSvcName, err)
	}

	var ir IntrospectResponse // initialize zero value of IntrospectResponse
	ir, err = connect.PostToService[IntrospectCmd, IntrospectResponse](
		v.auth,
		ctx,
		"/introspect",
		s2sToken,
		"",
		IntrospectCmd{Token: token},
	)
	if err != nil {
		return ir, fmt.Errorf("failed to introspect pat token: %v", err)
	}

	return ir, nil
}

// ValidateScopes is the concrete implementation of the interface method which
// checks if the scopes associated with a pat token contain at least one of the required scopes.
func (v *verifier) ValidateScopes(ctx context.Context, requiredScopes []string, token string) (bool, error) {
	return v.validateScopes(ctx, requiredScopes, token)
}

// validateScopes is a helper method that checks if the scopes associated with a pat token
// contain at least one of the required scopes.
func (v *verifier) validateScopes(ctx context.Context, requiredScopes []string, token string) (bool, error) {

	// sanity check on token length
	if len(token) < 64 || len(token) > 128 {
		return false, fmt.Errorf("invalid pat token length, must be between 64 and 128 characters")
	}

	// dont need to validate required scopes because those are provided in code
	// make a map for faster lookup
	if len(requiredScopes) == 0 {
		return false, fmt.Errorf("no required scopes provided for validation")
	}
	requiredMap := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {
		requiredMap[scope] = struct{}{}
	}

	// get the scopes associated with the token
	resp, err := v.getScopes(ctx, token)
	if err != nil {
		return false, fmt.Errorf("failed to get scopes for pat token: %v", err)
	}

	// quick validation of response fields
	// this should be redundant since the service should return an error if the token is invalid
	// for any reason, but goog practice to double check
	// check if the token is active
	if !resp.Active {
		return false, fmt.Errorf("pat token is not active")
	}

	// TODO: add audiences check.  Not a big deal for now since PATs are not audience restricted
	// but good practice to check if we start using audiences in the future

	if len(resp.Scope) == 0 {
		return false, fmt.Errorf("no scopes associated with pat token")
	}

	// split scope string into a slice
	scopes := strings.Split(resp.Scope, " ")
	if len(scopes) == 0 {
		return false, fmt.Errorf("no scopes associated with pat token")
	}

	// check if the token scopes contain at least one of the required scopes
	for _, scope := range scopes {
		if _, ok := requiredMap[scope]; ok {
			return true, nil
		}
	}

	return false, fmt.Errorf("pat token does not have any of the required scopes")
}

// BuildAuthorized builds a AuthorizedService struct of a service and its id that have passed authorization
// checks from an set/slice of // scopes and a pat token string.
func (v *verifier) BuildAuthorized(ctx context.Context, requiredScopes []string, token string) (AuthorizedService, error) {
	return v.buildAuthorized(ctx, requiredScopes, token)
}

// GetServiceToken is a helper method that builds a AuthorizedService struct of a service and its
// id that have passed authorization checks from an set/slice of required scopes and a pat token string.
func (v *verifier) buildAuthorized(ctx context.Context, requiredScopes []string, token string) (AuthorizedService, error) {

	// quick sanity check of token length
	if len(token) < 64 || len(token) > 128 {
		return AuthorizedService{}, fmt.Errorf("invalid pat token length")
	}

	// note: no need to validate required scopes because those are provided in code

	// sanity check on token length
	if len(token) < 64 || len(token) > 128 {
		return AuthorizedService{}, fmt.Errorf("invalid pat token length, must be between 64 and 128 characters")
	}

	// dont need to validate required scopes because those are provided in code
	// make a map for faster lookup
	if len(requiredScopes) == 0 {
		return AuthorizedService{}, fmt.Errorf("no required scopes provided for validation")
	}
	requiredMap := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {
		requiredMap[scope] = struct{}{}
	}

	// get the scopes associated with the token
	resp, err := v.getScopes(ctx, token)
	if err != nil {
		return AuthorizedService{}, fmt.Errorf("failed to get scopes for pat token: %v", err)
	}

	// quick validation of response fields
	// this should be redundant since the service should return an error if the token is invalid
	// for any reason, but goog practice to double check
	// check if the token is active
	if !resp.Active {
		return AuthorizedService{}, fmt.Errorf("pat token is not active")
	}

	// TODO: add audiences check.  Not a big deal for now since PATs are not audience restricted
	// but good practice to check if we start using audiences in the future
	if len(resp.Scope) == 0 {
		return AuthorizedService{}, fmt.Errorf("no scopes associated with pat token")
	}

	// split scope string into a slice
	scopes := strings.Split(resp.Scope, " ")
	if len(scopes) == 0 {
		return AuthorizedService{}, fmt.Errorf("no scopes associated with pat token")
	}

	// check if the token scopes contain at least one of the required scopes
	authorized := false
	for _, scope := range scopes {
		if _, ok := requiredMap[scope]; ok {
			authorized = true
			break
		}
	}

	if !authorized {
		return AuthorizedService{}, fmt.Errorf("pat token does not have any of the required scopes")
	}

	return AuthorizedService{
		ServiceId:    resp.Sub,
		ServiceName:  resp.ServiceName,
		AuthorizedBy: resp.Iss,
	}, nil
}
