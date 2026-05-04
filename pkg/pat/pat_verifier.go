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
	authSvcName string             // ie, iam vs s2s authentication service
	auth        *connect.S2sCaller // could be s2s or iam so leaving prop name generic
	tkn         provider.S2sTokenProvider

	logger *slog.Logger
}

// GetPatScopes takes in a PAT token string and returns the associated scopes from the upstream auth service
// so that a service endpoint can validate if the token is real, unexpired, and has the required scopes/permissions.
func (v *verifier) GetPatScopes(ctx context.Context, token string) (IntrospectResponse, error) {

	if len(token) < 64 || len(token) > 128 {

		return IntrospectResponse{}, fmt.Errorf("invalid pat token length")
	}

	s2sToken, err := v.tkn.GetServiceToken(ctx, v.authSvcName)
	if err != nil {

		return IntrospectResponse{}, fmt.Errorf("failed to get service token for %s: %v", v.authSvcName, err)
	}

	ir, err := connect.PostToService[IntrospectCmd, IntrospectResponse](
		ctx,
		v.auth,
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

// ValidateScopes checks if the scopes associated with a pat token contain at least one of the required scopes.
func (v *verifier) ValidateScopes(ctx context.Context, requiredScopes []string, token string) (bool, error) {

	if len(token) < 64 || len(token) > 128 {
		return false, fmt.Errorf("invalid pat token length, must be between 64 and 128 characters")
	}

	if len(requiredScopes) == 0 {
		return false, fmt.Errorf("no required scopes provided for validation")
	}

	// make map for efficient lookup of required scopes
	requiredMap := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {
		requiredMap[scope] = struct{}{}
	}

	// get the scopes associated with the pat token from the auth service
	resp, err := v.GetPatScopes(ctx, token)
	if err != nil {
		return false, fmt.Errorf("failed to get scopes for pat token: %v", err)
	}

	// validate that token has at least one of the required scopes and is active
	if err := authorizeFromResponse(resp, requiredMap); err != nil {
		return false, err
	}

	return true, nil
}

// BuildAuthorized builds a AuthorizedService struct of a service and its id that have passed authorization
// checks from an set/slice of required scopes and a pat token string.
func (v *verifier) BuildAuthorized(ctx context.Context, requiredScopes []string, token string) (AuthorizedService, error) {

	// quick input check
	if len(token) < 64 || len(token) > 128 {

		return AuthorizedService{}, fmt.Errorf("invalid pat token length, must be between 64 and 128 characters")
	}

	// if no required scopes provided return an error
	if len(requiredScopes) == 0 {

		return AuthorizedService{}, fmt.Errorf("no required scopes provided for validation")
	}

	// make map for efficient lookup of required scopes
	requiredMap := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {

		requiredMap[scope] = struct{}{}
	}

	// get the scopes associated with the pat token from the auth service
	resp, err := v.GetPatScopes(ctx, token)
	if err != nil {
		return AuthorizedService{}, fmt.Errorf("failed to get scopes for pat token: %v", err)
	}

	// validate that token has at least one of the required scopes and is active
	if err := authorizeFromResponse(resp, requiredMap); err != nil {
		return AuthorizedService{}, err
	}

	return AuthorizedService{
		ServiceId:    resp.Sub,
		ServiceName:  resp.ServiceName,
		AuthorizedBy: resp.Iss,
	}, nil
}

// authorizeFromResponse validates that a PAT introspect response is active and contains at least one required scope.
func authorizeFromResponse(resp IntrospectResponse, requiredMap map[string]struct{}) error {

	if !resp.Active {
		return fmt.Errorf("pat token is not active")
	}

	// TODO: add audiences check. Not a big deal for now since PATs are not audience restricted
	// but good practice to check if we start using audiences in the future

	if len(resp.Scope) == 0 {
		return fmt.Errorf("no scopes associated with pat token")
	}

	for scope := range strings.SplitSeq(resp.Scope, " ") {

		if _, ok := requiredMap[scope]; ok {

			return nil
		}
	}

	return fmt.Errorf("pat token does not have any of the required scopes")
}
