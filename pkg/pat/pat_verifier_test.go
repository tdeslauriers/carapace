package pat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// ---- test doubles -----------------------------------------------------------

type mockTlsClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTlsClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

var _ connect.TlsClient = (*mockTlsClient)(nil)

type mockTokenProvider struct {
	GetServiceTokenFunc func(ctx context.Context, serviceName string) (string, error)
}

func (m *mockTokenProvider) GetServiceToken(ctx context.Context, serviceName string) (string, error) {
	return m.GetServiceTokenFunc(ctx, serviceName)
}

var _ provider.S2sTokenProvider = (*mockTokenProvider)(nil)

// newTestVerifier builds a verifier with mocked HTTP and token-provider dependencies.
func newTestVerifier(t *testing.T, tlsClient connect.TlsClient, tp provider.S2sTokenProvider) *verifier {
	t.Helper()
	return &verifier{
		authSvcName: "test-auth-svc",
		auth: connect.NewS2sCaller(
			"https://auth.test",
			"test-auth-svc",
			tlsClient,
			connect.RetryConfiguration{MaxRetries: 1},
		),
		tkn: tp,
	}
}

// jsonResp builds an *http.Response with a JSON body and the given status code.
// Panics on marshal failure — this should never happen for the simple structs used in tests.
func jsonResp(status int, body any) *http.Response {
	b, err := json.Marshal(body)
	if err != nil {
		panic(fmt.Sprintf("test setup: json.Marshal failed: %v", err))
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

// okTokenProvider returns a mock token provider that always returns a fixed token.
func okTokenProvider() *mockTokenProvider {
	return &mockTokenProvider{
		GetServiceTokenFunc: func(_ context.Context, _ string) (string, error) {
			return "test-s2s-token", nil
		},
	}
}

// ---- fixtures ---------------------------------------------------------------

var (
	validPAT = strings.Repeat("A", 88)  // 88 chars, within [64, 128]
	shortPAT = strings.Repeat("A", 63)  // 63 chars, below minimum
	longPAT  = strings.Repeat("A", 129) // 129 chars, above maximum
)

// ---- TestNewVerifier --------------------------------------------------------

func TestNewVerifier(t *testing.T) {
	v := NewVerifier("test-svc", &connect.S2sCaller{}, nil)
	if v == nil {
		t.Fatal("expected non-nil Verifier, got nil")
	}
}

// ---- TestAuthorizeFromResponse ----------------------------------------------

func TestAuthorizeFromResponse(t *testing.T) {
	requiredMap := map[string]struct{}{
		"r:svc:*": {},
		"w:svc:*": {},
	}

	tests := []struct {
		name      string
		resp      IntrospectResponse
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "inactive_token",
			resp:      IntrospectResponse{Active: false},
			wantErr:   true,
			errSubstr: "not active",
		},
		{
			name:      "active_but_no_scopes",
			resp:      IntrospectResponse{Active: true, Scope: ""},
			wantErr:   true,
			errSubstr: "no scopes",
		},
		{
			name:      "active_no_matching_scopes",
			resp:      IntrospectResponse{Active: true, Scope: "r:other:* w:other:*"},
			wantErr:   true,
			errSubstr: "required scopes",
		},
		{
			name:    "first_scope_matches",
			resp:    IntrospectResponse{Active: true, Scope: "r:svc:*"},
			wantErr: false,
		},
		{
			name:    "second_of_two_scopes_matches",
			resp:    IntrospectResponse{Active: true, Scope: "r:other:* w:svc:*"},
			wantErr: false,
		},
		{
			name:    "multiple_scopes_all_match",
			resp:    IntrospectResponse{Active: true, Scope: "r:svc:* w:svc:*"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeFromResponse(tt.resp, requiredMap)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---- TestGetPatScopes -------------------------------------------------------

func TestGetPatScopes(t *testing.T) {
	successResp := IntrospectResponse{
		Active:      true,
		Scope:       "r:svc:* w:svc:*",
		Sub:         "client-id-123",
		ServiceName: "test-service",
		Iss:         "auth-svc",
	}

	tests := []struct {
		name      string
		token     string
		tlsClient connect.TlsClient
		tokenProv provider.S2sTokenProvider
		wantErr   bool
		errSubstr string
		checkFunc func(t *testing.T, resp IntrospectResponse)
	}{
		{
			name:      "token_too_short",
			token:     shortPAT,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:      "token_too_long",
			token:     longPAT,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:  "token_provider_fails",
			token: validPAT,
			tokenProv: &mockTokenProvider{
				GetServiceTokenFunc: func(_ context.Context, _ string) (string, error) {
					return "", fmt.Errorf("db unavailable")
				},
			},
			wantErr:   true,
			errSubstr: "failed to get service token",
		},
		{
			name:      "http_do_fails",
			token:     validPAT,
			tokenProv: okTokenProvider(),
			tlsClient: &mockTlsClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return nil, fmt.Errorf("connection refused")
				},
			},
			wantErr:   true,
			errSubstr: "failed to introspect pat token",
		},
		{
			name:      "upstream_returns_401",
			token:     validPAT,
			tokenProv: okTokenProvider(),
			tlsClient: &mockTlsClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return jsonResp(http.StatusUnauthorized, connect.ErrorHttp{
						StatusCode: http.StatusUnauthorized,
						Message:    "unauthorized",
					}), nil
				},
			},
			wantErr:   true,
			errSubstr: "failed to introspect pat token",
		},
		{
			name:      "valid_token_returns_introspect_response",
			token:     validPAT,
			tokenProv: okTokenProvider(),
			tlsClient: &mockTlsClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return jsonResp(http.StatusOK, successResp), nil
				},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, resp IntrospectResponse) {
				if !resp.Active {
					t.Error("want Active=true, got false")
				}
				if resp.Scope != successResp.Scope {
					t.Errorf("Scope: want %q, got %q", successResp.Scope, resp.Scope)
				}
				if resp.Sub != successResp.Sub {
					t.Errorf("Sub: want %q, got %q", successResp.Sub, resp.Sub)
				}
				if resp.ServiceName != successResp.ServiceName {
					t.Errorf("ServiceName: want %q, got %q", successResp.ServiceName, resp.ServiceName)
				}
				if resp.Iss != successResp.Iss {
					t.Errorf("Iss: want %q, got %q", successResp.Iss, resp.Iss)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(t, tt.tlsClient, tt.tokenProv)
			resp, err := v.GetPatScopes(context.Background(), tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, resp)
			}
		})
	}
}

// ---- TestValidateScopes -----------------------------------------------------

func TestValidateScopes(t *testing.T) {
	requiredScopes := []string{"r:svc:*", "w:svc:*"}

	// tlsClient that returns the given IntrospectResponse.
	introspectClient := func(ir IntrospectResponse) *mockTlsClient {
		return &mockTlsClient{
			DoFunc: func(_ *http.Request) (*http.Response, error) {
				return jsonResp(http.StatusOK, ir), nil
			},
		}
	}

	tests := []struct {
		name      string
		token     string
		scopes    []string
		tlsClient connect.TlsClient
		tokenProv provider.S2sTokenProvider
		wantOk    bool
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "token_too_short",
			token:     shortPAT,
			scopes:    requiredScopes,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:      "token_too_long",
			token:     longPAT,
			scopes:    requiredScopes,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:      "empty_required_scopes",
			token:     validPAT,
			scopes:    []string{},
			wantErr:   true,
			errSubstr: "no required scopes",
		},
		{
			name:  "token_provider_fails",
			token: validPAT,
			scopes: requiredScopes,
			tokenProv: &mockTokenProvider{
				GetServiceTokenFunc: func(_ context.Context, _ string) (string, error) {
					return "", fmt.Errorf("vault unreachable")
				},
			},
			wantErr:   true,
			errSubstr: "failed to get scopes for pat token",
		},
		{
			name:      "token_not_active",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: false}),
			wantErr:   true,
			errSubstr: "not active",
		},
		{
			name:      "no_scopes_in_response",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: ""}),
			wantErr:   true,
			errSubstr: "no scopes",
		},
		{
			name:      "no_matching_scopes",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: "r:other:*"}),
			wantErr:   true,
			errSubstr: "required scopes",
		},
		{
			name:      "one_required_scope_matches",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: "r:svc:*"}),
			wantOk:    true,
		},
		{
			name:      "second_of_two_required_scopes_matches",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: "r:other:* w:svc:*"}),
			wantOk:    true,
		},
		{
			name:      "all_required_scopes_present",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: "r:svc:* w:svc:*"}),
			wantOk:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(t, tt.tlsClient, tt.tokenProv)
			ok, err := v.ValidateScopes(context.Background(), tt.scopes, tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOk {
				t.Errorf("ValidateScopes: want %v, got %v", tt.wantOk, ok)
			}
		})
	}
}

// ---- TestBuildAuthorized ----------------------------------------------------

func TestBuildAuthorized(t *testing.T) {
	requiredScopes := []string{"r:svc:*", "w:svc:*"}

	introspectClient := func(ir IntrospectResponse) *mockTlsClient {
		return &mockTlsClient{
			DoFunc: func(_ *http.Request) (*http.Response, error) {
				return jsonResp(http.StatusOK, ir), nil
			},
		}
	}

	successResp := IntrospectResponse{
		Active:      true,
		Scope:       "r:svc:*",
		Sub:         "client-id-456",
		ServiceName: "my-service",
		Iss:         "auth-svc",
	}

	tests := []struct {
		name      string
		token     string
		scopes    []string
		tlsClient connect.TlsClient
		tokenProv provider.S2sTokenProvider
		wantErr   bool
		errSubstr string
		checkFunc func(t *testing.T, authorized AuthorizedService)
	}{
		{
			name:      "token_too_short",
			token:     shortPAT,
			scopes:    requiredScopes,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:      "token_too_long",
			token:     longPAT,
			scopes:    requiredScopes,
			wantErr:   true,
			errSubstr: "invalid pat token length",
		},
		{
			name:      "empty_required_scopes",
			token:     validPAT,
			scopes:    []string{},
			wantErr:   true,
			errSubstr: "no required scopes",
		},
		{
			name:  "token_provider_fails",
			token: validPAT,
			scopes: requiredScopes,
			tokenProv: &mockTokenProvider{
				GetServiceTokenFunc: func(_ context.Context, _ string) (string, error) {
					return "", fmt.Errorf("vault unreachable")
				},
			},
			wantErr:   true,
			errSubstr: "failed to get scopes for pat token",
		},
		{
			name:      "token_not_active",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: false}),
			wantErr:   true,
			errSubstr: "not active",
		},
		{
			name:      "no_scopes_in_response",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: ""}),
			wantErr:   true,
			errSubstr: "no scopes",
		},
		{
			name:      "no_matching_scopes",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{Active: true, Scope: "r:other:*"}),
			wantErr:   true,
			errSubstr: "required scopes",
		},
		{
			name:      "authorized_service_fields_populated",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(successResp),
			checkFunc: func(t *testing.T, authorized AuthorizedService) {
				if authorized.ServiceId != successResp.Sub {
					t.Errorf("ServiceId: want %q, got %q", successResp.Sub, authorized.ServiceId)
				}
				if authorized.ServiceName != successResp.ServiceName {
					t.Errorf("ServiceName: want %q, got %q", successResp.ServiceName, authorized.ServiceName)
				}
				if authorized.AuthorizedBy != successResp.Iss {
					t.Errorf("AuthorizedBy: want %q, got %q", successResp.Iss, authorized.AuthorizedBy)
				}
			},
		},
		{
			name:      "second_required_scope_matches",
			token:     validPAT,
			scopes:    requiredScopes,
			tokenProv: okTokenProvider(),
			tlsClient: introspectClient(IntrospectResponse{
				Active:      true,
				Scope:       "r:other:* w:svc:*",
				Sub:         "client-id-789",
				ServiceName: "other-service",
				Iss:         "auth-svc",
			}),
			checkFunc: func(t *testing.T, authorized AuthorizedService) {
				if authorized.ServiceId != "client-id-789" {
					t.Errorf("ServiceId: want %q, got %q", "client-id-789", authorized.ServiceId)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(t, tt.tlsClient, tt.tokenProv)
			authorized, err := v.BuildAuthorized(context.Background(), tt.scopes, tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, authorized)
			}
		})
	}
}
