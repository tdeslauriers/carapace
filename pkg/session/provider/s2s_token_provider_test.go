package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/connect/telemetry"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// mockRepository is a test double for the Repository interface.
// InsertToken and DeleteTokenById are called from goroutines, so they are mutex-protected.
type mockRepository struct {
	mu                 sync.Mutex
	findActiveTokensFn func(ctx context.Context, serviceName string) ([]S2sAuthorization, error)
	insertTokenFn      func(ctx context.Context, token S2sAuthorization) error
	deleteTokenByIdFn  func(ctx context.Context, uuid string) error
}

func (m *mockRepository) FindActiveTokens(ctx context.Context, serviceName string) ([]S2sAuthorization, error) {
	return m.findActiveTokensFn(ctx, serviceName)
}

func (m *mockRepository) InsertToken(ctx context.Context, token S2sAuthorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.insertTokenFn != nil {
		return m.insertTokenFn(ctx, token)
	}
	return nil
}

func (m *mockRepository) DeleteTokenById(ctx context.Context, uuid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteTokenByIdFn != nil {
		return m.deleteTokenByIdFn(ctx, uuid)
	}
	return nil
}

// mockCryptor is a test double for the data.Cryptor interface.
// EncryptServiceData is called from goroutines, so it is mutex-protected.
type mockCryptor struct {
	mu            sync.Mutex
	encryptDataFn func([]byte) (string, error)
	decryptDataFn func(string) ([]byte, error)
}

func (m *mockCryptor) EncryptServiceData(plaintext []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.encryptDataFn != nil {
		return m.encryptDataFn(plaintext)
	}
	return "enc-" + string(plaintext), nil
}

func (m *mockCryptor) DecryptServiceData(ciphertext string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decryptDataFn != nil {
		return m.decryptDataFn(ciphertext)
	}
	return []byte(ciphertext), nil
}

func (m *mockCryptor) EncryptField(fieldname, plaintext string, ch chan string, errCh chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	ch <- plaintext
}

func (m *mockCryptor) DecryptField(fieldname, ciphertext string, ch chan string, errCh chan error, wg *sync.WaitGroup) {
	defer wg.Done()
	ch <- ciphertext
}

// mockTlsClient is a test double for the connect.TlsClient interface.
// Do is only called from the main goroutine (login/refresh paths), not from spawned goroutines.
type mockTlsClient struct {
	doFn func(req *http.Request) (*http.Response, error)
}

func (m *mockTlsClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFn != nil {
		return m.doFn(req)
	}
	return nil, fmt.Errorf("unexpected HTTP call to %s", req.URL.String())
}

// jsonResponse builds a minimal *http.Response with a JSON body, as expected by PostToService.
func jsonResponse(status int, body any) *http.Response {
	b, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func TestGetServiceToken(t *testing.T) {

	future := data.CustomTime{Time: time.Now().Add(time.Hour)}
	past := data.CustomTime{Time: time.Now().Add(-time.Hour)}

	const (
		serviceName       = "pixie"
		encServiceToken   = "enc-service-token"
		encRefreshToken   = "enc-refresh-token"
		plainServiceToken = "plain-service-token"
		plainRefreshToken = "plain-refresh-token"
	)

	// activeToken simulates a record returned from the DB with an unexpired service token.
	activeToken := S2sAuthorization{
		Jti:            "active-jti",
		ServiceName:    serviceName,
		ServiceToken:   encServiceToken,
		TokenExpires:   future,
		RefreshToken:   encRefreshToken,
		RefreshExpires: future,
	}

	// expiredToken simulates a record where the service token has expired but the refresh has not.
	expiredToken := S2sAuthorization{
		Jti:            "expired-jti",
		ServiceName:    serviceName,
		ServiceToken:   encServiceToken,
		TokenExpires:   past,
		RefreshToken:   encRefreshToken,
		RefreshExpires: future,
	}

	// refreshedAuthz is the response body returned by a successful /refresh call.
	refreshedAuthz := S2sAuthorization{
		Jti:            "refreshed-jti",
		ServiceName:    serviceName,
		ServiceToken:   "refreshed-service-token",
		TokenExpires:   future,
		RefreshToken:   "new-refresh-token",
		RefreshExpires: future,
	}

	// loginAuthz is the response body returned by a successful /login call.
	loginAuthz := S2sAuthorization{
		Jti:            "login-jti",
		ServiceName:    serviceName,
		ServiceToken:   "login-service-token",
		TokenExpires:   future,
		RefreshToken:   "login-refresh-token",
		RefreshExpires: future,
	}

	tests := []struct {
		name        string
		ctx         context.Context
		serviceName string
		repo        *mockRepository
		cryptor     *mockCryptor
		tlsClient   *mockTlsClient
		wantToken   string
		wantErr     bool
		errSubstr   string
	}{
		{
			// Happy path: active cached token is found and decrypted, no network call.
			name:        "active_token_found",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{activeToken}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(_ string) ([]byte, error) {
					return []byte(plainServiceToken), nil
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(req *http.Request) (*http.Response, error) {
					t.Errorf("unexpected HTTP call: active token should have been returned from cache")
					return nil, nil
				},
			},
			wantToken: plainServiceToken,
			wantErr:   false,
		},
		{
			// Active token exists but decryption fails; falls through to the refresh loop.
			name:        "active_token_decrypt_fails_refresh_succeeds",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{activeToken}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(ciphertext string) ([]byte, error) {
					// Fail the service-token decrypt (loop 1) but succeed for the refresh
					// token decrypt inside refreshS2sToken (loop 2).
					if ciphertext == encServiceToken {
						return nil, fmt.Errorf("service token decryption failed")
					}
					return []byte(plainRefreshToken), nil
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusOK, refreshedAuthz), nil
				},
			},
			wantToken: refreshedAuthz.ServiceToken,
			wantErr:   false,
		},
		{
			// Service token is expired; the refresh loop runs and gets a new token via /refresh.
			name:        "expired_token_refresh_succeeds",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{expiredToken}, nil
				},
			},
			cryptor: &mockCryptor{},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusOK, refreshedAuthz), nil
				},
			},
			wantToken: refreshedAuthz.ServiceToken,
			wantErr:   false,
		},
		{
			// No cached tokens at all; a full /login is performed.
			name:        "no_tokens_login_succeeds",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{}, nil
				},
			},
			cryptor: &mockCryptor{},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusOK, loginAuthz), nil
				},
			},
			wantToken: loginAuthz.ServiceToken,
			wantErr:   false,
		},
		{
			// DB error on retrieval propagates immediately as an error.
			name:        "retrieve_tokens_db_error",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return nil, fmt.Errorf("db connection failed")
				},
			},
			cryptor:   &mockCryptor{},
			tlsClient: &mockTlsClient{},
			wantErr:   true,
			errSubstr: "failed to retrieve service tokens",
		},
		{
			// No cached tokens and /login returns a 4xx; error is propagated.
			name:        "login_fails_4xx",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{}, nil
				},
			},
			cryptor: &mockCryptor{},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusUnauthorized, connect.ErrorHttp{
						StatusCode: http.StatusUnauthorized,
						Message:    "invalid credentials",
					}), nil
				},
			},
			wantErr:   true,
			errSubstr: "s2s login failed",
		},
		{
			// Expired token and refresh-token decrypt fails for all records;
			// falls all the way through to a fresh /login.
			name:        "refresh_fails_fallback_to_login",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{expiredToken}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(_ string) ([]byte, error) {
					return nil, fmt.Errorf("refresh token claimed / unavailable")
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusOK, loginAuthz), nil
				},
			},
			wantToken: loginAuthz.ServiceToken,
			wantErr:   false,
		},
		{
			// Multiple expired tokens all fail to refresh; falls back to login.
			name:        "multiple_expired_tokens_all_refresh_fail_login_succeeds",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{expiredToken, expiredToken}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(_ string) ([]byte, error) {
					return nil, fmt.Errorf("all refresh tokens claimed")
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(_ *http.Request) (*http.Response, error) {
					return jsonResponse(http.StatusOK, loginAuthz), nil
				},
			},
			wantToken: loginAuthz.ServiceToken,
			wantErr:   false,
		},
		{
			// Telemetry fields present in context are picked up and enriched onto the logger.
			// Functionally identical to active_token_found; validates the telemetry code path.
			name: "active_token_with_telemetry_in_context",
			ctx: func() context.Context {
				t := &telemetry.Telemetry{
					Traceparent: telemetry.Traceparent{
						Version: "00",
						TraceId: telemetry.GenerateTraceId(),
						SpanId:  telemetry.GenerateSpanId(),
						Flags:   "01",
					},
				}
				req, _ := http.NewRequest(http.MethodGet, "http://test", nil)
				ctx := context.WithValue(req.Context(), telemetry.TelemetryKey, t)
				return ctx
			}(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					return []S2sAuthorization{activeToken}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(_ string) ([]byte, error) {
					return []byte(plainServiceToken), nil
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(req *http.Request) (*http.Response, error) {
					t.Errorf("unexpected HTTP call: active token should have been returned from cache")
					return nil, nil
				},
			},
			wantToken: plainServiceToken,
			wantErr:   false,
		},
		{
			// Two active tokens in cache; decrypt fails on the first, succeeds on the second.
			// Validates that the service-token loop continues rather than aborting on first failure.
			name:        "multiple_active_tokens_first_decrypt_fails_second_succeeds",
			ctx:         context.Background(),
			serviceName: serviceName,
			repo: &mockRepository{
				findActiveTokensFn: func(_ context.Context, _ string) ([]S2sAuthorization, error) {
					second := activeToken
					second.Jti = "active-jti-2"
					second.ServiceToken = "enc-service-token-2"
					return []S2sAuthorization{activeToken, second}, nil
				},
			},
			cryptor: &mockCryptor{
				decryptDataFn: func(ciphertext string) ([]byte, error) {
					if ciphertext == encServiceToken {
						return nil, fmt.Errorf("first token decryption failed")
					}
					return []byte("plain-service-token-2"), nil
				},
			},
			tlsClient: &mockTlsClient{
				doFn: func(req *http.Request) (*http.Response, error) {
					t.Errorf("unexpected HTTP call: second active token should have been returned from cache")
					return nil, nil
				},
			},
			wantToken: "plain-service-token-2",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			caller := connect.NewS2sCaller(
				"http://test-auth-service",
				serviceName,
				tt.tlsClient,
				connect.RetryConfiguration{
					MaxRetries:  1,
					BaseBackoff: 0,
					MaxBackoff:  0,
				},
			)

			provider := &s2sTokenProvider{
				s2s:     caller,
				creds:   S2sCredentials{ClientId: "test-client-id", ClientSecret: "test-client-secret"},
				db:      tt.repo,
				cryptor: tt.cryptor,
				logger:  slog.Default(),
			}

			token, err := provider.GetServiceToken(tt.ctx, tt.serviceName)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
			if token != tt.wantToken {
				t.Fatalf("expected token %q, got %q", tt.wantToken, token)
			}
		})
	}
}
