package types

import (
	"strings"
	"testing"
)

func TestAuthCodeExchangeValidateCmd(t *testing.T) {
	validAuthCode := strings.Repeat("a", 32)
	validState := strings.Repeat("s", 32)
	validNonce := strings.Repeat("n", 32)
	validClientId := strings.Repeat("c", 32)
	validRedirect := "https://example.com/callback"

	tests := []struct {
		name      string
		cmd       AuthCodeExchange
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr: false,
		},
		{
			name: "valid_token_response_type",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: Token,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr: false,
		},
		{
			name: "invalid_auth_code_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     strings.Repeat("a", 15),
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid auth code",
		},
		{
			name: "invalid_auth_code_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     strings.Repeat("a", 65),
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid auth code",
		},
		{
			name: "invalid_response_type_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: "abc",
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid response type",
		},
		{
			name: "invalid_response_type_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: "toolongtype",
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid response type",
		},
		{
			name: "invalid_state_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        strings.Repeat("s", 15),
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid state",
		},
		{
			name: "invalid_state_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        strings.Repeat("s", 257),
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid state",
		},
		{
			name: "invalid_nonce_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        strings.Repeat("n", 15),
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid nonce",
		},
		{
			name: "invalid_nonce_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        strings.Repeat("n", 65),
				ClientId:     validClientId,
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid nonce",
		},
		{
			name: "invalid_client_id_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     strings.Repeat("c", 15),
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "invalid_client_id_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     strings.Repeat("c", 65),
				Redirect:     validRedirect,
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "invalid_redirect_too_short",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     "http",
			},
			wantErr:   true,
			errSubstr: "invalid redirect",
		},
		{
			name: "invalid_redirect_too_long",
			cmd: AuthCodeExchange{
				AuthCode:     validAuthCode,
				ResponseType: AuthCode,
				State:        validState,
				Nonce:        validNonce,
				ClientId:     validClientId,
				Redirect:     strings.Repeat("a", 2049),
			},
			wantErr:   true,
			errSubstr: "invalid redirect",
		},
		{
			name: "valid_exact_min_boundaries",
			cmd: AuthCodeExchange{
				AuthCode:     strings.Repeat("a", 16),
				ResponseType: AuthCode,
				State:        strings.Repeat("s", 16),
				Nonce:        strings.Repeat("n", 16),
				ClientId:     strings.Repeat("c", 16),
				Redirect:     "https://x.co",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.ValidateCmd()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q", tt.name)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
		})
	}
}
