package types

import (
	"strings"
	"testing"
)

func TestS2sRefreshCmdValidateCmd(t *testing.T) {
	validToken := strings.Repeat("t", 32)
	validService := "pixie"

	tests := []struct {
		name      string
		cmd       S2sRefreshCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: S2sRefreshCmd{
				RefreshToken: validToken,
				ServiceName:  validService,
			},
			wantErr: false,
		},
		{
			name: "invalid_token_too_short",
			cmd: S2sRefreshCmd{
				RefreshToken: strings.Repeat("t", 15),
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "invalid_token_too_long",
			cmd: S2sRefreshCmd{
				RefreshToken: strings.Repeat("t", 65),
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "valid_token_exact_min",
			cmd: S2sRefreshCmd{
				RefreshToken: strings.Repeat("t", 16),
				ServiceName:  validService,
			},
			wantErr: false,
		},
		{
			name: "valid_token_exact_max",
			cmd: S2sRefreshCmd{
				RefreshToken: strings.Repeat("t", 64),
				ServiceName:  validService,
			},
			wantErr: false,
		},
		{
			name: "invalid_service_name_empty",
			cmd: S2sRefreshCmd{
				RefreshToken: validToken,
				ServiceName:  "",
			},
			wantErr:   true,
			errSubstr: "invalid service name",
		},
		{
			name: "invalid_service_name_uppercase",
			cmd: S2sRefreshCmd{
				RefreshToken: validToken,
				ServiceName:  "MyService",
			},
			wantErr:   true,
			errSubstr: "invalid service name",
		},
		{
			name: "invalid_service_name_hyphen",
			cmd: S2sRefreshCmd{
				RefreshToken: validToken,
				ServiceName:  "my-service",
			},
			wantErr:   true,
			errSubstr: "invalid service name",
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

func TestUserRefreshCmdValidateCmd(t *testing.T) {
	validToken := strings.Repeat("t", 32)
	validClientId := strings.Repeat("c", 32)

	tests := []struct {
		name      string
		cmd       UserRefreshCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: UserRefreshCmd{
				RefreshToken: validToken,
				ClientId:     validClientId,
			},
			wantErr: false,
		},
		{
			name: "invalid_token_too_short",
			cmd: UserRefreshCmd{
				RefreshToken: strings.Repeat("t", 15),
				ClientId:     validClientId,
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "invalid_token_too_long",
			cmd: UserRefreshCmd{
				RefreshToken: strings.Repeat("t", 65),
				ClientId:     validClientId,
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "valid_token_exact_min",
			cmd: UserRefreshCmd{
				RefreshToken: strings.Repeat("t", 16),
				ClientId:     validClientId,
			},
			wantErr: false,
		},
		{
			name: "valid_token_exact_max",
			cmd: UserRefreshCmd{
				RefreshToken: strings.Repeat("t", 64),
				ClientId:     validClientId,
			},
			wantErr: false,
		},
		{
			name: "invalid_client_id_too_short",
			cmd: UserRefreshCmd{
				RefreshToken: validToken,
				ClientId:     strings.Repeat("c", 15),
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "invalid_client_id_too_long",
			cmd: UserRefreshCmd{
				RefreshToken: validToken,
				ClientId:     strings.Repeat("c", 65),
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "valid_client_id_exact_min",
			cmd: UserRefreshCmd{
				RefreshToken: validToken,
				ClientId:     strings.Repeat("c", 16),
			},
			wantErr: false,
		},
		{
			name: "valid_client_id_exact_max",
			cmd: UserRefreshCmd{
				RefreshToken: validToken,
				ClientId:     strings.Repeat("c", 64),
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

func TestDestroyRefreshCmdValidateCmd(t *testing.T) {
	tests := []struct {
		name      string
		cmd       DestroyRefreshCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: strings.Repeat("t", 32),
			},
			wantErr: false,
		},
		{
			name: "valid_exact_min",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: strings.Repeat("t", 16),
			},
			wantErr: false,
		},
		{
			name: "valid_exact_max",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: strings.Repeat("t", 64),
			},
			wantErr: false,
		},
		{
			name: "invalid_too_short",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: strings.Repeat("t", 15),
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "invalid_too_long",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: strings.Repeat("t", 65),
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
		},
		{
			name: "invalid_empty",
			cmd: DestroyRefreshCmd{
				DestroyRefreshToken: "",
			},
			wantErr:   true,
			errSubstr: "invalid refresh token",
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
