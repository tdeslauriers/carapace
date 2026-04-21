package types

import (
	"strings"
	"testing"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

func TestS2sLoginCmdValidateCmd(t *testing.T) {
	validUuid := "b3e2a1d4-1234-5678-abcd-ef0123456789"
	validSecret := strings.Repeat("a", validate.PasswordMin)
	validService := "pixie"

	tests := []struct {
		name      string
		cmd       S2sLoginCmd
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: validSecret,
				ServiceName:  validService,
			},
			wantErr: false,
		},
		{
			name: "invalid_client_id_not_uuid",
			cmd: S2sLoginCmd{
				ClientId:     "not-a-uuid",
				ClientSecret: validSecret,
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "invalid_client_id_empty",
			cmd: S2sLoginCmd{
				ClientId:     "",
				ClientSecret: validSecret,
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid client id",
		},
		{
			name: "invalid_service_name_empty",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: validSecret,
				ServiceName:  "",
			},
			wantErr:   true,
			errSubstr: "invalid service",
		},
		{
			name: "invalid_service_name_uppercase",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: validSecret,
				ServiceName:  "MyService",
			},
			wantErr:   true,
			errSubstr: "invalid service",
		},
		{
			name: "invalid_service_name_too_long",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: validSecret,
				ServiceName:  strings.Repeat("a", validate.ServiceNameMax+1),
			},
			wantErr:   true,
			errSubstr: "invalid service",
		},
		{
			name: "invalid_secret_too_short",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: strings.Repeat("a", validate.PasswordMin-1),
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid client secret",
		},
		{
			name: "invalid_secret_too_long",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: strings.Repeat("a", validate.EmailMax+1),
				ServiceName:  validService,
			},
			wantErr:   true,
			errSubstr: "invalid client secret",
		},
		{
			name: "valid_secret_exact_min",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: strings.Repeat("a", validate.PasswordMin),
				ServiceName:  validService,
			},
			wantErr: false,
		},
		{
			name: "valid_secret_exact_max",
			cmd: S2sLoginCmd{
				ClientId:     validUuid,
				ClientSecret: strings.Repeat("a", validate.EmailMax),
				ServiceName:  validService,
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
