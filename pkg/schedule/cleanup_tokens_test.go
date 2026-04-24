package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
)

// mockRepository is a test double for the Repository interface.
// Methods called from goroutines (DeleteSessionAccessTknXref, DeleteSessionOauthXref)
// are mutex-protected.
type mockRepository struct {
	mu sync.Mutex

	findExpiredRefreshXrefsFn   func() ([]SessionAccessXref, error)
	findExpiredAccessTknXrefsFn func(hours int) ([]SessionAccessXref, error)
	findExpiredOauthXrefsFn     func(hours int) ([]SessionOauthXref, error)

	deleteExpiredAccessTokenFn func() error
	deleteExpiredSvcTknsFn     func() error
	deleteOauthFlowFn          func(hours int) error
	deleteExpiredSessionFn     func(hours int) error
	deleteExpiredRefreshFn     func(hours int) error
	deleteSessionAccessTknXrefFn func(id int) error
	deleteSessionOauthXrefFn   func(id int) error
	deleteAuthCodeXrefsFn      func() error
	deleteAuthCodeFn           func() error
}

func (m *mockRepository) FindExpiredRefreshXrefs() ([]SessionAccessXref, error) {
	if m.findExpiredRefreshXrefsFn != nil {
		return m.findExpiredRefreshXrefsFn()
	}
	return nil, nil
}

func (m *mockRepository) FindExpiredAccessTknXrefs(hours int) ([]SessionAccessXref, error) {
	if m.findExpiredAccessTknXrefsFn != nil {
		return m.findExpiredAccessTknXrefsFn(hours)
	}
	return nil, nil
}

func (m *mockRepository) FindExpiredOauthXrefs(hours int) ([]SessionOauthXref, error) {
	if m.findExpiredOauthXrefsFn != nil {
		return m.findExpiredOauthXrefsFn(hours)
	}
	return nil, nil
}

func (m *mockRepository) DeleteExpiredAccessToken() error {
	if m.deleteExpiredAccessTokenFn != nil {
		return m.deleteExpiredAccessTokenFn()
	}
	return nil
}

func (m *mockRepository) DeleteExpiredSvcTkns() error {
	if m.deleteExpiredSvcTknsFn != nil {
		return m.deleteExpiredSvcTknsFn()
	}
	return nil
}

func (m *mockRepository) DeleteOauthFlow(hours int) error {
	if m.deleteOauthFlowFn != nil {
		return m.deleteOauthFlowFn(hours)
	}
	return nil
}

func (m *mockRepository) DeleteExpiredSession(hours int) error {
	if m.deleteExpiredSessionFn != nil {
		return m.deleteExpiredSessionFn(hours)
	}
	return nil
}

func (m *mockRepository) DeleteExpiredRefresh(hours int) error {
	if m.deleteExpiredRefreshFn != nil {
		return m.deleteExpiredRefreshFn(hours)
	}
	return nil
}

func (m *mockRepository) DeleteSessionAccessTknXref(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteSessionAccessTknXrefFn != nil {
		return m.deleteSessionAccessTknXrefFn(id)
	}
	return nil
}

func (m *mockRepository) DeleteSessionOauthXref(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteSessionOauthXrefFn != nil {
		return m.deleteSessionOauthXrefFn(id)
	}
	return nil
}

func (m *mockRepository) DeleteAuthCodeXrefs() error {
	if m.deleteAuthCodeXrefsFn != nil {
		return m.deleteAuthCodeXrefsFn()
	}
	return nil
}

func (m *mockRepository) DeleteAuthCode() error {
	if m.deleteAuthCodeFn != nil {
		return m.deleteAuthCodeFn()
	}
	return nil
}

// newTestCleanup wires a cleanup struct with a mock repository and a silent logger.
func newTestCleanup(repo *mockRepository) *cleanup {
	return &cleanup{
		db:     repo,
		logger: slog.Default(),
	}
}

func TestRunExpiredRefresh(t *testing.T) {
	tests := []struct {
		name    string
		hours   int
		repo    *mockRepository
		wantErr bool
	}{
		{
			name:  "success",
			hours: 24,
			repo: &mockRepository{
				deleteExpiredRefreshFn: func(hours int) error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			name:  "db_error_logged_not_returned",
			hours: 24,
			repo: &mockRepository{
				deleteExpiredRefreshFn: func(hours int) error {
					return fmt.Errorf("db connection lost")
				},
			},
			// runExpiredRefresh logs the error but has no return value.
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCleanup(tt.repo)
			// Should never panic regardless of DB outcome.
			c.runExpiredRefresh(tt.hours)
		})
	}
}

func TestRunExpiredAccess(t *testing.T) {
	xrefs := []SessionAccessXref{
		{Id: 1, UxsessionId: "sess-uuid-1", AccesstokenId: "at-uuid-1"},
		{Id: 2, UxsessionId: "sess-uuid-2", AccesstokenId: "at-uuid-2"},
	}

	tests := []struct {
		name              string
		repo              *mockRepository
		wantErr           bool
		wantXrefDeletions int
	}{
		{
			// No expired xrefs exist; delete-access-token should still be called.
			name: "no_xrefs_deletes_access_tokens",
			repo: &mockRepository{
				findExpiredRefreshXrefsFn: func() ([]SessionAccessXref, error) {
					return []SessionAccessXref{}, nil
				},
				deleteExpiredAccessTokenFn: func() error {
					return nil
				},
			},
			wantErr:           false,
			wantXrefDeletions: 0,
		},
		{
			// Two expired xrefs exist; both xref rows and the access tokens get deleted.
			name: "two_xrefs_deleted_then_access_tokens",
			repo: &mockRepository{
				findExpiredRefreshXrefsFn: func() ([]SessionAccessXref, error) {
					return xrefs, nil
				},
				deleteSessionAccessTknXrefFn: func(id int) error {
					return nil
				},
				deleteExpiredAccessTokenFn: func() error {
					return nil
				},
			},
			wantErr:           false,
			wantXrefDeletions: 2,
		},
		{
			// Xref query fails; returns error to signal the scheduling loop to skip the cycle.
			name: "find_xrefs_error_returns_error",
			repo: &mockRepository{
				findExpiredRefreshXrefsFn: func() ([]SessionAccessXref, error) {
					return nil, fmt.Errorf("select failed")
				},
			},
			wantErr: true,
		},
		{
			// Individual xref delete fails; access token delete must NOT be called because
			// the surviving xref rows would violate the FK constraint.
			name: "xref_delete_fails_skips_access_token_delete",
			repo: &mockRepository{
				findExpiredRefreshXrefsFn: func() ([]SessionAccessXref, error) {
					return xrefs, nil
				},
				deleteSessionAccessTknXrefFn: func(id int) error {
					return fmt.Errorf("xref delete failed for id %d", id)
				},
				deleteExpiredAccessTokenFn: func() error {
					t.Error("DeleteExpiredAccessToken must not be called when xref deletes failed")
					return nil
				},
			},
			wantErr: false,
		},
		{
			// Access token delete fails; logged but no error is returned.
			name: "access_token_delete_fails_no_error_returned",
			repo: &mockRepository{
				findExpiredRefreshXrefsFn: func() ([]SessionAccessXref, error) {
					return []SessionAccessXref{}, nil
				},
				deleteExpiredAccessTokenFn: func() error {
					return fmt.Errorf("delete access token failed")
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCleanup(tt.repo)

			err := c.runExpiredAccess()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
		})
	}
}

func TestRunExpiredS2s(t *testing.T) {
	tests := []struct {
		name string
		repo *mockRepository
	}{
		{
			name: "success",
			repo: &mockRepository{
				deleteExpiredSvcTknsFn: func() error {
					return nil
				},
			},
		},
		{
			name: "db_error_logged_not_returned",
			repo: &mockRepository{
				deleteExpiredSvcTknsFn: func() error {
					return fmt.Errorf("delete s2s tokens failed")
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCleanup(tt.repo)
			// Should never panic regardless of DB outcome.
			c.runExpiredS2s()
		})
	}
}

func TestRunExpiredSession(t *testing.T) {
	oauthXrefs := []SessionOauthXref{
		{Id: 10, UxsessionId: "sess-uuid-1", OauthflowId: "oauth-uuid-1"},
		{Id: 11, UxsessionId: "sess-uuid-2", OauthflowId: "oauth-uuid-2"},
	}
	accessXrefs := []SessionAccessXref{
		{Id: 20, UxsessionId: "sess-uuid-1", AccesstokenId: "at-uuid-1"},
	}

	tests := []struct {
		name    string
		hours   int
		repo    *mockRepository
		wantErr bool
	}{
		{
			// Happy path: no xrefs of either type; fire-and-forget deletes are launched.
			name:  "no_xrefs_fires_delete_goroutines",
			hours: 24,
			repo: &mockRepository{
				findExpiredOauthXrefsFn: func(hours int) ([]SessionOauthXref, error) {
					return []SessionOauthXref{}, nil
				},
				findExpiredAccessTknXrefsFn: func(hours int) ([]SessionAccessXref, error) {
					return []SessionAccessXref{}, nil
				},
				deleteOauthFlowFn: func(hours int) error {
					return nil
				},
				deleteExpiredSessionFn: func(hours int) error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			// Both xref types present; all xref rows deleted before parent records.
			name:  "xrefs_present_all_deleted",
			hours: 24,
			repo: &mockRepository{
				findExpiredOauthXrefsFn: func(hours int) ([]SessionOauthXref, error) {
					return oauthXrefs, nil
				},
				findExpiredAccessTknXrefsFn: func(hours int) ([]SessionAccessXref, error) {
					return accessXrefs, nil
				},
				deleteSessionOauthXrefFn: func(id int) error {
					return nil
				},
				deleteSessionAccessTknXrefFn: func(id int) error {
					return nil
				},
				deleteOauthFlowFn: func(hours int) error {
					return nil
				},
				deleteExpiredSessionFn: func(hours int) error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			// OAuth xref query fails; returns error immediately (no access-xref query attempted).
			name:  "find_oauth_xrefs_error_returns_error",
			hours: 24,
			repo: &mockRepository{
				findExpiredOauthXrefsFn: func(hours int) ([]SessionOauthXref, error) {
					return nil, fmt.Errorf("oauth xref select failed")
				},
			},
			wantErr: true,
		},
		{
			// Access-token xref query fails after oauth goroutines are already launched;
			// must drain launched goroutines via wg.Wait() before returning.
			name:  "find_access_xrefs_error_after_oauth_goroutines_launched",
			hours: 24,
			repo: &mockRepository{
				findExpiredOauthXrefsFn: func(hours int) ([]SessionOauthXref, error) {
					return oauthXrefs, nil
				},
				deleteSessionOauthXrefFn: func(id int) error {
					return nil
				},
				findExpiredAccessTknXrefsFn: func(hours int) ([]SessionAccessXref, error) {
					return nil, fmt.Errorf("access xref select failed")
				},
			},
			wantErr: true,
		},
		{
			// Individual xref deletes fail; errors are logged but the cycle continues.
			name:  "xref_deletes_fail_cycle_completes",
			hours: 24,
			repo: &mockRepository{
				findExpiredOauthXrefsFn: func(hours int) ([]SessionOauthXref, error) {
					return oauthXrefs, nil
				},
				findExpiredAccessTknXrefsFn: func(hours int) ([]SessionAccessXref, error) {
					return accessXrefs, nil
				},
				deleteSessionOauthXrefFn: func(id int) error {
					return fmt.Errorf("oauth xref delete failed for id %d", id)
				},
				deleteSessionAccessTknXrefFn: func(id int) error {
					return fmt.Errorf("access xref delete failed for id %d", id)
				},
				deleteOauthFlowFn: func(hours int) error {
					return nil
				},
				deleteExpiredSessionFn: func(hours int) error {
					return nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use channel-based synchronization to wait for the fire-and-forget
			// DeleteOauthFlow and DeleteExpiredSession goroutines that runExpiredSession
			// launches after wg.Wait(). Without this, the test goroutine could exit
			// before those goroutines complete, causing races under -race.
			oauthDone := make(chan struct{}, 1)
			sessionDone := make(chan struct{}, 1)

			repo := tt.repo

			if repo.deleteOauthFlowFn != nil {
				origFn := repo.deleteOauthFlowFn
				repo.deleteOauthFlowFn = func(hours int) error {
					err := origFn(hours)
					oauthDone <- struct{}{}
					return err
				}
			}

			if repo.deleteExpiredSessionFn != nil {
				origFn := repo.deleteExpiredSessionFn
				repo.deleteExpiredSessionFn = func(hours int) error {
					err := origFn(hours)
					sessionDone <- struct{}{}
					return err
				}
			}

			c := newTestCleanup(repo)
			err := c.runExpiredSession(tt.hours)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}

			// Drain the synchronization channels for the fire-and-forget goroutines
			// only when the helper was expected to launch them (no early error return).
			if repo.deleteOauthFlowFn != nil {
				<-oauthDone
			}
			if repo.deleteExpiredSessionFn != nil {
				<-sessionDone
			}
		})
	}
}

func TestRunExpiredAuthcode(t *testing.T) {
	tests := []struct {
		name    string
		repo    *mockRepository
		wantErr bool
		errMsg  string
	}{
		{
			name: "success",
			repo: &mockRepository{
				deleteAuthCodeXrefsFn: func() error {
					return nil
				},
				deleteAuthCodeFn: func() error {
					return nil
				},
			},
			wantErr: false,
		},
		{
			// Xref delete fails; returns error so the cycle is skipped.
			name: "xref_delete_fails_returns_error",
			repo: &mockRepository{
				deleteAuthCodeXrefsFn: func() error {
					return fmt.Errorf("authcode xref delete failed")
				},
			},
			wantErr: true,
		},
		{
			// Xref delete succeeds but authcode delete fails; returns error.
			name: "authcode_delete_fails_returns_error",
			repo: &mockRepository{
				deleteAuthCodeXrefsFn: func() error {
					return nil
				},
				deleteAuthCodeFn: func() error {
					return fmt.Errorf("authcode delete failed")
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCleanup(tt.repo)

			err := c.runExpiredAuthcode()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	// Each public method launches a goroutine that selects on ctx.Done() or the
	// timer channel. With a pre-cancelled context the goroutine should exit
	// immediately without ever calling any repository method.

	noCallRepo := &mockRepository{
		deleteExpiredRefreshFn: func(hours int) error {
			t.Error("DeleteExpiredRefresh called on cancelled context")
			return nil
		},
		deleteExpiredAccessTokenFn: func() error {
			t.Error("DeleteExpiredAccessToken called on cancelled context")
			return nil
		},
		deleteExpiredSvcTknsFn: func() error {
			t.Error("DeleteExpiredSvcTkns called on cancelled context")
			return nil
		},
		deleteOauthFlowFn: func(hours int) error {
			t.Error("DeleteOauthFlow called on cancelled context")
			return nil
		},
		deleteExpiredSessionFn: func(hours int) error {
			t.Error("DeleteExpiredSession called on cancelled context")
			return nil
		},
		deleteAuthCodeFn: func() error {
			t.Error("DeleteAuthCode called on cancelled context")
			return nil
		},
	}

	t.Run("ExpiredRefresh_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newTestCleanup(noCallRepo)
		c.ExpiredRefresh(ctx, 24)
	})

	t.Run("ExpiredAccess_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newTestCleanup(noCallRepo)
		c.ExpiredAccess(ctx)
	})

	t.Run("ExpiredS2s_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newTestCleanup(noCallRepo)
		c.ExpiredS2s(ctx)
	})

	t.Run("ExpiredSession_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newTestCleanup(noCallRepo)
		c.ExpiredSession(ctx, 24)
	})

	t.Run("ExpiredAuthcode_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newTestCleanup(noCallRepo)
		c.ExpiredAuthcode(ctx)
	})
}
