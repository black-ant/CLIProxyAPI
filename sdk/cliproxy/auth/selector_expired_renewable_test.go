package auth

import (
	"testing"
	"time"
)

// TestExpiredCredentialSelection covers the "imported credential is already expired" case:
// a credential that still holds a usable refresh token must stay selectable so the request
// can trigger renewal, while credentials that cannot renew remain blocked.
func TestExpiredCredentialSelection(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour).Format(time.RFC3339)

	tests := []struct {
		name    string
		auth    *Auth
		blocked bool
	}{
		{
			name: "expired with refresh token stays selectable",
			auth: &Auth{
				ID:       "renewable",
				Provider: "codex",
				Status:   StatusActive,
				Metadata: map[string]any{
					"access_token":  "expired-token",
					"refresh_token": "rt-1",
					"expired":       past,
					"type":          "codex",
				},
			},
			blocked: false,
		},
		{
			name: "expired without refresh token stays blocked",
			auth: &Auth{
				ID:       "not-renewable",
				Provider: "codex",
				Status:   StatusActive,
				Metadata: map[string]any{
					"access_token": "expired-token",
					"expired":      past,
					"type":         "codex",
				},
			},
			blocked: true,
		},
		{
			name: "expired after terminal sign-in requirement stays blocked",
			auth: &Auth{
				ID:             "signin-required",
				Provider:       "codex",
				Status:         StatusActive,
				RequiresSignIn: true,
				Metadata: map[string]any{
					"access_token":  "expired-token",
					"refresh_token": "rt-1",
					"expired":       past,
					"type":          "codex",
				},
			},
			blocked: true,
		},
		{
			name: "rejected access token stays blocked",
			auth: &Auth{
				ID:                  "rejected",
				Provider:            "codex",
				Status:              StatusActive,
				RejectedAccessToken: "expired-token",
				Metadata: map[string]any{
					"access_token":  "expired-token",
					"refresh_token": "rt-1",
					"expired":       past,
					"type":          "codex",
				},
			},
			blocked: true,
		},
		{
			name: "valid token stays selectable",
			auth: &Auth{
				ID:       "valid",
				Provider: "codex",
				Status:   StatusActive,
				Metadata: map[string]any{
					"access_token":  "valid-token",
					"refresh_token": "rt-1",
					"expired":       now.Add(time.Hour).Format(time.RFC3339),
					"type":          "codex",
				},
			},
			blocked: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocked, _, _ := isAuthBlockedForModel(test.auth, "gpt-5", now)
			if blocked != test.blocked {
				t.Fatalf("isAuthBlockedForModel() = %v, want %v", blocked, test.blocked)
			}
		})
	}
}
