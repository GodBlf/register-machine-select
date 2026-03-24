package fileops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractAuthFieldsAndCodexDetection(t *testing.T) {
	t.Parallel()

	service := NewService()
	payload := map[string]any{
		"provider": "codex",
		"email":    "user@example.com",
		"metadata": map[string]any{
			"account_id": "acct_123",
		},
		"access_token":  "token-1",
		"refresh_token": "refresh-1",
	}

	if !service.LooksLikeCodex("codex-user.json", payload) {
		t.Fatalf("expected codex payload to be detected")
	}

	fields := service.ExtractAuthFields(payload)
	if fields.Email != "user@example.com" || fields.AccountID != "acct_123" || fields.AccessToken != "token-1" {
		t.Fatalf("unexpected extracted fields: %+v", fields)
	}
}

func TestDeleteFilesRejectsOutsideAllowedRoots(t *testing.T) {
	t.Parallel()

	service := NewService()
	baseDir := t.TempDir()
	allowedDir := filepath.Join(baseDir, "allowed")
	outsideDir := filepath.Join(baseDir, "outside")
	if err := os.MkdirAll(allowedDir, 0o755); err != nil {
		t.Fatalf("mkdir allowed: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}

	outsideFile := filepath.Join(outsideDir, "bad.json")
	if err := os.WriteFile(outsideFile, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	deleted, deleteErrors := service.DeleteFiles([]string{outsideFile}, []string{allowedDir})
	if len(deleted) != 0 {
		t.Fatalf("expected no deleted files, got %v", deleted)
	}
	if len(deleteErrors) != 1 {
		t.Fatalf("expected one delete error, got %d", len(deleteErrors))
	}
}
