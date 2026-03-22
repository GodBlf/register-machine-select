package config

import (
	"path/filepath"
	"testing"

	"github.com/example/clean-script-go/internal/model"
)

func TestBuildScanOptionsDerivesExceededDirFromEffectiveAuthDir(t *testing.T) {
	t.Parallel()

	cfg := AppConfig{
		Scan: ScanSection{
			AuthDir:        filepath.Join("C:", "tmp", "default-auth"),
			ExceededDir:    "",
			Model:          "gpt-5",
			Workers:        10,
			TimeoutSeconds: 20,
		},
		HTTPClient: HTTPClientSection{
			CodexBaseURL:        "https://example.com",
			QuotaPath:           "/responses",
			RefreshURL:          "https://auth.example.com",
			RetryAttempts:       3,
			RetryBackoffSeconds: 0.5,
			ClientID:            "client-id",
			Version:             "0.98.0",
			UserAgent:           "test-agent",
		},
	}

	override := filepath.Join("D:", "work", "auths")
	options, err := BuildScanOptions(cfg, model.ScanRequest{AuthDir: &override})
	if err != nil {
		t.Fatalf("BuildScanOptions returned error: %v", err)
	}

	expectedExceeded := filepath.Join(filepath.Dir(options.AuthDir), defaultExceededDirName)
	if options.ExceededDir != expectedExceeded {
		t.Fatalf("expected exceeded dir %q, got %q", expectedExceeded, options.ExceededDir)
	}
}
