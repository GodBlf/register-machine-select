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

func TestDefaultsResponseIncludesScheduleInterval(t *testing.T) {
	t.Parallel()

	cfg := AppConfig{
		Scan: ScanSection{
			AuthDir:          filepath.Join("C:", "tmp", "default-auth"),
			ExceededDir:      "",
			Model:            "gpt-5",
			Workers:          10,
			TimeoutSeconds:   20,
			ScheduleInterval: 180,
		},
	}

	defaults := DefaultsResponse(cfg)
	if defaults.ScheduleInterval != 180 {
		t.Fatalf("expected schedule interval 180, got %d", defaults.ScheduleInterval)
	}
}

func TestValidateAndNormalizeRejectsNegativeScheduleInterval(t *testing.T) {
	t.Parallel()

	cfg := AppConfig{
		App: AppSection{
			Host:                "127.0.0.1",
			Port:                8000,
			ReadTimeoutSeconds:  30,
			WriteTimeoutSeconds: 30,
		},
		Scan: ScanSection{
			AuthDir:          ".",
			ExceededDir:      "",
			Model:            "gpt-5",
			Workers:          10,
			TimeoutSeconds:   20,
			ScheduleInterval: -1,
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
		Web: WebSection{
			AllowOrigins: []string{"*"},
		},
	}

	if err := validateAndNormalize(&cfg); err == nil {
		t.Fatalf("expected negative schedule interval to be rejected")
	}
}
