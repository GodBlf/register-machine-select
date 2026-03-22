package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/clean-script-go/internal/model"
	"github.com/spf13/viper"
	"go.uber.org/fx"
)

const defaultExceededDirName = "exceeded"

type AppConfig struct {
	App        AppSection        `mapstructure:"app"`
	Scan       ScanSection       `mapstructure:"scan"`
	HTTPClient HTTPClientSection `mapstructure:"http_client"`
	Web        WebSection        `mapstructure:"web"`
}

type AppSection struct {
	Host                string `mapstructure:"host"`
	Port                int    `mapstructure:"port"`
	ReadTimeoutSeconds  int    `mapstructure:"read_timeout_seconds"`
	WriteTimeoutSeconds int    `mapstructure:"write_timeout_seconds"`
}

type ScanSection struct {
	AuthDir            string  `mapstructure:"auth_dir"`
	ExceededDir        string  `mapstructure:"exceeded_dir"`
	Model              string  `mapstructure:"model"`
	Workers            int     `mapstructure:"workers"`
	TimeoutSeconds     float64 `mapstructure:"timeout_seconds"`
	RefreshBeforeCheck bool    `mapstructure:"refresh_before_check"`
	NoQuarantine       bool    `mapstructure:"no_quarantine"`
	Delete401          bool    `mapstructure:"delete_401"`
}

type HTTPClientSection struct {
	CodexBaseURL        string  `mapstructure:"codex_base_url"`
	QuotaPath           string  `mapstructure:"quota_path"`
	RefreshURL          string  `mapstructure:"refresh_url"`
	RetryAttempts       int     `mapstructure:"retry_attempts"`
	RetryBackoffSeconds float64 `mapstructure:"retry_backoff_seconds"`
	ClientID            string  `mapstructure:"client_id"`
	Version             string  `mapstructure:"version"`
	UserAgent           string  `mapstructure:"user_agent"`
}

type WebSection struct {
	AllowOrigins []string `mapstructure:"allow_origins"`
}

var Module = fx.Options(
	fx.Provide(Load),
)

func Load() (AppConfig, error) {
	v := viper.New()
	setDefaults(v)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.SetEnvPrefix("CLEAN_SCRIPT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return AppConfig{}, fmt.Errorf("read config: %w", err)
	}

	var cfg AppConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return AppConfig{}, fmt.Errorf("decode config: %w", err)
	}
	if err := validateAndNormalize(&cfg); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func DefaultsResponse(cfg AppConfig) model.ScanDefaultsResponse {
	exceededDir := cfg.Scan.ExceededDir
	if strings.TrimSpace(exceededDir) == "" {
		exceededDir = filepath.Join(filepath.Dir(cfg.Scan.AuthDir), defaultExceededDirName)
	}
	return model.ScanDefaultsResponse{
		AuthDir:            cfg.Scan.AuthDir,
		ExceededDir:        exceededDir,
		Workers:            cfg.Scan.Workers,
		TimeoutSeconds:     cfg.Scan.TimeoutSeconds,
		Model:              cfg.Scan.Model,
		RefreshBeforeCheck: cfg.Scan.RefreshBeforeCheck,
		NoQuarantine:       cfg.Scan.NoQuarantine,
		Delete401:          cfg.Scan.Delete401,
	}
}

func BuildScanOptions(cfg AppConfig, req model.ScanRequest) (model.ScanOptions, error) {
	authDir := cfg.Scan.AuthDir
	if req.AuthDir != nil {
		authDir = *req.AuthDir
	}
	var err error
	authDir, err = normalizePath(authDir)
	if err != nil {
		return model.ScanOptions{}, fmt.Errorf("normalize auth_dir: %w", err)
	}

	exceededDir := cfg.Scan.ExceededDir
	if req.ExceededDir != nil {
		exceededDir = *req.ExceededDir
	}
	if strings.TrimSpace(exceededDir) == "" {
		exceededDir = filepath.Join(filepath.Dir(authDir), defaultExceededDirName)
	}
	exceededDir, err = normalizePath(exceededDir)
	if err != nil {
		return model.ScanOptions{}, fmt.Errorf("normalize exceeded_dir: %w", err)
	}

	modelName := cfg.Scan.Model
	if req.Model != nil {
		modelName = strings.TrimSpace(*req.Model)
	}
	if modelName == "" {
		return model.ScanOptions{}, fmt.Errorf("model must not be empty")
	}

	workers := cfg.Scan.Workers
	if req.Workers != nil {
		workers = *req.Workers
	}
	if workers < 1 {
		return model.ScanOptions{}, fmt.Errorf("workers must be >= 1")
	}

	timeoutSeconds := cfg.Scan.TimeoutSeconds
	if req.TimeoutSeconds != nil {
		timeoutSeconds = *req.TimeoutSeconds
	}
	if timeoutSeconds <= 0 {
		return model.ScanOptions{}, fmt.Errorf("timeout_seconds must be > 0")
	}

	refreshBeforeCheck := cfg.Scan.RefreshBeforeCheck
	if req.RefreshBeforeCheck != nil {
		refreshBeforeCheck = *req.RefreshBeforeCheck
	}

	noQuarantine := cfg.Scan.NoQuarantine
	if req.NoQuarantine != nil {
		noQuarantine = *req.NoQuarantine
	}

	delete401 := cfg.Scan.Delete401
	if req.Delete401 != nil {
		delete401 = *req.Delete401
	}

	if cfg.HTTPClient.RetryAttempts < 1 {
		return model.ScanOptions{}, fmt.Errorf("http_client.retry_attempts must be >= 1")
	}
	if cfg.HTTPClient.RetryBackoffSeconds < 0 {
		return model.ScanOptions{}, fmt.Errorf("http_client.retry_backoff_seconds must be >= 0")
	}

	return model.ScanOptions{
		AuthDir:            authDir,
		ExceededDir:        exceededDir,
		Workers:            workers,
		Timeout:            time.Duration(timeoutSeconds * float64(time.Second)),
		Model:              modelName,
		RefreshBeforeCheck: refreshBeforeCheck,
		NoQuarantine:       noQuarantine,
		Delete401:          delete401,
		BaseURL:            strings.TrimSpace(cfg.HTTPClient.CodexBaseURL),
		QuotaPath:          strings.TrimSpace(cfg.HTTPClient.QuotaPath),
		RefreshURL:         strings.TrimSpace(cfg.HTTPClient.RefreshURL),
		RetryAttempts:      cfg.HTTPClient.RetryAttempts,
		RetryBackoff:       time.Duration(cfg.HTTPClient.RetryBackoffSeconds * float64(time.Second)),
		ClientID:           strings.TrimSpace(cfg.HTTPClient.ClientID),
		Version:            strings.TrimSpace(cfg.HTTPClient.Version),
		UserAgent:          strings.TrimSpace(cfg.HTTPClient.UserAgent),
	}, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("app.host", "0.0.0.0")
	v.SetDefault("app.port", 8000)
	v.SetDefault("app.read_timeout_seconds", 30)
	v.SetDefault("app.write_timeout_seconds", 30)
	v.SetDefault("scan.auth_dir", "~/.cli-proxy-api")
	v.SetDefault("scan.exceeded_dir", "")
	v.SetDefault("scan.model", "gpt-5")
	v.SetDefault("scan.workers", 100)
	v.SetDefault("scan.timeout_seconds", 20.0)
	v.SetDefault("scan.refresh_before_check", false)
	v.SetDefault("scan.no_quarantine", false)
	v.SetDefault("scan.delete_401", false)
	v.SetDefault("http_client.codex_base_url", "https://chatgpt.com/backend-api/codex")
	v.SetDefault("http_client.quota_path", "/responses")
	v.SetDefault("http_client.refresh_url", "https://auth.openai.com/oauth/token")
	v.SetDefault("http_client.retry_attempts", 3)
	v.SetDefault("http_client.retry_backoff_seconds", 0.6)
	v.SetDefault("http_client.client_id", "app_EMoamEEZ73f0CkXaXp7hrann")
	v.SetDefault("http_client.version", "0.98.0")
	v.SetDefault("http_client.user_agent", "codex_cli_rs/0.98.0 (go-port)")
	v.SetDefault("web.allow_origins", []string{"*"})
}

func validateAndNormalize(cfg *AppConfig) error {
	var err error
	cfg.Scan.AuthDir, err = normalizePath(cfg.Scan.AuthDir)
	if err != nil {
		return fmt.Errorf("normalize scan.auth_dir: %w", err)
	}
	if strings.TrimSpace(cfg.Scan.ExceededDir) != "" {
		cfg.Scan.ExceededDir, err = normalizePath(cfg.Scan.ExceededDir)
		if err != nil {
			return fmt.Errorf("normalize scan.exceeded_dir: %w", err)
		}
	}

	if strings.TrimSpace(cfg.App.Host) == "" {
		return fmt.Errorf("app.host must not be empty")
	}
	if cfg.App.Port < 1 || cfg.App.Port > 65535 {
		return fmt.Errorf("app.port must be between 1 and 65535")
	}
	if cfg.App.ReadTimeoutSeconds <= 0 {
		return fmt.Errorf("app.read_timeout_seconds must be > 0")
	}
	if cfg.App.WriteTimeoutSeconds <= 0 {
		return fmt.Errorf("app.write_timeout_seconds must be > 0")
	}
	if cfg.Scan.Workers < 1 {
		return fmt.Errorf("scan.workers must be >= 1")
	}
	if cfg.Scan.TimeoutSeconds <= 0 {
		return fmt.Errorf("scan.timeout_seconds must be > 0")
	}
	if strings.TrimSpace(cfg.Scan.Model) == "" {
		return fmt.Errorf("scan.model must not be empty")
	}
	if strings.TrimSpace(cfg.HTTPClient.CodexBaseURL) == "" {
		return fmt.Errorf("http_client.codex_base_url must not be empty")
	}
	if strings.TrimSpace(cfg.HTTPClient.QuotaPath) == "" {
		return fmt.Errorf("http_client.quota_path must not be empty")
	}
	if strings.TrimSpace(cfg.HTTPClient.RefreshURL) == "" {
		return fmt.Errorf("http_client.refresh_url must not be empty")
	}
	if cfg.HTTPClient.RetryAttempts < 1 {
		return fmt.Errorf("http_client.retry_attempts must be >= 1")
	}
	if cfg.HTTPClient.RetryBackoffSeconds < 0 {
		return fmt.Errorf("http_client.retry_backoff_seconds must be >= 0")
	}
	if len(cfg.Web.AllowOrigins) == 0 {
		cfg.Web.AllowOrigins = []string{"*"}
	}
	return nil
}

func normalizePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		if path == "~" {
			path = homeDir
		} else {
			remainder := strings.TrimLeft(strings.TrimPrefix(path, "~"), `/\`)
			path = filepath.Join(homeDir, remainder)
		}
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}
