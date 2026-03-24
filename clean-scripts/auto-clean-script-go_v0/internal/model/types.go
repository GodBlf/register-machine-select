package model

import "time"

type AuthFields struct {
	Provider     string
	Email        string
	AccessToken  string
	RefreshToken string
	AccountID    string
	BaseURL      string
}

type ScanRequest struct {
	AuthDir            *string  `json:"auth_dir"`
	ExceededDir        *string  `json:"exceeded_dir"`
	Workers            *int     `json:"workers"`
	TimeoutSeconds     *float64 `json:"timeout_seconds"`
	Model              *string  `json:"model"`
	RefreshBeforeCheck *bool    `json:"refresh_before_check"`
	NoQuarantine       *bool    `json:"no_quarantine"`
	Delete401          *bool    `json:"delete_401"`
}

type Delete401Request struct {
	Files []string `json:"files"`
}

type ScanOptions struct {
	AuthDir            string
	ExceededDir        string
	Workers            int
	Timeout            time.Duration
	Model              string
	RefreshBeforeCheck bool
	NoQuarantine       bool
	Delete401          bool
	BaseURL            string
	QuotaPath          string
	RefreshURL         string
	RetryAttempts      int
	RetryBackoff       time.Duration
	ClientID           string
	Version            string
	UserAgent          string
}

type ScanDefaultsResponse struct {
	AuthDir            string  `json:"auth_dir"`
	ExceededDir        string  `json:"exceeded_dir"`
	Workers            int     `json:"workers"`
	TimeoutSeconds     float64 `json:"timeout_seconds"`
	ScheduleInterval   int     `json:"schedule_interval_seconds"`
	Model              string  `json:"model"`
	RefreshBeforeCheck bool    `json:"refresh_before_check"`
	NoQuarantine       bool    `json:"no_quarantine"`
	Delete401          bool    `json:"delete_401"`
}

type CheckResult struct {
	File             string `json:"file"`
	Provider         string `json:"provider"`
	Email            string `json:"email"`
	AccountID        string `json:"account_id"`
	StatusCode       *int   `json:"status_code"`
	Unauthorized401  bool   `json:"unauthorized_401"`
	NoLimitUnlimited bool   `json:"no_limit_unlimited"`
	QuotaExceeded    bool   `json:"quota_exceeded"`
	QuotaResetsAt    *int64 `json:"quota_resets_at"`
	Error            string `json:"error"`
	ResponsePreview  string `json:"response_preview"`
}

type DeleteError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type QuarantineSummary struct {
	Enabled                 bool          `json:"enabled"`
	ExceededDir             string        `json:"exceeded_dir"`
	MovedToExceeded         []string      `json:"moved_to_exceeded"`
	MovedToExceededErrors   []DeleteError `json:"moved_to_exceeded_errors"`
	MovedFromExceeded       []string      `json:"moved_from_exceeded"`
	MovedFromExceededErrors []DeleteError `json:"moved_from_exceeded_errors"`
}

type DeletionSummary struct {
	Requested    bool          `json:"requested"`
	TargetCount  int           `json:"target_count"`
	Confirmed    bool          `json:"confirmed"`
	DeletedCount int           `json:"deleted_count"`
	DeletedFiles []string      `json:"deleted_files"`
	Errors       []DeleteError `json:"errors"`
}

type ProgressEvent struct {
	Type     string `json:"type"`
	Stage    string `json:"stage,omitempty"`
	Current  int    `json:"current"`
	Total    int    `json:"total"`
	Filename string `json:"filename"`
}

type ErrorEvent struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type ScanFinalEvent struct {
	Type               string            `json:"type"`
	Results            []CheckResult     `json:"results"`
	ExceededDirResults []CheckResult     `json:"exceeded_dir_results"`
	Quarantine         QuarantineSummary `json:"quarantine"`
	Deletion           DeletionSummary   `json:"deletion"`
}

type ScheduleStatus struct {
	Enabled         bool       `json:"enabled"`
	IntervalSeconds int        `json:"interval_seconds"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	LastOutcome     string     `json:"last_outcome"`
	LastError       string     `json:"last_error,omitempty"`
}

type StatusResponse struct {
	Running      bool           `json:"running"`
	HasResult    bool           `json:"has_result"`
	LastResultAt *time.Time     `json:"last_result_at,omitempty"`
	Schedule     ScheduleStatus `json:"schedule"`
}
