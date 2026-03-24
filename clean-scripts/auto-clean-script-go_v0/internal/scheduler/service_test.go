package scheduler

import (
	"errors"
	"testing"
	"time"

	"github.com/example/clean-script-go/internal/manager"
	"github.com/example/clean-script-go/internal/model"
)

func TestTriggerStartsScanAndUpdatesStatus(t *testing.T) {
	t.Parallel()

	called := false
	service := &Service{
		intervalSeconds: 60,
		buildOptions: func() (model.ScanOptions, error) {
			return model.ScanOptions{AuthDir: "auth", ExceededDir: "exceeded"}, nil
		},
		startScan: func(options model.ScanOptions) error {
			called = true
			if options.AuthDir != "auth" {
				t.Fatalf("unexpected auth dir: %q", options.AuthDir)
			}
			return nil
		},
		lastOutcome: "waiting",
	}

	triggerAt := time.Date(2026, 3, 24, 10, 0, 0, 0, time.UTC)
	service.trigger(triggerAt)

	if !called {
		t.Fatalf("expected scheduled scan to be started")
	}

	status := service.Status()
	if status.LastOutcome != "started" {
		t.Fatalf("expected last outcome to be started, got %q", status.LastOutcome)
	}
	if status.LastTriggeredAt == nil || !status.LastTriggeredAt.Equal(triggerAt) {
		t.Fatalf("expected last triggered time to be %v, got %v", triggerAt, status.LastTriggeredAt)
	}
}

func TestTriggerMarksBusySkip(t *testing.T) {
	t.Parallel()

	service := &Service{
		intervalSeconds: 60,
		buildOptions: func() (model.ScanOptions, error) {
			return model.ScanOptions{}, nil
		},
		startScan: func(model.ScanOptions) error {
			return manager.ErrScanAlreadyRunning
		},
		lastOutcome: "waiting",
	}

	service.trigger(time.Now())

	status := service.Status()
	if status.LastOutcome != "skipped_busy" {
		t.Fatalf("expected skipped_busy, got %q", status.LastOutcome)
	}
	if status.LastError != "" {
		t.Fatalf("expected empty error message, got %q", status.LastError)
	}
}

func TestTriggerRecordsBuildError(t *testing.T) {
	t.Parallel()

	service := &Service{
		intervalSeconds: 60,
		buildOptions: func() (model.ScanOptions, error) {
			return model.ScanOptions{}, errors.New("bad config")
		},
		startScan: func(model.ScanOptions) error {
			t.Fatal("startScan should not be called when buildOptions fails")
			return nil
		},
		lastOutcome: "waiting",
	}

	service.trigger(time.Now())

	status := service.Status()
	if status.LastOutcome != "error" {
		t.Fatalf("expected error outcome, got %q", status.LastOutcome)
	}
	if status.LastError != "bad config" {
		t.Fatalf("expected bad config error, got %q", status.LastError)
	}
}
