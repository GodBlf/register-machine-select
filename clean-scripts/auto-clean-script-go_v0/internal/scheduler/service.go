package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/example/clean-script-go/internal/config"
	"github.com/example/clean-script-go/internal/manager"
	"github.com/example/clean-script-go/internal/model"
	"github.com/example/clean-script-go/internal/scanner"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewService),
	fx.Invoke(Register),
)

type Service struct {
	intervalSeconds int
	interval        time.Duration
	buildOptions    func() (model.ScanOptions, error)
	startScan       func(model.ScanOptions) error

	mu              sync.RWMutex
	cancel          context.CancelFunc
	nextRunAt       *time.Time
	lastTriggeredAt *time.Time
	lastOutcome     string
	lastError       string
}

func NewService(cfg config.AppConfig, manager *manager.Manager, scanner *scanner.Service) *Service {
	service := &Service{
		intervalSeconds: cfg.Scan.ScheduleInterval,
		lastOutcome:     "disabled",
	}

	if cfg.Scan.ScheduleInterval > 0 {
		service.interval = time.Duration(cfg.Scan.ScheduleInterval) * time.Second
		service.lastOutcome = "waiting"
	}

	service.buildOptions = func() (model.ScanOptions, error) {
		return config.BuildScanOptions(cfg, model.ScanRequest{})
	}
	service.startScan = func(options model.ScanOptions) error {
		return manager.StartScan(options, func(ctx context.Context, publish func(model.ProgressEvent)) (model.ScanFinalEvent, error) {
			return scanner.Scan(ctx, options, publish)
		})
	}

	return service
}

func Register(lc fx.Lifecycle, service *Service) {
	lc.Append(fx.Hook{
		OnStart: service.onStart,
		OnStop:  service.onStop,
	})
}

func (s *Service) Status() model.ScheduleStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return model.ScheduleStatus{
		Enabled:         s.intervalSeconds > 0,
		IntervalSeconds: s.intervalSeconds,
		NextRunAt:       cloneTimePtr(s.nextRunAt),
		LastTriggeredAt: cloneTimePtr(s.lastTriggeredAt),
		LastOutcome:     s.lastOutcome,
		LastError:       s.lastError,
	}
}

func (s *Service) onStart(context.Context) error {
	if s.interval <= 0 {
		return nil
	}

	runCtx, cancel := context.WithCancel(context.Background())
	nextRun := time.Now().Add(s.interval)

	s.mu.Lock()
	s.cancel = cancel
	s.nextRunAt = &nextRun
	s.lastOutcome = "waiting"
	s.lastError = ""
	s.mu.Unlock()

	go s.loop(runCtx)
	return nil
}

func (s *Service) onStop(context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.nextRunAt = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

func (s *Service) loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case tickAt := <-ticker.C:
			nextRun := tickAt.Add(s.interval)
			s.mu.Lock()
			s.nextRunAt = &nextRun
			s.mu.Unlock()
			s.trigger(tickAt)
		}
	}
}

func (s *Service) trigger(now time.Time) {
	s.mu.Lock()
	s.lastTriggeredAt = &now
	s.lastError = ""
	s.mu.Unlock()

	options, err := s.buildOptions()
	if err != nil {
		s.setOutcome("error", err.Error())
		return
	}

	err = s.startScan(options)
	switch {
	case err == nil:
		s.setOutcome("started", "")
	case errors.Is(err, manager.ErrScanAlreadyRunning):
		s.setOutcome("skipped_busy", "")
	default:
		s.setOutcome("error", err.Error())
	}
}

func (s *Service) setOutcome(outcome, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastOutcome = outcome
	s.lastError = message
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
