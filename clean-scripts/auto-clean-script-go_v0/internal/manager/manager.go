package manager

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/example/clean-script-go/internal/model"
	"go.uber.org/fx"
)

var (
	ErrScanAlreadyRunning = errors.New("scan already running")
	Module                = fx.Options(
		fx.Provide(NewManager),
	)
)

type StreamMessage struct {
	Payload  []byte
	Terminal bool
}

type Runner func(context.Context, func(model.ProgressEvent)) (model.ScanFinalEvent, error)

type Manager struct {
	mu           sync.RWMutex
	running      bool
	subscribers  map[chan StreamMessage]struct{}
	lastResult   *StreamMessage
	lastResultAt *time.Time
	allowedRoots []string
}

func NewManager() *Manager {
	return &Manager{
		subscribers: make(map[chan StreamMessage]struct{}),
	}
}

func (m *Manager) StartScan(options model.ScanOptions, runner Runner) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrScanAlreadyRunning
	}
	m.running = true
	m.lastResult = nil
	m.lastResultAt = nil
	m.allowedRoots = []string{options.AuthDir, options.ExceededDir}
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
		}()

		finalEvent, err := runner(context.Background(), m.publishProgress)
		if err != nil {
			m.publishTerminal(model.ErrorEvent{Type: "error", Message: err.Error()})
			return
		}
		m.publishTerminal(finalEvent)
	}()
	return nil
}

func (m *Manager) Subscribe() chan StreamMessage {
	ch := make(chan StreamMessage, 16)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()
	return ch
}

func (m *Manager) Unsubscribe(ch chan StreamMessage) {
	m.mu.Lock()
	if _, ok := m.subscribers[ch]; ok {
		delete(m.subscribers, ch)
		close(ch)
	}
	m.mu.Unlock()
}

func (m *Manager) Status() (bool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running, m.lastResult != nil
}

type StatusSnapshot struct {
	Running      bool
	HasResult    bool
	LastResultAt *time.Time
}

func (m *Manager) Snapshot() StatusSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return StatusSnapshot{
		Running:      m.running,
		HasResult:    m.lastResult != nil,
		LastResultAt: cloneTimePtr(m.lastResultAt),
	}
}

func (m *Manager) LastResult() (StreamMessage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastResult == nil {
		return StreamMessage{}, false
	}
	return *m.lastResult, true
}

func (m *Manager) AllowedRoots(defaults ...string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.allowedRoots) > 0 {
		return append([]string(nil), m.allowedRoots...)
	}
	return append([]string(nil), defaults...)
}

func (m *Manager) publishProgress(event model.ProgressEvent) {
	m.publish(event, false)
}

func (m *Manager) publishTerminal(event any) {
	m.publish(event, true)
}

func (m *Manager) publish(event any, terminal bool) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}

	message := StreamMessage{Payload: payload, Terminal: terminal}
	m.mu.Lock()
	if terminal {
		now := time.Now()
		m.lastResult = &message
		m.lastResultAt = &now
	}
	for subscriber := range m.subscribers {
		select {
		case subscriber <- message:
		default:
		}
	}
	m.mu.Unlock()
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
