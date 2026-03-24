package scanner

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/example/clean-script-go/internal/codex"
	"github.com/example/clean-script-go/internal/fileops"
	"github.com/example/clean-script-go/internal/model"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewService),
)

type Service struct {
	files  *fileops.Service
	client *codex.Client
}

func NewService(files *fileops.Service, client *codex.Client) *Service {
	return &Service{files: files, client: client}
}

func (s *Service) Scan(ctx context.Context, options model.ScanOptions, publish func(model.ProgressEvent)) (model.ScanFinalEvent, error) {
	probeBody, err := codex.BuildProbeBody(options.Model)
	if err != nil {
		return model.ScanFinalEvent{}, fmt.Errorf("build probe body: %w", err)
	}

	files, err := s.files.ListJSONFilesRecursive(options.AuthDir)
	if err != nil {
		return model.ScanFinalEvent{}, fmt.Errorf("list auth files: %w", err)
	}

	results, err := s.scanFileList(ctx, files, options, probeBody, publish, "scan")
	if err != nil {
		return model.ScanFinalEvent{}, err
	}

	quarantine := model.QuarantineSummary{
		Enabled:                 !options.NoQuarantine,
		ExceededDir:             options.ExceededDir,
		MovedToExceeded:         []string{},
		MovedToExceededErrors:   []model.DeleteError{},
		MovedFromExceeded:       []string{},
		MovedFromExceededErrors: []model.DeleteError{},
	}

	if !options.NoQuarantine {
		for _, item := range results {
			if !item.QuotaExceeded {
				continue
			}
			dst, moveErr := s.files.MoveFileSafely(item.File, options.ExceededDir, []string{options.AuthDir, options.ExceededDir})
			if moveErr != nil {
				quarantine.MovedToExceededErrors = append(quarantine.MovedToExceededErrors, model.DeleteError{
					File:  item.File,
					Error: moveErr.Error(),
				})
				continue
			}
			quarantine.MovedToExceeded = append(quarantine.MovedToExceeded, dst)
		}
	}

	exceededFiles, err := s.files.ListJSONFilesFlat(options.ExceededDir)
	if err != nil {
		return model.ScanFinalEvent{}, fmt.Errorf("list exceeded files: %w", err)
	}

	exceededResults := make([]model.CheckResult, 0)
	if !options.NoQuarantine && len(exceededFiles) > 0 {
		exceededResults, err = s.scanFileList(ctx, exceededFiles, options, probeBody, publish, "recovery")
		if err != nil {
			return model.ScanFinalEvent{}, err
		}
		for _, item := range exceededResults {
			if item.QuotaExceeded || item.StatusCode == nil {
				continue
			}
			if *item.StatusCode < http.StatusOK || *item.StatusCode >= http.StatusMultipleChoices {
				continue
			}
			dst, moveErr := s.files.MoveFileSafely(item.File, options.AuthDir, []string{options.AuthDir, options.ExceededDir})
			if moveErr != nil {
				quarantine.MovedFromExceededErrors = append(quarantine.MovedFromExceededErrors, model.DeleteError{
					File:  item.File,
					Error: moveErr.Error(),
				})
				continue
			}
			quarantine.MovedFromExceeded = append(quarantine.MovedFromExceeded, dst)
		}
	}

	unauthorizedFiles := make([]string, 0)
	for _, item := range results {
		if item.Unauthorized401 {
			unauthorizedFiles = append(unauthorizedFiles, item.File)
		}
	}

	deletion := model.DeletionSummary{
		Requested:    options.Delete401,
		TargetCount:  len(unauthorizedFiles),
		Confirmed:    false,
		DeletedCount: 0,
		DeletedFiles: []string{},
		Errors:       []model.DeleteError{},
	}
	if options.Delete401 && len(unauthorizedFiles) > 0 {
		deletion.Confirmed = true
		deletedFiles, deleteErrors := s.files.DeleteFiles(unauthorizedFiles, []string{options.AuthDir, options.ExceededDir})
		deletion.DeletedFiles = deletedFiles
		deletion.DeletedCount = len(deletedFiles)
		deletion.Errors = deleteErrors
	}

	return model.ScanFinalEvent{
		Type:               "final",
		Results:            results,
		ExceededDirResults: exceededResults,
		Quarantine:         quarantine,
		Deletion:           deletion,
	}, nil
}

func (s *Service) scanFileList(ctx context.Context, files []string, options model.ScanOptions, probeBody []byte, publish func(model.ProgressEvent), stage string) ([]model.CheckResult, error) {
	if len(files) == 0 {
		return []model.CheckResult{}, nil
	}

	workers := options.Workers
	if workers > len(files) {
		workers = len(files)
	}
	type job struct {
		index int
		path  string
	}
	type resultGroup struct {
		index   int
		results []model.CheckResult
	}

	jobs := make(chan job)
	results := make(chan resultGroup, len(files))
	var completed atomic.Int64
	var workerWG sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for item := range jobs {
				fileResults := s.scanSingleFile(ctx, item.path, options, probeBody)
				current := int(completed.Add(1))
				if publish != nil {
					publish(model.ProgressEvent{
						Type:     "progress",
						Stage:    stage,
						Current:  current,
						Total:    len(files),
						Filename: filepath.Base(item.path),
					})
				}

				select {
				case <-ctx.Done():
					return
				case results <- resultGroup{index: item.index, results: fileResults}:
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index, path := range files {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{index: index, path: path}:
			}
		}
	}()

	go func() {
		workerWG.Wait()
		close(results)
	}()

	ordered := make([][]model.CheckResult, len(files))
	for group := range results {
		ordered[group.index] = group.results
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	flattened := make([]model.CheckResult, 0, len(files))
	for _, group := range ordered {
		if len(group) == 0 {
			continue
		}
		flattened = append(flattened, group...)
	}
	return flattened, nil
}

func (s *Service) scanSingleFile(ctx context.Context, path string, options model.ScanOptions, probeBody []byte) []model.CheckResult {
	payload, err := s.files.LoadJSONFile(path)
	if err != nil {
		return []model.CheckResult{makeErrorResult(path, model.AuthFields{Provider: "unknown"}, fmt.Sprintf("parse error: %v", err))}
	}
	if !s.files.LooksLikeCodex(path, payload) {
		return nil
	}

	fields := s.files.ExtractAuthFields(payload)
	if options.RefreshBeforeCheck && fields.RefreshToken != "" {
		refreshedToken, _, refreshErr := s.client.RefreshAccessToken(ctx, options, fields.RefreshToken)
		if refreshErr != nil {
			return []model.CheckResult{makeErrorResult(path, fields, refreshErr.Error())}
		}
		fields.AccessToken = refreshedToken
	}
	if fields.AccessToken == "" {
		return []model.CheckResult{makeErrorResult(path, fields, "missing access token")}
	}

	probeResult, err := s.client.Probe(ctx, options, fields, probeBody)
	if err != nil {
		return []model.CheckResult{makeErrorResult(path, fields, fmt.Sprintf("network error: %v", err))}
	}

	statusCode := probeResult.StatusCode
	return []model.CheckResult{
		{
			File:             path,
			Provider:         fields.Provider,
			Email:            fields.Email,
			AccountID:        fields.AccountID,
			StatusCode:       &statusCode,
			Unauthorized401:  probeResult.Unauthorized401,
			NoLimitUnlimited: probeResult.NoLimitUnlimited,
			QuotaExceeded:    probeResult.QuotaExceeded,
			QuotaResetsAt:    probeResult.QuotaResetsAt,
			Error:            "",
			ResponsePreview:  probeResult.ResponsePreview,
		},
	}
}

func makeErrorResult(file string, fields model.AuthFields, message string) model.CheckResult {
	provider := fields.Provider
	if provider == "" {
		provider = "unknown"
	}
	return model.CheckResult{
		File:             file,
		Provider:         provider,
		Email:            fields.Email,
		AccountID:        fields.AccountID,
		StatusCode:       nil,
		Unauthorized401:  false,
		NoLimitUnlimited: false,
		QuotaExceeded:    false,
		QuotaResetsAt:    nil,
		Error:            message,
		ResponsePreview:  "",
	}
}
