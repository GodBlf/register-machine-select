package fileops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/example/clean-script-go/internal/model"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewService),
)

var providerKeys = []string{"type", "provider", "metadata.type"}
var emailKeys = []string{"email", "metadata.email", "attributes.email"}
var accessTokenKeys = []string{
	"access_token",
	"accessToken",
	"token.access_token",
	"token.accessToken",
	"metadata.access_token",
	"metadata.accessToken",
	"metadata.token.access_token",
	"metadata.token.accessToken",
	"attributes.api_key",
}
var refreshTokenKeys = []string{
	"refresh_token",
	"refreshToken",
	"token.refresh_token",
	"token.refreshToken",
	"metadata.refresh_token",
	"metadata.refreshToken",
	"metadata.token.refresh_token",
	"metadata.token.refreshToken",
}
var accountIDKeys = []string{
	"account_id",
	"accountId",
	"metadata.account_id",
	"metadata.accountId",
}
var baseURLKeys = []string{
	"base_url",
	"baseUrl",
	"metadata.base_url",
	"metadata.baseUrl",
	"attributes.base_url",
	"attributes.baseUrl",
}

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) ListJSONFilesRecursive(root string) ([]string, error) {
	rootPath, err := normalizePath(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", rootPath)
	}

	files := make([]string, 0, 32)
	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			files = append(files, filepath.Clean(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func (s *Service) ListJSONFilesFlat(root string) ([]string, error) {
	rootPath, err := normalizePath(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", rootPath)
	}

	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			files = append(files, filepath.Join(rootPath, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s *Service) LoadJSONFile(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("root JSON value is not an object")
	}
	return obj, nil
}

func (s *Service) LooksLikeCodex(path string, payload map[string]any) bool {
	provider := pick(payload, providerKeys)
	if provider != "" {
		return strings.EqualFold(provider, "codex")
	}
	if strings.HasPrefix(strings.ToLower(filepath.Base(path)), "codex-") {
		return true
	}

	accessToken := pick(payload, accessTokenKeys)
	refreshToken := pick(payload, refreshTokenKeys)
	accountID := pick(payload, accountIDKeys)
	return accessToken != "" && (refreshToken != "" || accountID != "")
}

func (s *Service) ExtractAuthFields(payload map[string]any) model.AuthFields {
	provider := pick(payload, providerKeys)
	if provider == "" {
		provider = "codex"
	}
	return model.AuthFields{
		Provider:     provider,
		Email:        pick(payload, emailKeys),
		AccessToken:  pick(payload, accessTokenKeys),
		RefreshToken: pick(payload, refreshTokenKeys),
		AccountID:    pick(payload, accountIDKeys),
		BaseURL:      pick(payload, baseURLKeys),
	}
}

func (s *Service) DeleteFiles(paths []string, allowedRoots []string) ([]string, []model.DeleteError) {
	deleted := make([]string, 0, len(paths))
	errors := make([]model.DeleteError, 0)
	seen := make(map[string]struct{}, len(paths))
	normalizedRoots := normalizeRoots(allowedRoots)

	for _, rawPath := range paths {
		normalizedPath, err := normalizePath(rawPath)
		if err != nil {
			errors = append(errors, model.DeleteError{File: rawPath, Error: err.Error()})
			continue
		}
		if _, ok := seen[normalizedPath]; ok {
			continue
		}
		seen[normalizedPath] = struct{}{}

		if len(normalizedRoots) > 0 && !isWithinAnyRoot(normalizedPath, normalizedRoots) {
			errors = append(errors, model.DeleteError{File: normalizedPath, Error: "path is outside allowed roots"})
			continue
		}
		if err := os.Remove(normalizedPath); err != nil {
			errors = append(errors, model.DeleteError{File: normalizedPath, Error: err.Error()})
			continue
		}
		deleted = append(deleted, normalizedPath)
	}
	return deleted, errors
}

func (s *Service) MoveFileSafely(src, dstDir string, allowedRoots []string) (string, error) {
	normalizedSrc, err := normalizePath(src)
	if err != nil {
		return "", err
	}
	normalizedDstDir, err := normalizePath(dstDir)
	if err != nil {
		return "", err
	}
	if len(allowedRoots) > 0 && !isWithinAnyRoot(normalizedSrc, normalizeRoots(allowedRoots)) {
		return "", fmt.Errorf("path is outside allowed roots")
	}

	if err := os.MkdirAll(normalizedDstDir, 0o755); err != nil {
		return "", err
	}

	baseName := filepath.Base(normalizedSrc)
	targetPath := filepath.Join(normalizedDstDir, baseName)
	ext := filepath.Ext(baseName)
	stem := strings.TrimSuffix(baseName, ext)

	counter := 1
	for pathExists(targetPath) {
		targetPath = filepath.Join(normalizedDstDir, fmt.Sprintf("%s_%d%s", stem, counter, ext))
		counter++
	}

	if err := os.Rename(normalizedSrc, targetPath); err != nil {
		if copyErr := copyFile(normalizedSrc, targetPath); copyErr != nil {
			return "", copyErr
		}
		if removeErr := os.Remove(normalizedSrc); removeErr != nil {
			return "", removeErr
		}
	}
	return targetPath, nil
}

func normalizePath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	absPath, err := filepath.Abs(trimmed)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}

func normalizeRoots(roots []string) []string {
	seen := make(map[string]struct{}, len(roots))
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		normalized, err := normalizePath(root)
		if err != nil || normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func isWithinAnyRoot(candidate string, roots []string) bool {
	for _, root := range roots {
		if isWithinRoot(candidate, root) {
			return true
		}
	}
	return false
}

func isWithinRoot(candidate, root string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func dotGet(data any, dottedKey string) any {
	current := data
	for _, key := range strings.Split(dottedKey, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = obj[key]
	}
	return current
}

func pick(data map[string]any, candidates []string) string {
	for _, candidate := range candidates {
		value := dotGet(data, candidate)
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
	}
	return ""
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return dstFile.Sync()
}
