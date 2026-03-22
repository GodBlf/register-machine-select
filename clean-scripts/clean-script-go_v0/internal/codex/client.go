package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/example/clean-script-go/internal/model"
	"github.com/go-resty/resty/v2"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(NewClient),
)

var unlimitedTextMarkers = []string{
	"unlimited",
	"no limit",
	"no-limit",
	"without limit",
	"limitless",
	"不限额",
	"无限额",
	"无限制",
}

var unlimitedKeyHints = []string{"unlimited", "no_limit", "nolimit", "limitless"}
var limitLikeKeyHints = []string{"quota", "limit", "cap"}
var quotaExceededTextMarkers = []string{
	"usage_limit_reached",
	"usage limit has been reached",
	"quota exceeded",
	"limit exceeded",
	"超出配额",
	"额度已用完",
}

type ProbeResponse struct {
	StatusCode       int
	ResponseText     string
	ResponsePreview  string
	Unauthorized401  bool
	NoLimitUnlimited bool
	QuotaExceeded    bool
	QuotaResetsAt    *int64
}

type Client struct {
	http *resty.Client
}

func NewClient() *Client {
	client := resty.New()
	client.SetRetryCount(0)
	return &Client{http: client}
}

func BuildProbeBody(modelName string) ([]byte, error) {
	payload := map[string]any{
		"model":        modelName,
		"stream":       true,
		"store":        false,
		"instructions": "",
		"input": []map[string]any{
			{
				"role": "user",
				"content": []map[string]any{
					{
						"type": "input_text",
						"text": "ping",
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func (c *Client) RefreshAccessToken(ctx context.Context, options model.ScanOptions, refreshToken string) (string, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	resp, err := c.http.R().
		SetContext(reqCtx).
		SetHeader("Accept", "application/json").
		SetFormData(map[string]string{
			"client_id":     options.ClientID,
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
			"scope":         "openid profile email",
		}).
		Post(options.RefreshURL)
	if err != nil {
		return "", "", fmt.Errorf("refresh network error: %w", err)
	}
	if resp.StatusCode() != 200 {
		return "", "", fmt.Errorf("refresh failed with %d: %s", resp.StatusCode(), truncate(resp.String(), 300))
	}

	var payload map[string]any
	if err := json.Unmarshal(resp.Body(), &payload); err != nil {
		return "", "", fmt.Errorf("refresh response is not valid JSON: %w", err)
	}

	accessToken, _ := payload["access_token"].(string)
	refreshTokenValue, _ := payload["refresh_token"].(string)
	accessToken = strings.TrimSpace(accessToken)
	refreshTokenValue = strings.TrimSpace(refreshTokenValue)
	if accessToken == "" {
		return "", "", fmt.Errorf("refresh succeeded but access_token missing")
	}
	return accessToken, refreshTokenValue, nil
}

func (c *Client) Probe(ctx context.Context, options model.ScanOptions, fields model.AuthFields, probeBody []byte) (ProbeResponse, error) {
	url := strings.TrimRight(firstNonEmpty(fields.BaseURL, options.BaseURL), "/") + "/" + strings.TrimLeft(options.QuotaPath, "/")
	headers := map[string]string{
		"Authorization": "Bearer " + fields.AccessToken,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
		"Version":       options.Version,
		"Openai-Beta":   "responses=experimental",
		"User-Agent":    options.UserAgent,
		"Originator":    "codex_cli_rs",
	}
	if fields.AccountID != "" {
		headers["Chatgpt-Account-Id"] = fields.AccountID
	}

	var lastErr error
	for attempt := 1; attempt <= options.RetryAttempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, options.Timeout)
		resp, err := c.http.R().
			SetContext(reqCtx).
			SetHeaders(headers).
			SetBody(probeBody).
			Post(url)
		cancel()
		if err == nil {
			responseText := resp.String()
			quotaExceeded, resetsAt := detectQuotaExceeded(responseText)
			return ProbeResponse{
				StatusCode:       resp.StatusCode(),
				ResponseText:     responseText,
				ResponsePreview:  truncate(responseText, 300),
				Unauthorized401:  resp.StatusCode() == 401,
				NoLimitUnlimited: looksUnlimitedFromResponse(resp.StatusCode(), responseText),
				QuotaExceeded:    quotaExceeded,
				QuotaResetsAt:    resetsAt,
			}, nil
		}

		lastErr = err
		if attempt == options.RetryAttempts {
			break
		}
		if options.RetryBackoff > 0 {
			wait := options.RetryBackoff * time.Duration(1<<(attempt-1))
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ProbeResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return ProbeResponse{}, lastErr
}

func detectQuotaExceeded(responseText string) (bool, *int64) {
	if strings.TrimSpace(responseText) == "" {
		return false, nil
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(responseText), &payload); err == nil {
		if errBody, ok := payload["error"].(map[string]any); ok {
			if errType, _ := errBody["type"].(string); errType == "usage_limit_reached" {
				if resetsAt, ok := asInt64Pointer(errBody["resets_at"]); ok {
					return true, resetsAt
				}
				return true, nil
			}
		}
	}

	lowered := strings.ToLower(responseText)
	for _, marker := range quotaExceededTextMarkers {
		if strings.Contains(lowered, marker) {
			return true, nil
		}
	}
	return false, nil
}

func looksUnlimitedFromResponse(statusCode int, responseText string) bool {
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	lowered := strings.ToLower(responseText)
	for _, marker := range unlimitedTextMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}

	var payload any
	if err := json.Unmarshal([]byte(responseText), &payload); err != nil {
		return false
	}

	stack := []any{payload}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		switch value := current.(type) {
		case map[string]any:
			for key, entry := range value {
				keyLC := strings.ToLower(key)
				for _, hint := range unlimitedKeyHints {
					if strings.Contains(keyLC, hint) {
						if boolValue, ok := entry.(bool); ok && boolValue {
							return true
						}
						if textValue, ok := entry.(string); ok {
							switch strings.ToLower(strings.TrimSpace(textValue)) {
							case "1", "true", "yes", "unlimited", "no_limit", "nolimit":
								return true
							}
						}
						if numberValue, ok := asFloat64(entry); ok && numberValue == -1 {
							return true
						}
					}
				}
				for _, hint := range limitLikeKeyHints {
					if strings.Contains(keyLC, hint) {
						if entry == nil {
							return true
						}
						if numberValue, ok := asFloat64(entry); ok && (numberValue == -1 || numberValue >= 9999) {
							return true
						}
						if textValue, ok := entry.(string); ok {
							switch strings.ToLower(strings.TrimSpace(textValue)) {
							case "none", "null", "unlimited", "no limit", "no-limit", "无限", "不限额", "无限额":
								return true
							}
						}
					}
				}

				switch nested := entry.(type) {
				case map[string]any, []any:
					stack = append(stack, nested)
				case string:
					nestedLC := strings.ToLower(nested)
					for _, marker := range unlimitedTextMarkers {
						if strings.Contains(nestedLC, marker) {
							return true
						}
					}
				}
			}
		case []any:
			stack = append(stack, value...)
		}
	}
	return false
}

func asInt64Pointer(value any) (*int64, bool) {
	switch parsed := value.(type) {
	case int64:
		return &parsed, true
	case int:
		converted := int64(parsed)
		return &converted, true
	case float64:
		converted := int64(parsed)
		return &converted, true
	case json.Number:
		number, err := parsed.Int64()
		if err != nil {
			return nil, false
		}
		return &number, true
	default:
		return nil, false
	}
}

func asFloat64(value any) (float64, bool) {
	switch parsed := value.(type) {
	case float64:
		return parsed, true
	case float32:
		return float64(parsed), true
	case int:
		return float64(parsed), true
	case int64:
		return float64(parsed), true
	case json.Number:
		number, err := parsed.Float64()
		if err != nil {
			return 0, false
		}
		return number, true
	default:
		return 0, false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func truncate(text string, limit int) string {
	runes := []rune(text)
	if limit <= 0 || len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}
