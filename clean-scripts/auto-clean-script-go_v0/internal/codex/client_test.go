package codex

import "testing"

func TestDetectQuotaExceeded(t *testing.T) {
	t.Parallel()

	text := `{"error":{"type":"usage_limit_reached","resets_at":1740000000}}`
	exceeded, resetsAt := detectQuotaExceeded(text)
	if !exceeded {
		t.Fatalf("expected quota exceeded")
	}
	if resetsAt == nil || *resetsAt != 1740000000 {
		t.Fatalf("unexpected resets_at: %#v", resetsAt)
	}
}

func TestLooksUnlimitedFromResponse(t *testing.T) {
	t.Parallel()

	text := `{"quota":{"daily_limit":null},"plan":{"unlimited":true}}`
	if !looksUnlimitedFromResponse(200, text) {
		t.Fatalf("expected unlimited response detection")
	}
	if looksUnlimitedFromResponse(401, text) {
		t.Fatalf("unexpected unlimited detection for non-2xx response")
	}
}
