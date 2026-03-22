# tempmail.lol Workflow Reference

## Scope

Use this reference when implementing the `tempmail.lol` flow in a new project or when aligning another codebase with the behavior already used in this repository.

This reference is based on:

- The repository implementation in `src/services/tempmail.py`
- The shared transport wrapper in `src/core/http_client.py`
- Live checks performed on 2026-03-22 against `https://api.tempmail.lol/v2`

## API Contract

### Base URL

Default base URL:

```text
https://api.tempmail.lol/v2
```

### Create inbox

Request:

```http
POST /inbox/create
Accept: application/json
Content-Type: application/json
User-Agent: curl/8.0.0

{}
```

Observed response shape on 2026-03-22:

```json
{
  "address": "random-name@example-domain.tld",
  "token": "per_inbox_token_here"
}
```

Implementation requirements:

- Reject the response if `address` is missing or blank.
- Reject the response if `token` is missing or blank.
- Store both values together for the rest of the registration flow.

### Read inbox

Request:

```http
GET /inbox?token=<token>
Accept: application/json
User-Agent: curl/8.0.0
```

Observed empty-inbox response on 2026-03-22:

```json
{
  "emails": [],
  "expired": false
}
```

Implementation requirements:

- Treat `token` as the inbox identifier and access credential.
- Expect `emails` to be a list when the inbox is still valid.
- Treat `expired: true` as terminal.
- If the API returns an empty object or `None`, treat the inbox as expired or unusable.

## Polling Algorithm

Recommended defaults:

- `timeout = 120`
- `poll_interval = 3`
- `pattern = (?<!\d)(\d{6})(?!\d)`

Recommended loop:

1. Record `deadline = now + timeout`.
2. Fetch `/inbox?token=...`.
3. Stop early if the inbox is expired.
4. Iterate over `emails`.
5. De-duplicate using `date`, then `id`, then a serialized fallback if needed.
6. Build a combined text blob from `from`, `subject`, `body`, and `html`.
7. Apply any sender/content filter.
8. Run the regex against the combined text.
9. Return the first matching code.
10. Sleep `poll_interval` seconds and continue until timeout.

## OTP Extraction Strategy

The repository implementation extracts the code from a merged string:

```text
sender + "\n" + subject + "\n" + body + "\n" + html
```

That strategy is deliberate:

- Some providers place the OTP only in `html`.
- Some providers leave `body` blank.
- Filtering only one field misses valid emails.

For OpenAI-specific flows:

- Prefer filtering on `openai` in sender or combined content before applying the regex.

Default regex used in this repository:

```python
r"(?<!\d)(\d{6})(?!\d)"
```

That matches a standalone six-digit code and avoids longer numeric strings.

## Transport Notes

Important live finding from 2026-03-22:

- `urllib` without a `User-Agent` returned `403 Forbidden`
- `urllib` with `User-Agent: curl/8.0.0` succeeded

Practical guidance:

- Always send a non-empty `User-Agent`
- Reuse an existing HTTP client abstraction if the project already has one
- If a site blocks a bare client, switch to a more browser-like HTTP stack or set a realistic user agent before rewriting the whole integration

In this repository:

- `src/core/http_client.py` uses `curl_cffi`
- The default request config impersonates Chrome
- `src/services/tempmail.py` relies on that shared client

## Minimal Data Model

Return at least this shape from inbox creation:

```json
{
  "email": "generated@domain.tld",
  "token": "inbox_token",
  "service_id": "inbox_token"
}
```

Why:

- `email` is needed for registration
- `token` is needed for inbox polling
- `service_id` keeps the integration compatible with systems that expect a stable service identifier

## Error Handling Rules

- Raise immediately if create returns a non-200/201 status.
- Raise immediately if create succeeds but omits `address` or `token`.
- Retry polling failures that are transient.
- Return `None` on timeout rather than fabricating a code.
- Log enough context to distinguish HTTP failure, timeout, and inbox expiry.

## Mapping Back to This Repository

Primary implementation:

- `src/services/tempmail.py`

Supporting files:

- `src/core/http_client.py`
- `src/config/constants.py`
- `src/web/routes/settings.py`
- `src/web/routes/registration.py`

Useful constants and behavior:

- Default regex: `src/config/constants.py`
- Settings-backed base URL, timeout, retries: `src/config/settings.py`
- Default base URL in this repo: `https://api.tempmail.lol/v2`

## Reuse Checklist

- Add create inbox support
- Persist the inbox token
- Add inbox polling
- Add combined-field OTP extraction
- Expose timeout and poll interval as parameters
- Set a non-empty `User-Agent`
- Test create flow before wiring the full registration path
