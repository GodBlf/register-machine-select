---
name: tempmail-lol-integration
description: Implement tempmail.lol temporary mailbox workflows for creating disposable inboxes, storing the inbox token, polling inbox state, and extracting verification codes or OTP emails. Use when a project needs tempmail.lol integration, 临时邮箱创建, inbox polling, OpenAI email verification retrieval, or reusable code/scripts for temp email flows in Python or other backends.
---

# Tempmail.lol Integration

## Overview

Use this skill to add or refine a `tempmail.lol` integration in any project. Follow the same minimal workflow used in this repository: create an inbox, persist the returned token, poll the inbox, combine message fields, and extract the verification code with a regex.

## Workflow

### 1. Decide whether to reuse or recreate

- Reuse an existing client if the current repository already talks to `tempmail.lol`.
- Recreate only the minimal flow if no client exists yet.
- Read [references/workflow.md](./references/workflow.md) for endpoint details, response shapes, and edge cases.
- Use [scripts/tempmail_lol_client.py](./scripts/tempmail_lol_client.py) as a runnable Python example when you need a quick implementation baseline.

### 2. Create the inbox

- `POST {base_url}/inbox/create` with an empty JSON body.
- Send `Accept: application/json`, `Content-Type: application/json`, and a non-empty `User-Agent`.
- Expect `address` and `token` in the response.
- Persist the `token` together with the email address for the whole verification session.

### 3. Poll the inbox

- `GET {base_url}/inbox?token=...`.
- Treat `token` as the per-inbox credential.
- Keep polling until timeout, inbox expiry, or a matching message arrives.
- Use a seen-message set keyed by `date`, `id`, or another stable field to avoid processing the same email repeatedly.

### 4. Extract the verification code

- Concatenate `from`, `subject`, `body`, and `html`.
- If the flow is OpenAI-specific, optionally filter for messages mentioning `openai`.
- Use a six-digit regex by default: `(?<!\d)(\d{6})(?!\d)`.
- Return the first matching code and stop polling.

### 5. Preserve a stable interface

- Expose a create function that returns at least `{email, token}`.
- Expose an inbox fetch function that returns the raw inbox payload.
- Expose a wait function that accepts `token`, `timeout`, `poll_interval`, and `pattern`.
- Fail fast if `address` or `token` is missing from the create response.

### 6. Validate before shipping

- Run the example script with `create` to confirm the API path still works.
- Verify the polling loop handles empty inboxes and timeout cleanly.
- If the target project already has its own HTTP layer, keep the skill logic and adapt only transport details.

## Important Notes

- On 2026-03-22, a plain `urllib` request without `User-Agent` returned `403`, while the same request succeeded once `User-Agent` was set. Do not omit the header.
- In this repository, the working implementation lives in `src/services/tempmail.py`, and the shared transport wrapper lives in `src/core/http_client.py`.
- This repository does not use a global tempmail.lol API key. The only credential in the workflow is the inbox-scoped `token` returned by `/inbox/create`.

## Resources

- [references/workflow.md](./references/workflow.md): endpoint contract, polling rules, OTP extraction strategy, and mapping back to this repository.
- [scripts/tempmail_lol_client.py](./scripts/tempmail_lol_client.py): standalone Python example for inbox creation and code polling.
