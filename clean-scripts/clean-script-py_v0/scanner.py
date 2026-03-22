#!/usr/bin/env python3
"""Scan Codex auth files and report HTTP 401 and no-limit credentials.  

This script ports key parts from CLIProxyAPI's Codex implementation:  

- Default Codex base URL from `internal/runtime/executor/codex_executor.go`
- Codex request headers style from `applyCodexHeaders`
- Refresh-token flow from `internal/auth/codex/openai_auth.go`  

Usage examples:  

  python scripts/codex_quota_401_scanner.py --auth-dir ./auths
  python scripts/codex_quota_401_scanner.py --auth-dir ~/.cli-proxy-api --refresh-before-check
  python scripts/codex_quota_401_scanner.py --auth-dir ./auths --output-json
  python scripts/codex_quota_401_scanner.py --auth-dir ./auths --delete-401
  python scripts/codex_quota_401_scanner.py --auth-dir ./auths --delete-401 --yes
"""  

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import os
import shutil
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Iterable  

import aiohttp  


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------  

DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
DEFAULT_REFRESH_URL = "https://auth.openai.com/oauth/token"
DEFAULT_AUTH_DIR = "~/.cli-proxy-api"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_VERSION = "0.98.0"
DEFAULT_USER_AGENT = "codex_cli_rs/0.98.0 (python-port)"
DEFAULT_WORKERS = min(300, max(50, (os.cpu_count() or 1) * 20))  # Much higher concurrency for async
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF = 0.6
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_MAGENTA = "\033[35m"
DEFAULT_EXCEEDED_DIR_NAME = "exceeded"  

# ---------------------------------------------------------------------------
# Shared field-key candidate lists (used by _looks_like_codex & _extract)
# ---------------------------------------------------------------------------  

_PROVIDER_KEYS = ["type", "provider", "metadata.type"]
_EMAIL_KEYS = ["email", "metadata.email", "attributes.email"]  

_ACCESS_TOKEN_KEYS = [
    "access_token",
    "accessToken",
    "token.access_token",
    "token.accessToken",
    "metadata.access_token",
    "metadata.accessToken",
    "metadata.token.access_token",
    "metadata.token.accessToken",
    "attributes.api_key",
]  

_REFRESH_TOKEN_KEYS = [
    "refresh_token",
    "refreshToken",
    "token.refresh_token",
    "token.refreshToken",
    "metadata.refresh_token",
    "metadata.refreshToken",
    "metadata.token.refresh_token",
    "metadata.token.refreshToken",
]  

_ACCOUNT_ID_KEYS = [
    "account_id",
    "accountId",
    "metadata.account_id",
    "metadata.accountId",
]  

_BASE_URL_KEYS = [
    "base_url",
    "baseUrl",
    "metadata.base_url",
    "metadata.baseUrl",
    "attributes.base_url",
    "attributes.baseUrl",
]  


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------  

@dataclass
class CheckResult:
    file: str
    provider: str
    email: str
    account_id: str
    status_code: int | None
    unauthorized_401: bool
    no_limit_unlimited: bool
    quota_exceeded: bool
    quota_resets_at: int | None
    error: str
    response_preview: str  

    @classmethod
    def make_error(
        cls,
        file: str,
        error_msg: str,
        *,
        provider: str = "unknown",
        email: str = "",
        account_id: str = "",
    ) -> "CheckResult":
        """Convenience factory for error/skip results."""
        return cls(
            file=file,
            provider=provider,
            email=email,
            account_id=account_id,
            status_code=None,
            unauthorized_401=False,
            no_limit_unlimited=False,
            quota_exceeded=False,
            quota_resets_at=None,
            error=error_msg,
            response_preview="",
        )  

    @classmethod
    def from_fields_error(
        cls, file: str, fields: dict[str, str], error_msg: str
    ) -> "CheckResult":
        """Factory using pre-extracted auth fields."""
        return cls.make_error(
            file,
            error_msg,
            provider=fields.get("provider", "unknown"),
            email=fields.get("email", ""),
            account_id=fields.get("account_id", ""),
        )  


@dataclass
class DeleteError:
    file: str
    error: str  


# ---------------------------------------------------------------------------
# Terminal / color helpers
# ---------------------------------------------------------------------------  

def _is_tty_stdout() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()  


def _supports_color(disabled: bool) -> bool:
    return (not disabled) and _is_tty_stdout() and ("NO_COLOR" not in os.environ)  


def _paint(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return "".join(codes) + text + ANSI_RESET  


def _truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    if limit <= 3:
        return "." * limit
    return text[: limit - 3] + "..."  


class _ProgressDisplay:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._last_len = 0
        self._finished = False  

    def update(self, current: int, total: int, path: Path) -> None:
        if not self.enabled or total <= 0:
            return  

        width = shutil.get_terminal_size(fallback=(100, 20)).columns
        bar_width = max(12, min(30, width - 52))
        percent = int((current * 100) / total)
        filled = int((current * bar_width) / total)
        bar = "#" * filled + "-" * (bar_width - filled)
        message = f"[{bar}] {current}/{total} {percent:>3}% {_truncate(path.name, 28)}"
        message = _truncate(message, max(10, width - 1))
        padding = " " * max(0, self._last_len - len(message))
        sys.stdout.write(f"\r{message}{padding}")
        sys.stdout.flush()
        self._last_len = len(message)  

    def finish(self) -> None:
        if not self.enabled or self._finished:
            return
        self._finished = True
        sys.stdout.write("\n")
        sys.stdout.flush()  


# ---------------------------------------------------------------------------
# JSON field helpers
# ---------------------------------------------------------------------------  

def _first_non_empty_str(values: Iterable[Any]) -> str:
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return ""  


def _dot_get(data: Any, dotted_key: str) -> Any:
    current = data
    for key in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current  


def _pick(data: dict[str, Any], candidates: list[str]) -> str:
    values = [_dot_get(data, key) for key in candidates]
    return _first_non_empty_str(values)  


# ---------------------------------------------------------------------------
# Codex detection & field extraction (using shared key constants)
# ---------------------------------------------------------------------------  

def _looks_like_codex(path: Path, payload: dict[str, Any]) -> bool:
    provider = _pick(payload, _PROVIDER_KEYS)
    if provider:
        return provider.lower() == "codex"  

    name = path.name.lower()
    if name.startswith("codex-"):
        return True  

    access_token = _pick(payload, _ACCESS_TOKEN_KEYS)
    refresh_token = _pick(payload, _REFRESH_TOKEN_KEYS)
    account_id = _pick(payload, _ACCOUNT_ID_KEYS)  

    return bool(access_token and (refresh_token or account_id))  


def _extract_auth_fields(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "provider": _pick(payload, _PROVIDER_KEYS) or "codex",
        "email": _pick(payload, _EMAIL_KEYS),
        "access_token": _pick(payload, _ACCESS_TOKEN_KEYS),
        "refresh_token": _pick(payload, _REFRESH_TOKEN_KEYS),
        "account_id": _pick(payload, _ACCOUNT_ID_KEYS),
        "base_url": _pick(payload, _BASE_URL_KEYS),
    }  


# ---------------------------------------------------------------------------
# Response analysis
# ---------------------------------------------------------------------------  

_UNLIMITED_TEXT_MARKERS = (
    "unlimited",
    "no limit",
    "no-limit",
    "without limit",
    "limitless",
    "不限额",
    "无限额",
    "无限制",
)  

_UNLIMITED_KEY_HINTS = (
    "unlimited",
    "no_limit",
    "nolimit",
    "limitless",
)  

_LIMIT_LIKE_KEY_HINTS = (
    "quota",
    "limit",
    "cap",
)  


def _looks_unlimited_from_response(status_code: int | None, response_text: str) -> bool:
    if status_code is None or status_code < 200 or status_code >= 300:
        return False  

    lowered = (response_text or "").lower()
    if any(marker in lowered for marker in _UNLIMITED_TEXT_MARKERS):
        return True  

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        return False  

    stack: list[Any] = [parsed]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                key_lc = str(key).lower()
                if any(hint in key_lc for hint in _UNLIMITED_KEY_HINTS):
                    if isinstance(value, bool) and value:
                        return True
                    if isinstance(value, str) and value.strip().lower() in {
                        "1",
                        "true",
                        "yes",
                        "unlimited",
                        "no_limit",
                        "nolimit",
                    }:
                        return True
                    if isinstance(value, (int, float)) and value == -1:
                        return True
                if any(hint in key_lc for hint in _LIMIT_LIKE_KEY_HINTS):
                    if value is None:
                        return True
                    if isinstance(value, (int, float)) and (
                        value == -1 or value >= 9999
                    ):
                        return True
                    if isinstance(value, str) and value.strip().lower() in {
                        "none",
                        "null",
                        "unlimited",
                        "no limit",
                        "no-limit",
                        "无限",
                        "不限额",
                        "无限额",
                    }:
                        return True
                if isinstance(value, (dict, list)):
                    stack.append(value)
                elif isinstance(value, str):
                    text_value = value.lower()
                    if any(marker in text_value for marker in _UNLIMITED_TEXT_MARKERS):
                        return True
        elif isinstance(current, list):
            stack.extend(current)  

    return False  


_QUOTA_EXCEEDED_TEXT_MARKERS = (
    "usage_limit_reached",
    "usage limit has been reached",
    "quota exceeded",
    "limit exceeded",
    "超出配额",
    "额度已用完",
)  


def _detect_quota_exceeded(response_text: str) -> tuple[bool, int | None]:
    """Return (is_exceeded, resets_at_unix_or_None)."""
    if not response_text:
        return False, None  

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        parsed = None  

    if isinstance(parsed, dict):
        err = parsed.get("error")
        if isinstance(err, dict):
            if err.get("type") == "usage_limit_reached":
                resets_at = err.get("resets_at")
                if isinstance(resets_at, (int, float)):
                    return True, int(resets_at)
                return True, None  

    lowered = response_text.lower()
    if any(marker in lowered for marker in _QUOTA_EXCEEDED_TEXT_MARKERS):
        return True, None  

    return False, None  


# ---------------------------------------------------------------------------
# Async HTTP helpers & Token refresh
# ---------------------------------------------------------------------------  

async def _http_request_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    retry_attempts: int,
    retry_backoff: float,
) -> tuple[int, bytes]:
    last_exc: Exception | None = None
    client_timeout = aiohttp.ClientTimeout(total=timeout)  

    for attempt in range(1, retry_attempts + 1):
        try:
            async with session.request(
                method.upper(), url, headers=headers, data=body, timeout=client_timeout
            ) as resp:
                resp_bytes = await resp.read()
                return resp.status, resp_bytes
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            last_exc = exc
            if attempt >= retry_attempts:
                break
            if retry_backoff > 0:
                sleep_seconds = retry_backoff * (2 ** (attempt - 1))
                await asyncio.sleep(sleep_seconds)  

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("request failed without a captured exception")  


async def _refresh_access_token(
    session: aiohttp.ClientSession, refresh_url: str, refresh_token: str, timeout: float
) -> tuple[str, str]:
    body = {
        "client_id": DEFAULT_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "openid profile email",
    }
    client_timeout = aiohttp.ClientTimeout(total=timeout)  

    try:
        async with session.post(
            refresh_url,
            data=body,
            headers={
                "Accept": "application/json",
            },
            timeout=client_timeout,
        ) as resp:
            resp_body = await resp.read()
            status = resp.status
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise RuntimeError(f"refresh network error: {exc}") from exc  

    if status != 200:
        msg = resp_body.decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"refresh failed with {status}: {msg}")  

    try:
        parsed = json.loads(resp_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"refresh response is not valid JSON: {exc}") from exc  

    new_token = _first_non_empty_str([parsed.get("access_token")])
    new_refresh = _first_non_empty_str([parsed.get("refresh_token")])
    if not new_token:
        raise RuntimeError("refresh succeeded but access_token missing")  

    return new_token, new_refresh  


# ---------------------------------------------------------------------------
# Probe request building
# ---------------------------------------------------------------------------  

def _build_probe_headers(access_token: str, account_id: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": DEFAULT_VERSION,
        "Openai-Beta": "responses=experimental",
        "User-Agent": DEFAULT_USER_AGENT,
        "Originator": "codex_cli_rs",
    }
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    return headers  


def _build_probe_body(model: str) -> bytes:
    payload = {
        "model": model,
        "stream": True,
        "store": False,
        "instructions": "",
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": "ping",
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")  


# ---------------------------------------------------------------------------
# Async single-file scan
# ---------------------------------------------------------------------------  

def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8-sig")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("root JSON value is not an object")
    return obj  


async def _scan_single_file(
    session: aiohttp.ClientSession, path: Path, args: argparse.Namespace, probe_body: bytes
) -> list[CheckResult]:
    try:
        payload = await asyncio.to_thread(_load_json, path)
    except Exception as exc:  # noqa: BLE001
        return [CheckResult.make_error(str(path), f"parse error: {exc}")]  

    if not _looks_like_codex(path, payload):
        return []  

    fields = _extract_auth_fields(payload)
    access_token = fields["access_token"]
    refresh_token = fields["refresh_token"]  

    try:
        if args.refresh_before_check and refresh_token:
            access_token, _ = await _refresh_access_token(
                session, args.refresh_url, refresh_token, args.timeout
            )
    except Exception as exc:  # noqa: BLE001
        return [CheckResult.from_fields_error(str(path), fields, str(exc))]  

    if not access_token:
        return [
            CheckResult.from_fields_error(str(path), fields, "missing access token")
        ]  

    base_url = fields["base_url"] or args.base_url
    probe_url = base_url.rstrip("/") + "/" + args.quota_path.lstrip("/")
    headers = _build_probe_headers(access_token, fields["account_id"])  

    try:
        status, resp_body = await _http_request_with_retry(
            session=session,
            url=probe_url,
            method="POST",
            headers=headers,
            body=probe_body,
            timeout=args.timeout,
            retry_attempts=args.retry_attempts,
            retry_backoff=args.retry_backoff,
        )
        response_text = resp_body.decode("utf-8", errors="replace")
        preview = response_text[:300]
        _quota_exceeded, _resets_at = _detect_quota_exceeded(response_text)
        return [
            CheckResult(
                file=str(path),
                provider=fields["provider"],
                email=fields["email"],
                account_id=fields["account_id"],
                status_code=status,
                unauthorized_401=(status == 401),
                no_limit_unlimited=_looks_unlimited_from_response(
                    status, response_text
                ),
                quota_exceeded=_quota_exceeded,
                quota_resets_at=_resets_at,
                error="",
                response_preview=preview,
            )
        ]
    except Exception as exc:
        return [
            CheckResult.from_fields_error(str(path), fields, f"network error: {exc}")
        ]  


# ---------------------------------------------------------------------------
# Async concurrent scanner 
# ---------------------------------------------------------------------------  

async def _scan_files(
    json_files: list[Path],
    args: argparse.Namespace,
    probe_body: bytes,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    """Scan *json_files* concurrently using asyncio.gather and a Semaphore."""
    total = len(json_files)
    if total == 0:
        return []  

    workers = min(args.workers, total)
    semaphore = asyncio.Semaphore(workers)
    completed = 0  

    async def _sem_worker(index: int, path: Path, session: aiohttp.ClientSession) -> tuple[int, list[CheckResult]]:
        nonlocal completed
        async with semaphore:
            try:
                file_results = await _scan_single_file(session, path, args, probe_body)
            except Exception as exc:  # noqa: BLE001
                file_results = [CheckResult.make_error(str(path), f"internal error: {exc}")]
            completed += 1
            if progress_callback:
                progress_callback(completed, total, path)
            return index, file_results  

    # Use a single TCPConnector and ClientSession for connection pooling
    connector = aiohttp.TCPConnector(limit=workers)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(_sem_worker(index, path, session))
            for index, path in enumerate(json_files, start=1)
        ]
        results_with_index = await asyncio.gather(*tasks)  

    results_with_index.sort(key=lambda item: item[0])
    return [row for _, group in results_with_index for row in group if group]  


async def scan_auth_files(
    args: argparse.Namespace,
    probe_body: bytes,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    auth_dir = Path(args.auth_dir).expanduser().resolve()
    if not auth_dir.exists() or not auth_dir.is_dir():
        raise FileNotFoundError(f"auth directory not found: {auth_dir}")  

    json_files = sorted(auth_dir.rglob("*.json"))
    return await _scan_files(json_files, args, probe_body, progress_callback)  


async def _scan_dir_flat(
    dir_path: Path,
    args: argparse.Namespace,
    probe_body: bytes,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    if not dir_path.exists() or not dir_path.is_dir():
        return []  

    json_files = sorted(dir_path.glob("*.json"))
    return await _scan_files(json_files, args, probe_body, progress_callback)  


# ---------------------------------------------------------------------------
# Display / Output / File-system helpers
# ---------------------------------------------------------------------------  

def _status_label(item: CheckResult, use_color: bool) -> str:
    if item.unauthorized_401:
        return _paint("401", ANSI_BOLD, ANSI_RED, enabled=use_color)
    if item.quota_exceeded:
        return _paint("LIM", ANSI_BOLD, ANSI_MAGENTA, enabled=use_color)
    if item.status_code is None:
        return _paint("ERR", ANSI_BOLD, ANSI_YELLOW, enabled=use_color)
    code = str(item.status_code)
    if 200 <= item.status_code < 300:
        return _paint(code, ANSI_GREEN, enabled=use_color)
    if 400 <= item.status_code < 500:
        return _paint(code, ANSI_YELLOW, enabled=use_color)
    if item.status_code >= 500:
        return _paint(code, ANSI_RED, enabled=use_color)
    return code  


def _print_table(results: list[CheckResult], use_color: bool) -> None:
    if not results:
        print(_paint("No codex auth files found.", ANSI_YELLOW, enabled=use_color))
        return  

    unauthorized = [r for r in results if r.unauthorized_401]
    quota_exceeded_list = [r for r in results if r.quota_exceeded and not r.unauthorized_401]
    no_limit_unlimited = [r for r in results if r.no_limit_unlimited]
    ok_count = sum(
        1
        for item in results
        if item.status_code is not None and 200 <= item.status_code < 300
    )
    failed_count = len(results) - ok_count  

    print(_paint("Scan Summary", ANSI_BOLD, ANSI_CYAN, enabled=use_color))
    print(f"  checked codex files : {len(results)}")
    print(f"  unauthorized (401)  : {len(unauthorized)}")
    print(f"  quota-exceeded      : {len(quota_exceeded_list)}")
    print(f"  no-limit/unlimited  : {len(no_limit_unlimited)}")
    print(f"  non-2xx or errors   : {failed_count}")
    print()  

    if unauthorized:
        print(_paint("401 Files", ANSI_BOLD, ANSI_RED, enabled=use_color))
        for item in unauthorized:
            email = f" ({item.email})" if item.email else ""
            print(f"  [{_status_label(item, use_color)}] {item.file}{email}")
        print()  

    if quota_exceeded_list:
        print(_paint("Quota-Exceeded Files", ANSI_BOLD, ANSI_MAGENTA, enabled=use_color))
        for item in quota_exceeded_list:
            email = f" ({item.email})" if item.email else ""
            if item.quota_resets_at is not None:
                resets_str = _dt.datetime.fromtimestamp(
                    item.quota_resets_at, tz=_dt.timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
                suffix = f" [resets {resets_str}]"
            else:
                suffix = ""
            print(f"  [{_status_label(item, use_color)}] {item.file}{email}{suffix}")
        print()  

    others = [
        r
        for r in results
        if (not r.unauthorized_401)
        and (not r.quota_exceeded)
        and (not r.no_limit_unlimited)
    ]
    if no_limit_unlimited:
        print(
            _paint("No-limit/Unlimited Files", ANSI_BOLD, ANSI_GREEN, enabled=use_color)
        )
        for item in no_limit_unlimited:
            email = f" ({item.email})" if item.email else ""
            print(f"  [{_status_label(item, use_color)}] {item.file}{email}")
        print()  

    if others:
        print(_paint("Other Results", ANSI_BOLD, ANSI_CYAN, enabled=use_color))
        for item in others:
            status = _status_label(item, use_color)
            reason = item.error or item.response_preview.replace("\n", " ")[:120]
            reason = reason.strip() or "-"
            print(f"  [{status}] {item.file} :: {_truncate(reason, 120)}")  


def _move_file_safely(src: Path, dst_dir: Path) -> tuple[str | None, str | None]:
    """Move *src* into *dst_dir*, creating dst_dir if necessary.  

    Returns ``(dst_path, None)`` on success or ``(None, error_message)`` on failure.
    """
    try:
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / src.name
        counter = 1
        while dst.exists():
            dst = dst_dir / f"{src.stem}_{counter}{src.suffix}"
            counter += 1
        shutil.move(str(src), str(dst))
        return str(dst), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)  


def _confirm_deletion(targets: list[str], assume_yes: bool) -> bool:
    if not targets:
        return False
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("No interactive terminal for confirmation; deletion cancelled. Use --yes to force.")
        return False
    print()
    print(f"Delete {len(targets)} files with 401? This action cannot be undone.")
    answer = input("Confirm deletion? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}  


def _delete_files(paths: list[str]) -> tuple[list[str], list[DeleteError]]:
    deleted: list[str] = []
    errors: list[DeleteError] = []
    seen: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        normalized = str(path.resolve())
        if normalized in seen: continue
        seen.add(normalized)
        try:
            path.unlink()
            deleted.append(str(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(DeleteError(file=str(path), error=str(exc)))
    return deleted, errors  


def _print_deletion_summary(
    *, requested: bool, target_count: int, confirmed: bool,
    deleted_files: list[str], errors: list[DeleteError], use_color: bool,
) -> None:
    if not requested:
        return
    if target_count == 0:
        print()
        print(_paint("Delete mode enabled, but no 401 files found.", ANSI_DIM, enabled=use_color))
        return
    print()
    if not confirmed:
        print(_paint("Deletion cancelled by user.", ANSI_YELLOW, enabled=use_color))
        return  

    print(_paint(f"Deletion completed: {len(deleted_files)}/{target_count} removed.", ANSI_BOLD, ANSI_GREEN, enabled=use_color))
    for path in deleted_files:
        print(f"[{_paint('deleted', ANSI_GREEN, enabled=use_color)}] {path}")
    for item in errors:
        print(f"[{_paint('delete-failed', ANSI_RED, enabled=use_color)}] {item.file} :: {item.error}")  


# ---------------------------------------------------------------------------
# CLI argument parser & Main entry
# ---------------------------------------------------------------------------  

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Traverse auth folder and detect Codex auth files returning 401 or no-limit markers. (AsyncIO Rewrite)"
    )
    parser.add_argument("--auth-dir", default=DEFAULT_AUTH_DIR, help=f"Folder containing auth JSON files (default: {DEFAULT_AUTH_DIR}).")
    parser.add_argument("--base-url", default=DEFAULT_CODEX_BASE_URL, help=f"Codex base URL (default: {DEFAULT_CODEX_BASE_URL})")
    parser.add_argument("--quota-path", default="/responses", help="API path used for quota/auth probe (default: /responses)")
    parser.add_argument("--model", default="gpt-5", help="Model used in probe request body (default: gpt-5)")
    parser.add_argument("--timeout", type=float, default=20, help="HTTP timeout in seconds (default: 20)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"Max concurrent async requests (default: {DEFAULT_WORKERS})")
    parser.add_argument("--retry-attempts", type=int, default=DEFAULT_RETRY_ATTEMPTS, help=f"Total attempts for network errors per file (default: {DEFAULT_RETRY_ATTEMPTS})")
    parser.add_argument("--retry-backoff", type=float, default=DEFAULT_RETRY_BACKOFF, help=f"Base seconds for exponential retry backoff (default: {DEFAULT_RETRY_BACKOFF})")
    parser.add_argument("--refresh-before-check", action="store_true", help="Refresh access token with refresh_token before probe.")
    parser.add_argument("--refresh-url", default=DEFAULT_REFRESH_URL, help=f"Token refresh endpoint (default: {DEFAULT_REFRESH_URL})")
    parser.add_argument("--output-json", action="store_true", help="Print full results as JSON instead of table view.")
    parser.add_argument("--no-progress", action="store_true", help="Disable live scan progress in terminal output.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    parser.add_argument("--delete-401", action="store_true", help="Delete auth files that returned HTTP 401 after confirmation.")
    parser.add_argument("--yes", action="store_true", help="Skip deletion confirmation prompt (only applies with --delete-401).")
    parser.add_argument("--exceeded-dir", default=None, help="Directory to move quota-exceeded auth files into.")
    parser.add_argument("--no-quarantine", action="store_true", help="Disable automatic quarantine: do not move quota-exceeded files.")
    return parser  


async def async_main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.workers < 1: parser.error("--workers must be >= 1")
    if args.retry_attempts < 1: parser.error("--retry-attempts must be >= 1")
    if args.retry_backoff < 0: parser.error("--retry-backoff must be >= 0")  

    use_color = _supports_color(args.no_color) and (not args.output_json)
    progress_enabled = _is_tty_stdout() and (not args.no_progress) and (not args.output_json)
    progress = _ProgressDisplay(progress_enabled)  

    auth_dir = Path(args.auth_dir).expanduser().resolve()
    exceeded_dir = Path(args.exceeded_dir).expanduser().resolve() if args.exceeded_dir else auth_dir.parent / DEFAULT_EXCEEDED_DIR_NAME
    probe_body = _build_probe_body(args.model)  

    if progress_enabled:
        print(_paint("Scanning auth JSON files...", ANSI_DIM, enabled=use_color))  

    try:
        results = await scan_auth_files(
            args, probe_body, progress_callback=progress.update if progress_enabled else None
        )
    except Exception as exc:  # noqa: BLE001
        progress.finish()
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    progress.finish()  

    # Quarantine logic
    moved_to_exceeded: list[str] = []
    move_to_exceeded_errors: list[DeleteError] = []
    if not args.no_quarantine:
        for item in results:
            if item.quota_exceeded:
                dst, err = _move_file_safely(Path(item.file), exceeded_dir)
                if err:
                    move_to_exceeded_errors.append(DeleteError(file=item.file, error=err))
                else:
                    if dst: moved_to_exceeded.append(dst)  

    # Recovery logic
    exceeded_results: list[CheckResult] = []
    moved_from_exceeded: list[str] = []
    move_from_exceeded_errors: list[DeleteError] = []
    if not args.no_quarantine and exceeded_dir.exists():
        if progress_enabled:
            print(_paint(f"Scanning exceeded dir: {exceeded_dir} ...", ANSI_DIM, enabled=use_color))
        exceeded_results = await _scan_dir_flat(exceeded_dir, args, probe_body)
        for item in exceeded_results:
            recovered = (not item.quota_exceeded and item.status_code is not None and 200 <= item.status_code < 300)
            if recovered:
                dst, err = _move_file_safely(Path(item.file), auth_dir)
                if err: move_from_exceeded_errors.append(DeleteError(file=item.file, error=err))
                else:
                    if dst: moved_from_exceeded.append(dst)  

    # Delete 401 logic
    unauthorized_files = [item.file for item in results if item.unauthorized_401]
    delete_confirmed = False
    deleted_files: list[str] = []
    delete_errors: list[DeleteError] = []
    if args.delete_401 and unauthorized_files:
        delete_confirmed = _confirm_deletion(unauthorized_files, args.yes)
        if delete_confirmed:
            deleted_files, delete_errors = _delete_files(unauthorized_files)  

    # Outputs
    if args.output_json:
        print(json.dumps({
            "results": [asdict(item) for item in results],
            "exceeded_dir_results": [asdict(item) for item in exceeded_results],
            "quarantine": {
                "enabled": not args.no_quarantine,
                "exceeded_dir": str(exceeded_dir),
                "moved_to_exceeded": moved_to_exceeded,
                "moved_to_exceeded_errors": [asdict(e) for e in move_to_exceeded_errors],
                "moved_from_exceeded": moved_from_exceeded,
                "moved_from_exceeded_errors": [asdict(e) for e in move_from_exceeded_errors],
            },
            "deletion": {
                "requested": args.delete_401,
                "target_count": len(unauthorized_files),
                "confirmed": delete_confirmed,
                "deleted_count": len(deleted_files),
                "deleted_files": deleted_files,
                "errors": [asdict(item) for item in delete_errors],
            },
        }, ensure_ascii=False, indent=2))
    else:
        _print_table(results, use_color=use_color)
        if exceeded_results:
            print(_paint(f"Exceeded Dir Scan ({exceeded_dir})", ANSI_BOLD, ANSI_MAGENTA, enabled=use_color))
            _print_table(exceeded_results, use_color=use_color)
        if moved_to_exceeded or move_to_exceeded_errors:
            print()
            print(_paint("Quarantine Moves (auth-dir → exceeded)", ANSI_BOLD, ANSI_MAGENTA, enabled=use_color))
            for dst in moved_to_exceeded: print(f"  [{_paint('moved', ANSI_MAGENTA, enabled=use_color)}] → {dst}")
            for e in move_to_exceeded_errors: print(f"  [{_paint('move-failed', ANSI_RED, enabled=use_color)}] {e.file} :: {e.error}")
        if moved_from_exceeded or move_from_exceeded_errors:
            print()
            print(_paint("Recovery Moves (exceeded → auth-dir)", ANSI_BOLD, ANSI_GREEN, enabled=use_color))
            for dst in moved_from_exceeded: print(f"  [{_paint('recovered', ANSI_GREEN, enabled=use_color)}] → {dst}")
            for e in move_from_exceeded_errors: print(f"  [{_paint('recover-failed', ANSI_RED, enabled=use_color)}] {e.file} :: {e.error}")  

        _print_deletion_summary(
            requested=args.delete_401, target_count=len(unauthorized_files),
            confirmed=delete_confirmed, deleted_files=deleted_files, errors=delete_errors,
            use_color=use_color,
        )  

    has_401 = any(item.unauthorized_401 for item in results)
    return 1 if has_401 else 0  


def main() -> int:
    # On Windows, need to use SelectorEventLoop for aiohttp
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130  


if __name__ == "__main__":
    raise SystemExit(main())
