#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import datetime as dt
import hashlib
import json
import logging
import os
import random
import re
import secrets
import string
import sys
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import aiohttp
except Exception:
    aiohttp = None


OPENAI_AUTH_BASE = "https://auth.openai.com"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_MGMT_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
DEFAULT_LOOP_INTERVAL_SECONDS = 60.0
MIN_LOOP_INTERVAL_SECONDS = 5.0

COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": OPENAI_AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}

TRANSIENT_FLOW_MARKERS_DEFAULT = (
    "sentinel_",
    "oauth_authorization_code_not_found",
    "headers_failed",
    "server disconnected",
    "unexpected_eof_while_reading",
    "unexpected eof while reading",
    "timeout",
    "timed out",
    "transport",
    "remoteprotocolerror",
    "connection reset",
    "temporarily unavailable",
    "network",
    "eof occurred",
    "http_429",
    "http_500",
    "http_502",
    "http_503",
    "http_504",
)

PHONE_VERIFICATION_MARKERS_DEFAULT = (
    "add_phone",
    "/add-phone",
    "phone_verification",
    "phone-verification",
    "phone/verify",
)

TRACE_REDACT_KEYS = (
    "password",
    "passwd",
    "authorization",
    "cookie",
    "token",
    "secret",
    "session",
    "csrf",
    "code_verifier",
)
TRACE_REDACT_QUERY_KEYS = {
    "code",
    "state",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "csrfToken",
}


def is_transient_flow_error(reason: str | None, markers: tuple[str, ...] = TRANSIENT_FLOW_MARKERS_DEFAULT) -> bool:
    text = str(reason or "").strip().lower()
    if not text:
        return False
    return any(marker in text for marker in markers)


def parse_marker_config(raw: Any, *, fallback: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(raw, str):
        values = [part.strip().lower() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple)):
        values = [str(item).strip().lower() for item in raw]
    sanitized = tuple(item for item in values if item)
    return sanitized or fallback


def parse_choice(raw: Any, *, allowed: tuple[str, ...], fallback: str) -> str:
    text = str(raw or "").strip().lower()
    return text if text in allowed else fallback


def parse_bool(raw: Any, *, fallback: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw or "").strip().lower()
    if not text:
        return fallback
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return fallback


def parse_otp_validate_order(raw: Any) -> tuple[str, ...]:
    values = parse_marker_config(raw, fallback=("normal", "sentinel"))
    sanitized = tuple(item for item in values if item in {"normal", "sentinel"})
    return sanitized or ("normal", "sentinel")


def requires_phone_verification(
    payload: Dict[str, Any] | None,
    response_text: str = "",
    markers: tuple[str, ...] = PHONE_VERIFICATION_MARKERS_DEFAULT,
) -> bool:
    data = payload if isinstance(payload, dict) else {}
    page = data.get("page") or {}
    page_type = str(page.get("type") or "").strip().lower() if isinstance(page, dict) else ""
    continue_url = str(data.get("continue_url") or "").strip().lower()
    haystack = " ".join([page_type, continue_url, str(response_text or "").lower()])
    return any(str(marker).strip().lower() in haystack for marker in markers if str(marker).strip())


def extract_oauth_callback_params_from_url(url: str) -> Optional[Dict[str, str]]:
    if not url or "code=" not in url:
        return None
    try:
        query = parse_qs(urlparse(url).query)
    except Exception:
        return None

    code_values = query.get("code", [])
    if not code_values or not code_values[0]:
        return None

    params: Dict[str, str] = {}
    for key, values in query.items():
        if values and values[0]:
            params[str(key)] = str(values[0])
    return params or None


def extract_oauth_code_from_url(url: str) -> Optional[str]:
    params = extract_oauth_callback_params_from_url(url)
    return str((params or {}).get("code") or "").strip() or None


def extract_oauth_callback_params_from_payload(payload: Any) -> Optional[Dict[str, str]]:
    seen: set[int] = set()
    direct_params_candidates: list[Dict[str, str]] = []

    def _extract_from_text(text: Any) -> Optional[Dict[str, str]]:
        candidate = str(text or "").strip()
        if not candidate:
            return None
        for variant in (candidate, unquote(candidate)):
            params = extract_oauth_callback_params_from_url(variant)
            if params:
                return params
            if "code=" in variant:
                match = re.search(r"[?&]code=([^&\"'\\s]+)([^\"'\\s]*)", variant)
                if match:
                    query = f"code={match.group(1)}{match.group(2)}"
                    return extract_oauth_callback_params_from_url(f"http://localhost/dummy?{query}")
        return None

    def _walk(value: Any) -> Optional[Dict[str, str]]:
        if isinstance(value, dict):
            value_id = id(value)
            if value_id in seen:
                return None
            seen.add(value_id)

            direct_code = str(value.get("code") or "").strip()
            if direct_code:
                params = {"code": direct_code}
                for key in ("scope", "state"):
                    direct_value = str(value.get(key) or "").strip()
                    if direct_value:
                        params[key] = direct_value
                direct_params_candidates.append(params)

            for key in ("continue_url", "callback_url", "url", "redirect_url"):
                params = _extract_from_text(value.get(key))
                if params:
                    return params

            for nested_value in value.values():
                params = _walk(nested_value)
                if params:
                    return params
            return None

        if isinstance(value, (list, tuple, set)):
            for item in value:
                params = _walk(item)
                if params:
                    return params
            return None

        if isinstance(value, str):
            return _extract_from_text(value)

        return None

    extracted = _walk(payload)
    if extracted:
        return extracted
    return direct_params_candidates[0] if direct_params_candidates else None


def extract_oauth_callback_params_from_response(
    payload: Dict[str, Any] | None,
    response_headers: Optional[Dict[str, Any]] = None,
    response_url: str = "",
    response_text: str = "",
) -> Optional[Dict[str, str]]:
    candidates: list[str] = []

    if isinstance(payload, dict):
        for key in ("continue_url", "callback_url", "url", "redirect_url"):
            value = payload.get(key)
            if value:
                candidates.append(str(value))

    if isinstance(response_headers, dict):
        for key in ("Location", "location"):
            value = response_headers.get(key)
            if value:
                candidates.append(str(value))

    if response_url:
        candidates.append(str(response_url))

    for candidate in candidates:
        params = extract_oauth_callback_params_from_url(candidate)
        if params:
            return params

    payload_params = extract_oauth_callback_params_from_payload(payload)
    if payload_params:
        return payload_params

    if response_text and "code=" in response_text:
        match = re.search(r"[?&]code=([^&\"'\\s]+)([^\"'\\s]*)", response_text)
        if match:
            query = f"code={match.group(1)}{match.group(2)}"
            return extract_oauth_callback_params_from_url(f"http://localhost/dummy?{query}")

    return None


def extract_oauth_callback_params_from_session_cookies(session: requests.Session) -> Optional[Dict[str, str]]:
    jar = getattr(session, "cookies", None)
    if jar is None:
        return None

    def _iter_text_candidates(raw_value: Any) -> list[str]:
        first = str(raw_value or "").strip()
        if not first:
            return []
        queue = [first]
        queued = {first}
        processed: set[str] = set()
        collected: list[str] = []

        def _push(text: str) -> None:
            candidate = str(text or "").strip()
            if not candidate or candidate in processed or candidate in queued:
                return
            queue.append(candidate)
            queued.add(candidate)

        while queue:
            current = queue.pop(0)
            if not current or current in processed:
                continue
            processed.add(current)
            collected.append(current)

            decoded_variants = [unquote(current)]
            if "." in current:
                decoded_variants.append(current.split(".", 1)[0])

            for variant in decoded_variants:
                stripped = str(variant or "").strip()
                if not stripped:
                    continue
                if stripped != current:
                    _push(stripped)
                base64_candidate = stripped
                if re.fullmatch(r"[A-Za-z0-9_-]+", base64_candidate):
                    padding = (-len(base64_candidate)) % 4
                    try:
                        decoded = base64.urlsafe_b64decode(base64_candidate + ("=" * padding)).decode("utf-8")
                    except Exception:
                        decoded = ""
                    if decoded and all(ch.isprintable() or ch in "\r\n\t" for ch in decoded):
                        _push(decoded)

        return collected

    try:
        cookies = list(jar)
    except Exception:
        return None

    for cookie in cookies:
        cookie_name = str(getattr(cookie, "name", "") or "").strip().lower()
        if cookie_name and not (
            cookie_name.startswith("oai-")
            or any(marker in cookie_name for marker in ("auth", "session", "oauth", "login", "callback", "redirect"))
        ):
            continue
        for candidate in _iter_text_candidates(getattr(cookie, "value", "")):
            if candidate.startswith("{") or candidate.startswith("["):
                try:
                    parsed = json.loads(candidate)
                except Exception:
                    parsed = None
                params = extract_oauth_callback_params_from_payload(parsed)
                if params:
                    return params
            params = extract_oauth_callback_params_from_payload(candidate)
            if params:
                return params
    return None


def extract_oauth_code_from_response(
    payload: Dict[str, Any] | None,
    response_headers: Optional[Dict[str, Any]] = None,
    response_url: str = "",
    response_text: str = "",
) -> Optional[str]:
    params = extract_oauth_callback_params_from_response(
        payload,
        response_headers=response_headers,
        response_url=response_url,
        response_text=response_text,
    )
    return str((params or {}).get("code") or "").strip() or None


def extract_continue_url_from_response(
    payload: Dict[str, Any] | None,
    response_headers: Optional[Dict[str, Any]] = None,
    response_url: str = "",
) -> str:
    if isinstance(payload, dict):
        for key in ("continue_url", "callback_url", "url", "redirect_url"):
            value = str(payload.get(key) or "").strip()
            if value:
                return value

    if isinstance(response_headers, dict):
        for key in ("Location", "location"):
            value = str(response_headers.get(key) or "").strip()
            if value:
                return value

    return str(response_url or "").strip()


def parse_mail_timestamp(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            return number / 1000.0
        if number > 0:
            return number
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        numeric = float(text)
        if numeric > 10_000_000_000:
            return numeric / 1000.0
        if numeric > 0:
            return numeric
    except ValueError:
        pass

    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue

    try:
        return parsedate_to_datetime(text).timestamp()
    except Exception:
        return None


def extract_mail_timestamp(payload: Dict[str, Any]) -> Optional[float]:
    candidates = (
        payload.get("received_at"),
        payload.get("receivedAt"),
        payload.get("created_at"),
        payload.get("createdAt"),
        payload.get("date"),
        payload.get("timestamp"),
    )
    for candidate in candidates:
        parsed = parse_mail_timestamp(candidate)
        if parsed is not None:
            return parsed
    return None


def is_mail_recent_enough(payload: Dict[str, Any], not_before_ts: Optional[float]) -> bool:
    if not_before_ts is None:
        return True
    ts = extract_mail_timestamp(payload)
    if ts is None:
        return True
    return ts >= float(not_before_ts) - 2.0


def flow_step_retry_delay(conf: Dict[str, Any], attempt_number: int) -> float:
    safe_attempt = max(1, int(attempt_number))
    base = float(pick_conf(conf, "flow", "step_retry_delay_base", default=0.2) or 0.2)
    cap = float(pick_conf(conf, "flow", "step_retry_delay_cap", default=0.8) or 0.8)
    return min(max(0.05, cap), max(0.05, base) * safe_attempt)


def flow_step_retry_attempts(conf: Dict[str, Any]) -> int:
    return max(1, int(pick_conf(conf, "flow", "step_retry_attempts", default=2) or 2))


def flow_outer_retry_attempts(conf: Dict[str, Any], fallback: int = 2) -> int:
    return max(1, int(pick_conf(conf, "flow", "outer_retry_attempts", default=fallback) or fallback))


def oauth_local_retry_attempts(conf: Dict[str, Any], fallback: int = 3) -> int:
    return max(1, int(pick_conf(conf, "flow", "oauth_local_retry_attempts", default=fallback) or fallback))


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件格式错误，顶层必须是对象: {path}")
    return data


def _mask_trace_secret(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}...{text[-4:]}(len={len(text)})"


def _trim_trace_text(value: Any, limit: int) -> str:
    text = str(value or "")
    safe_limit = max(128, int(limit or 0))
    if len(text) <= safe_limit:
        return text
    return f"{text[:safe_limit]}...(truncated,total={len(text)})"


def _sanitize_trace_url(url: str, reveal_sensitive: bool, body_limit: int) -> str:
    text = str(url or "")
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        query = parse_qs(parsed.query, keep_blank_values=True)
        sanitized_query: Dict[str, List[str]] = {}
        for key, values in query.items():
            if reveal_sensitive or key not in TRACE_REDACT_QUERY_KEYS:
                sanitized_query[key] = values
            else:
                sanitized_query[key] = [_mask_trace_secret(item) for item in values]
        encoded_query = urlencode(sanitized_query, doseq=True)
        return parsed._replace(query=encoded_query).geturl()
    except Exception:
        return _trim_trace_text(text, body_limit)


def sanitize_trace_value(value: Any, *, key: str = "", reveal_sensitive: bool = False, body_limit: int = 4096) -> Any:
    normalized_key = str(key or "").strip().lower()
    is_sensitive_key = any(marker in normalized_key for marker in TRACE_REDACT_KEYS)

    if isinstance(value, dict):
        return {
            str(item_key): sanitize_trace_value(
                item_value,
                key=f"{normalized_key}.{item_key}" if normalized_key else str(item_key),
                reveal_sensitive=reveal_sensitive,
                body_limit=body_limit,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [
            sanitize_trace_value(
                item,
                key=normalized_key,
                reveal_sensitive=reveal_sensitive,
                body_limit=body_limit,
            )
            for item in value
        ]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    text = str(value)
    if not reveal_sensitive and is_sensitive_key:
        return _mask_trace_secret(text)
    if "url" in normalized_key:
        return _sanitize_trace_url(text, reveal_sensitive, body_limit)
    return _trim_trace_text(text, body_limit)


def describe_session_cookies(session: Any, *, reveal_sensitive: bool = False) -> List[Dict[str, Any]]:
    jar = getattr(session, "cookies", None)
    if jar is None:
        return []
    described: List[Dict[str, Any]] = []
    try:
        iterator = list(jar)
    except Exception:
        return []
    for cookie in iterator[:20]:
        name = str(getattr(cookie, "name", "") or "")
        value = getattr(cookie, "value", "")
        described.append(
            {
                "name": name,
                "domain": str(getattr(cookie, "domain", "") or ""),
                "path": str(getattr(cookie, "path", "") or ""),
                "value": sanitize_trace_value(
                    value,
                    key=f"cookie.{name}",
                    reveal_sensitive=reveal_sensitive,
                ),
            }
        )
    return described


def build_response_trace_payload(response: requests.Response, *, reveal_sensitive: bool = False, body_limit: int = 4096) -> Dict[str, Any]:
    headers = dict(getattr(response, "headers", {}) or {})
    history = []
    for item in getattr(response, "history", []) or []:
        history.append(
            {
                "status_code": getattr(item, "status_code", None),
                "url": sanitize_trace_value(getattr(item, "url", ""), key="history.url", reveal_sensitive=reveal_sensitive, body_limit=body_limit),
                "location": sanitize_trace_value(
                    (getattr(item, "headers", {}) or {}).get("Location", ""),
                    key="history.location",
                    reveal_sensitive=reveal_sensitive,
                    body_limit=body_limit,
                ),
            }
        )
    return {
        "status_code": getattr(response, "status_code", None),
        "url": sanitize_trace_value(getattr(response, "url", ""), key="response.url", reveal_sensitive=reveal_sensitive, body_limit=body_limit),
        "headers": sanitize_trace_value(headers, key="response.headers", reveal_sensitive=reveal_sensitive, body_limit=body_limit),
        "body_preview": sanitize_trace_value(getattr(response, "text", ""), key="response.body", reveal_sensitive=reveal_sensitive, body_limit=body_limit),
        "history": history,
    }


class FlowTraceRecorder:
    def __init__(self, file_path: str | Path, *, reveal_sensitive: bool = False, body_limit: int = 4096, enabled: bool = True):
        self.path = Path(file_path)
        self.enabled = bool(enabled)
        self.reveal_sensitive = bool(reveal_sensitive)
        self.body_limit = max(256, int(body_limit or 0))
        self._lock = threading.Lock()
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        if not self.enabled:
            return
        payload = {
            "ts": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            "event": str(event or "").strip() or "unknown",
        }
        for key, value in fields.items():
            payload[str(key)] = sanitize_trace_value(
                value,
                key=str(key),
                reveal_sensitive=self.reveal_sensitive,
                body_limit=self.body_limit,
            )
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as trace_file:
                trace_file.write(f"{line}\n")


def build_flow_trace_recorder(log_dir: Path) -> Optional[FlowTraceRecorder]:
    enabled = parse_bool(os.environ.get("APP_FLOW_TRACE", ""), fallback=True)
    if not enabled:
        return None

    reveal_sensitive = parse_bool(os.environ.get("APP_FLOW_TRACE_RAW", ""), fallback=False)
    body_limit_raw = os.environ.get("APP_FLOW_TRACE_BODY_LIMIT", "")
    try:
        body_limit = max(256, int(body_limit_raw or 6000))
    except Exception:
        body_limit = 6000

    trace_dir_raw = str(os.environ.get("APP_FLOW_TRACE_DIR", "flow-trace") or "flow-trace").strip()
    trace_dir = Path(trace_dir_raw)
    if not trace_dir.is_absolute():
        trace_dir = (log_dir / trace_dir).resolve()

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    trace_path = trace_dir / f"flow_trace_{ts}.jsonl"
    recorder = FlowTraceRecorder(trace_path, reveal_sensitive=reveal_sensitive, body_limit=body_limit, enabled=True)
    recorder.record(
        "flow_trace_started",
        path=str(trace_path),
        reveal_sensitive=reveal_sensitive,
        body_limit=body_limit,
        pid=os.getpid(),
    )
    return recorder


def setup_logger(log_dir: Path) -> tuple[logging.Logger, Path]:
    custom_log_file = str(os.environ.get("APP_LOG_FILE", "") or "").strip()
    if custom_log_file:
        log_path = Path(custom_log_file)
        if not log_path.is_absolute():
            log_path = (log_dir / log_path).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = log_dir / f"pool_maintainer_{ts}.log"

    logger = logging.getLogger("pool_maintainer")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    flow_trace = build_flow_trace_recorder(log_dir)
    setattr(logger, "flow_trace", flow_trace)
    if flow_trace is not None:
        logger.info("详细流程日志: %s", flow_trace.path)
    return logger, log_path


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def mgmt_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def get_item_type(item: Dict[str, Any]) -> str:
    return str(item.get("type") or item.get("typo") or "")


def is_item_disabled(item: Dict[str, Any]) -> bool:
    if parse_bool(item.get("disabled"), fallback=False):
        return True
    status_text = str(item.get("status") or item.get("state") or "").strip().lower()
    if status_text in {"disabled", "inactive"}:
        return True
    return False


def extract_chatgpt_account_id(item: Dict[str, Any]) -> Optional[str]:
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return str(val)
    return None


def safe_json_text(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {}


def normalize_status_code(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def normalize_used_percent(value: Any) -> Optional[float]:
    try:
        num = float(value)
    except Exception:
        return None
    if num < 0:
        return 0.0
    if num > 100:
        return 100.0
    return round(num, 2)


def parse_usage_body(body_raw: Any) -> tuple[Dict[str, Any], str]:
    if isinstance(body_raw, dict):
        return body_raw, json.dumps(body_raw, ensure_ascii=False)
    if isinstance(body_raw, str):
        parsed = safe_json_text(body_raw)
        return parsed if isinstance(parsed, dict) else {}, body_raw
    return {}, str(body_raw or "")


def analyze_usage_status(
    *,
    status_code: Optional[int],
    body_obj: Dict[str, Any],
    body_text: str,
    used_percent_threshold: int,
) -> Dict[str, Any]:
    rate_limit = body_obj.get("rate_limit")
    if not isinstance(rate_limit, dict):
        rate_limit = {}

    windows: List[Dict[str, Any]] = []
    for key in ("primary_window", "secondary_window"):
        window = rate_limit.get(key)
        if isinstance(window, dict):
            windows.append(window)

    used_values: List[float] = []
    for window in windows:
        value = normalize_used_percent(window.get("used_percent"))
        if value is not None:
            used_values.append(value)

    used_percent = max(used_values) if used_values else None
    over_threshold = bool(used_percent is not None and used_percent >= float(used_percent_threshold))

    limit_reached = bool(rate_limit.get("limit_reached")) or rate_limit.get("allowed") is False
    if not limit_reached:
        limit_reached = any(v >= 100.0 for v in used_values)

    merged_text = f"{json.dumps(body_obj, ensure_ascii=False)} {body_text or ''}".lower()
    quota_markers = ("quota exhausted", "limit reached", "payment_required")
    is_quota = bool(limit_reached or (status_code == 402) or any(marker in merged_text for marker in quota_markers))
    is_healthy = bool(status_code == 200 and not is_quota and not over_threshold)

    return {
        "used_percent": used_percent,
        "over_threshold": over_threshold,
        "is_quota": is_quota or over_threshold,
        "is_healthy": is_healthy,
    }


def decide_clean_action(
    *,
    status_code: Optional[int],
    disabled: bool,
    is_quota: bool,
    over_threshold: bool,
) -> str:
    if status_code == 401:
        return "delete"
    if is_quota or over_threshold:
        return "keep" if disabled else "disable"
    if status_code == 200 and disabled:
        return "enable"
    return "keep"


def pick_conf(root: Dict[str, Any], section: str, key: str, *legacy_keys: str, default: Any = None) -> Any:
    sec = root.get(section)
    if not isinstance(sec, dict):
        sec = {}

    v = sec.get(key)
    if v is None:
        for lk in legacy_keys:
            v = sec.get(lk)
            if v is not None:
                break
    if v is not None:
        return v

    v = root.get(key)
    if v is None:
        for lk in legacy_keys:
            v = root.get(lk)
            if v is not None:
                break
    if v is not None:
        return v
    return default


def pick_conf_list(root: Dict[str, Any], section: str, key: str, *legacy_keys: str) -> List[str]:
    value = pick_conf(root, section, key, *legacy_keys, default=[])
    return normalize_mail_domains(value)


def get_candidates_count_from_files(files: List[Dict[str, Any]], target_type: str) -> tuple[int, int]:
    """从已获取的文件列表中统计候选账号数量"""
    candidates = []
    for f in files:
        if get_item_type(f).lower() != target_type.lower():
            continue
        if is_item_disabled(f):
            continue
        candidates.append(f)
    return len(files), len(candidates)


def get_candidates_count(base_url: str, token: str, target_type: str, timeout: int) -> tuple[int, int]:
    """获取候选账号数量（直接调用API）"""
    url = f"{base_url.rstrip('/')}/v0/management/auth-files"
    resp = requests.get(url, headers=mgmt_headers(token), timeout=timeout)
    resp.raise_for_status()
    raw = resp.json()
    payload = raw if isinstance(raw, dict) else {}
    files = payload.get("files", []) if isinstance(payload, dict) else []
    return get_candidates_count_from_files(files, target_type)


def create_session(proxy: str = "") -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def generate_datadog_trace() -> Dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def generate_random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(length - 4))
    )
    random.shuffle(pwd)
    return "".join(pwd)


def generate_random_name() -> tuple[str, str]:
    first = ["James", "Robert", "John", "Michael", "David", "Mary", "Jennifer", "Linda", "Emma", "Olivia"]
    last = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    return random.choice(first), random.choice(last)


def generate_random_birthday() -> str:
    year = random.randint(1996, 2006)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id or str(uuid.uuid4())
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    @staticmethod
    def _base64_encode(data: Any) -> str:
        js = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        return base64.b64encode(js.encode("utf-8")).decode("ascii")

    def _get_config(self) -> List[Any]:
        now = dt.datetime.now(dt.timezone.utc).strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        return [
            "1920x1080",
            now,
            4294705152,
            random.random(),
            USER_AGENT,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            "en-US,en",
            random.random(),
            "vendorSub−undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time_origin,
        ]

    def _run_check(self, start_time: float, seed: str, difficulty: str, config: List[Any], nonce: int) -> Optional[str]:
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        if hash_hex[: len(difficulty)] <= difficulty:
            return data + "~S"
        return None

    def generate_requirements_token(self) -> str:
        cfg = self._get_config()
        cfg[3] = 1
        cfg[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(cfg)

    def generate_token(self, seed: Optional[str] = None, difficulty: Optional[str] = None) -> str:
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"
        cfg = self._get_config()
        start = time.time()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start, seed, difficulty or "0", cfg, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))


def fetch_sentinel_challenge(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[Dict[str, Any]]:
    gen = SentinelTokenGenerator(device_id=device_id)
    body = {"p": gen.generate_requirements_token(), "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": USER_AGENT,
        "Origin": "https://sentinel.openai.com",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps(body),
            headers=headers,
            timeout=15,
            verify=False,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def build_sentinel_token(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[str]:
    challenge = fetch_sentinel_challenge(session, device_id, flow)
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork", {})
    gen = SentinelTokenGenerator(device_id=device_id)
    if isinstance(pow_data, dict) and pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(seed=pow_data.get("seed"), difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = gen.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow})



def extract_verification_code(content: str) -> Optional[str]:
    if not content:
        return None
    m = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", content)
    if m:
        return m.group(1)
    m = re.search(r"Subject:.*?(\d{6})", content)
    if m and m.group(1) != "177010":
        return m.group(1)
    for pat in [r">\s*(\d{6})\s*<", r"(?<![#&])\b(\d{6})\b"]:
        for code in re.findall(pat, content):
            if code != "177010":
                return code
    return None


@dataclass(frozen=True)
class Mailbox:
    email: str
    token: str = ""
    password: str = ""
    account_id: str = ""
    domain: str = ""
    account_name: str = ""
    failure_target: str = ""


def _mail_content_signature(payload: Any) -> str:
    if isinstance(payload, (dict, list)):
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    else:
        raw = str(payload or "")
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def _flatten_mail_content(mail_obj: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("subject", "body", "text", "html", "intro"):
        value = mail_obj.get(key)
        if isinstance(value, list):
            parts.extend(str(item or "") for item in value)
        elif isinstance(value, dict):
            parts.append(json.dumps(value, ensure_ascii=False))
        elif value:
            parts.append(str(value))

    sender = mail_obj.get("from")
    if isinstance(sender, dict):
        parts.append(str(sender.get("name") or ""))
        parts.append(str(sender.get("address") or ""))
    elif isinstance(sender, list):
        parts.extend(str(item or "") for item in sender)
    elif sender:
        parts.append(str(sender))

    recipients = mail_obj.get("to")
    if isinstance(recipients, list):
        for item in recipients:
            if isinstance(item, dict):
                parts.append(str(item.get("name") or ""))
                parts.append(str(item.get("address") or ""))
            elif item:
                parts.append(str(item))
    elif recipients:
        parts.append(str(recipients))

    return " ".join(part for part in parts if part).strip()


def build_mail_api_headers(mail_api_key: str) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    token = str(mail_api_key or "").strip()
    if token:
        headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    return headers


def normalize_mail_provider(value: str) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "": "self_hosted_mail_api",
        "cfmail": "cfmail",
        "mail_api": "self_hosted_mail_api",
        "self_hosted": "self_hosted_mail_api",
        "self_hosted_mail_api": "self_hosted_mail_api",
        "duckmail": "duckmail",
        "tempmail": "tempmail_lol",
        "tempmail_lol": "tempmail_lol",
        "215": "yyds_mail",
        "215.im": "yyds_mail",
        "vip215": "yyds_mail",
        "vip.215.im": "yyds_mail",
        "yyds": "yyds_mail",
        "yyds_mail": "yyds_mail",
    }
    return aliases.get(raw, raw)


def normalize_mail_domain(value: str) -> str:
    return str(value or "").strip().lstrip("@.").rstrip(".")


def normalize_mail_domains(values: Any) -> List[str]:
    if isinstance(values, str):
        candidates = [values]
    elif isinstance(values, (list, tuple)):
        candidates = list(values)
    else:
        candidates = []

    normalized: List[str] = []
    for value in candidates:
        domain = normalize_mail_domain(str(value or ""))
        if domain and domain not in normalized:
            normalized.append(domain)
    return normalized


class MailProviderBase:
    provider_name = "unknown"

    def __init__(self, *, proxy: str, logger: logging.Logger):
        self.proxy = str(proxy or "")
        self.logger = logger
        self._thread_local = threading.local()

    def create_mailbox(self) -> Optional[Mailbox]:
        raise NotImplementedError

    @property
    def last_selected_domain(self) -> str:
        return ""

    @property
    def last_selected_target(self) -> str:
        return self.last_selected_domain

    def wait_for_availability(self, worker_id: int = 0) -> None:
        return None

    def note_domain_failure(self, domain: str, *, stage: str, detail: str = "") -> None:
        return None

    def note_domain_success(self, domain: str) -> None:
        return None

    def note_target_failure(self, target: str, *, stage: str, detail: str = "") -> None:
        self.note_domain_failure(target, stage=stage, detail=detail)

    def note_target_success(self, target: str) -> None:
        self.note_domain_success(target)

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        raise NotImplementedError

    def wait_for_verification_code(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        timeout: int = 120,
        not_before_ts: Optional[float] = None,
        poll_interval_seconds: float = 3.0,
    ) -> Optional[str]:
        seen_ids: set[str] = set()
        start = time.time()
        poll_interval = max(0.2, float(poll_interval_seconds or 3.0))
        while time.time() - start < timeout:
            codes = self.poll_verification_codes(
                mailbox,
                email=email,
                seen_ids=seen_ids,
                not_before_ts=not_before_ts,
            )
            if codes:
                return codes[0]
            time.sleep(poll_interval)
        return None

    def describe(self) -> str:
        return self.provider_name

    def _session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = create_session(proxy=self.proxy)
            self._thread_local.session = session
        return session


class DomainAwareMailProvider(MailProviderBase):
    def __init__(
        self,
        *,
        proxy: str,
        logger: logging.Logger,
        domain: str = "",
        domains: Optional[List[str]] = None,
        failure_threshold: int = 5,
        failure_cooldown_seconds: float = 45.0,
    ):
        super().__init__(proxy=proxy, logger=logger)
        normalized_domains = normalize_mail_domains(domains or [])
        if not normalized_domains:
            normalized_domains = normalize_mail_domains([domain])
        self.domains = normalized_domains
        self.failure_threshold = max(1, int(failure_threshold or 5))
        self.failure_cooldown_seconds = max(1.0, float(failure_cooldown_seconds or 45.0))
        self.domain_failure_counts: Dict[str, int] = {item: 0 for item in self.domains}
        self.domain_cooldown_until: Dict[str, float] = {item: 0.0 for item in self.domains}
        self._domain_lock = threading.Lock()
        self._round_robin_index = 0
        self._last_selected_domain = ""

    @property
    def last_selected_domain(self) -> str:
        with self._domain_lock:
            return self._last_selected_domain

    def wait_for_availability(self, worker_id: int = 0) -> None:
        if not self.domains:
            return
        while True:
            now = time.time()
            with self._domain_lock:
                next_ready_at = 0.0
                for candidate in self.domains:
                    cooldown_until = self.domain_cooldown_until.get(candidate, 0.0)
                    if cooldown_until <= now:
                        return
                    if not next_ready_at or cooldown_until < next_ready_at:
                        next_ready_at = cooldown_until
            wait_seconds = max(0.0, next_ready_at - now)
            self.logger.warning(
                "邮箱域名全部处于冷却期，provider=%s worker=%s 等待 %.1fs",
                self.provider_name,
                worker_id or "-",
                wait_seconds,
            )
            time.sleep(min(wait_seconds, 5.0))

    def acquire_domain(self) -> str:
        if not self.domains:
            return ""
        while True:
            now = time.time()
            with self._domain_lock:
                total = len(self.domains)
                next_ready_at = 0.0
                for offset in range(total):
                    idx = (self._round_robin_index + offset) % total
                    candidate = self.domains[idx]
                    cooldown_until = self.domain_cooldown_until.get(candidate, 0.0)
                    if cooldown_until > now:
                        if not next_ready_at or cooldown_until < next_ready_at:
                            next_ready_at = cooldown_until
                        continue
                    self._round_robin_index = (idx + 1) % total
                    self._last_selected_domain = candidate
                    return candidate
            wait_seconds = max(0.0, next_ready_at - now)
            self.logger.warning(
                "邮箱域名全部处于冷却期，provider=%s 等待 %.1fs",
                self.provider_name,
                wait_seconds,
            )
            time.sleep(min(wait_seconds, 5.0))

    def note_domain_failure(self, domain: str, *, stage: str, detail: str = "") -> None:
        normalized_domain = normalize_mail_domain(domain)
        if not normalized_domain or normalized_domain not in self.domain_failure_counts:
            return
        with self._domain_lock:
            failure_count = self.domain_failure_counts[normalized_domain] + 1
            self.domain_failure_counts[normalized_domain] = failure_count
            should_cooldown = failure_count >= self.failure_threshold
            cooldown_until = self.domain_cooldown_until.get(normalized_domain, 0.0)
            if should_cooldown:
                cooldown_until = max(cooldown_until, time.time() + self.failure_cooldown_seconds)
                self.domain_cooldown_until[normalized_domain] = cooldown_until
        if should_cooldown:
            self.logger.warning(
                "邮箱域名熔断: provider=%s domain=%s stage=%s detail=%s consecutive=%s/%s cooldown_until=%s",
                self.provider_name,
                normalized_domain,
                stage,
                detail or "-",
                failure_count,
                self.failure_threshold,
                dt.datetime.fromtimestamp(cooldown_until).strftime("%Y-%m-%d %H:%M:%S"),
            )
        else:
            self.logger.warning(
                "邮箱域名失败: provider=%s domain=%s stage=%s detail=%s consecutive=%s/%s",
                self.provider_name,
                normalized_domain,
                stage,
                detail or "-",
                failure_count,
                self.failure_threshold,
            )

    def note_domain_success(self, domain: str) -> None:
        normalized_domain = normalize_mail_domain(domain)
        if not normalized_domain or normalized_domain not in self.domain_failure_counts:
            return
        with self._domain_lock:
            self.domain_failure_counts[normalized_domain] = 0
            self.domain_cooldown_until[normalized_domain] = 0.0


class CfmailProvider(DomainAwareMailProvider):
    provider_name = "cfmail"
    CODE_PATTERNS = (
        r"Subject:\s*Your ChatGPT code is\s*(\d{6})",
        r"Your ChatGPT code is\s*(\d{6})",
        r"temporary verification code to continue:\s*(\d{6})",
        r"(?<![#&])\b(\d{6})\b",
    )

    def __init__(
        self,
        *,
        proxy: str,
        logger: logging.Logger,
        api_base: str,
        api_key: str,
        domain: str = "",
        domains: Optional[List[str]] = None,
        failure_threshold: int,
        failure_cooldown_seconds: float,
    ):
        super().__init__(
            proxy=proxy,
            logger=logger,
            domain=domain,
            domains=domains,
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
        self.api_base = str(api_base or "").rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.domain = self.domains[0] if self.domains else ""
        if not self.api_base:
            raise RuntimeError("cfmail.api_base 未配置，无法创建 CF Mail 邮箱。")
        if not self.api_key:
            raise RuntimeError("cfmail.api_key 未配置，无法创建 CF Mail 邮箱。")
        if not self.domains:
            raise RuntimeError("cfmail.domains 未配置，无法创建 CF Mail 邮箱。")

    def _create_address_for_domain(self, domain: str) -> Optional[Mailbox]:
        local = f"oc{secrets.token_hex(5)}"
        session = self._session()
        try:
            resp = session.post(
                f"{self.api_base}/admin/new_address",
                headers={
                    "x-admin-auth": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={"enablePrefix": True, "name": local, "domain": domain},
                timeout=15,
                verify=False,
            )
            if resp.status_code != 200:
                self.logger.warning("cfmail 创建邮箱失败: domain=%s status=%s body=%s", domain, resp.status_code, resp.text[:200])
                return None
            body = resp.json() if resp.content else {}
            if not isinstance(body, dict):
                return None
            email = str(body.get("address") or "").strip()
            jwt = str(body.get("jwt") or "").strip()
            if not email or not jwt:
                return None
            return Mailbox(
                email=email,
                token=jwt,
                domain=domain,
                failure_target=domain,
            )
        except Exception as exc:
            self.logger.warning("cfmail 创建邮箱异常: domain=%s error=%s", domain, exc)
            return None

    def create_mailbox(self) -> Optional[Mailbox]:
        selected_domain = self.acquire_domain()
        return self._create_address_for_domain(selected_domain)

    def _fetch_cfmail_messages(self, mailbox: Mailbox) -> List[Dict[str, Any]]:
        if not mailbox.token:
            return []
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/api/mails",
                params={"limit": 10, "offset": 0},
                headers={"Accept": "application/json", "Content-Type": "application/json", "Authorization": f"Bearer {mailbox.token}"},
                timeout=15,
                verify=False,
            )
            if resp.status_code != 200:
                return []
            body = resp.json() if resp.content else {}
            results = body.get("results") if isinstance(body, dict) else []
            return results if isinstance(results, list) else []
        except Exception:
            return []

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        messages = self._fetch_cfmail_messages(mailbox)
        codes: List[str] = []
        normalized_email = (email or mailbox.email).strip().lower()
        for message in messages:
            if not isinstance(message, dict):
                continue
            message_id = str(message.get("id") or message.get("createdAt") or "").strip()
            if seen_ids is not None and message_id:
                if message_id in seen_ids:
                    continue
                seen_ids.add(message_id)
            if not is_mail_recent_enough(message, not_before_ts):
                continue

            recipient = str(message.get("address") or "").strip().lower()
            if recipient and normalized_email and recipient != normalized_email:
                continue
            metadata = message.get("metadata") or {}
            content = "\n".join(
                [
                    recipient,
                    str(message.get("raw") or ""),
                    json.dumps(metadata, ensure_ascii=False),
                ]
            )
            if "openai" not in content.lower() and "chatgpt" not in content.lower():
                continue
            for pattern in self.CODE_PATTERNS:
                matched = re.search(pattern, content, re.I | re.S)
                if matched:
                    codes.append(matched.group(1))
                    break
        return list(dict.fromkeys(codes))

    def describe(self) -> str:
        return f"{self.provider_name}({self.api_base}, domains={','.join(self.domains)})"


class SelfHostedMailApiProvider(DomainAwareMailProvider):
    provider_name = "self_hosted_mail_api"

    def __init__(
        self,
        *,
        proxy: str,
        logger: logging.Logger,
        api_base: str,
        api_key: str,
        domain: str,
        domains: Optional[List[str]] = None,
        failure_threshold: int = 5,
        failure_cooldown_seconds: float = 45.0,
    ):
        super().__init__(
            proxy=proxy,
            logger=logger,
            domain=domain,
            domains=domains,
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
        self.api_base = str(api_base or "").rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.domain = self.domains[0] if self.domains else ""
        if not self.api_base:
            raise RuntimeError("mail.api_base 未配置，无法调用自建邮箱 API。")
        if not self.api_key:
            raise RuntimeError("mail.api_key 未配置，无法调用自建邮箱 API。")
        if not self.domains:
            raise RuntimeError("mail.domain 未配置，无法生成邮箱地址。")

    def create_mailbox(self) -> Optional[Mailbox]:
        selected_domain = self.acquire_domain()
        email = f"oc{secrets.token_hex(5)}@{selected_domain}"
        self.logger.info("生成临时邮箱成功: %s", email)
        return Mailbox(email=email, domain=selected_domain)

    def _fetch_latest_email(self, email: str) -> Optional[Dict[str, Any]]:
        if not email:
            return None
        session = self._session()
        try:
            res = session.get(
                f"{self.api_base}/api/latest?address={quote(email)}",
                headers=build_mail_api_headers(self.api_key),
                timeout=30,
                verify=False,
            )
            if res.status_code != 200:
                self.logger.warning(
                    "自建邮箱获取邮件失败: status=%s email=%s body=%s",
                    res.status_code,
                    email,
                    (res.text or "")[:200],
                )
                return None
            data = res.json()
            if not isinstance(data, dict):
                return None
            mail_obj = data.get("email")
            if data.get("ok") and isinstance(mail_obj, dict):
                return mail_obj
            if isinstance(mail_obj, dict):
                return mail_obj
            if any(key in data for key in ("subject", "body", "text", "html")):
                return data
        except Exception:
            return None
        return None

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        mail_obj = self._fetch_latest_email(mailbox.email)
        if not mail_obj:
            return []
        if not is_mail_recent_enough(mail_obj, not_before_ts):
            return []

        signature = _mail_content_signature(mail_obj)
        if seen_ids is not None and signature in seen_ids:
            return []
        if seen_ids is not None:
            seen_ids.add(signature)

        content = _flatten_mail_content(mail_obj)
        code = extract_verification_code(content)
        return [code] if code else []

    def describe(self) -> str:
        return f"{self.provider_name}({self.api_base}, domains={','.join(self.domains)})"


class DuckMailProvider(DomainAwareMailProvider):
    provider_name = "duckmail"

    def __init__(
        self,
        *,
        proxy: str,
        logger: logging.Logger,
        api_base: str,
        bearer: str,
        domain: str = "duckmail.sbs",
        domains: Optional[List[str]] = None,
        failure_threshold: int = 5,
        failure_cooldown_seconds: float = 45.0,
    ):
        super().__init__(
            proxy=proxy,
            logger=logger,
            domain=domain or "duckmail.sbs",
            domains=domains,
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
        self.api_base = str(api_base or "https://api.duckmail.sbs").rstrip("/")
        self.bearer = str(bearer or "").strip()
        self.domain = self.domains[0] if self.domains else normalize_mail_domain(domain or "duckmail.sbs")
        if not self.bearer:
            raise RuntimeError("duckmail.bearer 未配置，无法创建 DuckMail 邮箱。")

    def create_mailbox(self) -> Optional[Mailbox]:
        selected_domain = self.acquire_domain()
        local = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(8, 13)))
        email = f"{local}@{selected_domain}"
        password = generate_random_password()
        session = self._session()
        headers = {"Authorization": f"Bearer {self.bearer}", "Accept": "application/json"}
        try:
            resp = session.post(
                f"{self.api_base}/accounts",
                json={"address": email, "password": password},
                headers=headers,
                timeout=30,
                verify=False,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")

            token_resp = session.post(
                f"{self.api_base}/token",
                json={"address": email, "password": password},
                timeout=30,
                verify=False,
            )
            if token_resp.status_code != 200:
                raise RuntimeError(f"HTTP {token_resp.status_code}: {token_resp.text[:200]}")
            data = token_resp.json() if token_resp.content else {}
            token = str(data.get("token") or "").strip()
            if not token:
                raise RuntimeError("token 为空")
        except Exception as exc:
            self.logger.warning("DuckMail 创建邮箱失败: %s", exc)
            return None

        self.logger.info("生成 DuckMail 邮箱成功: %s", email)
        return Mailbox(email=email, password=password, token=token, domain=selected_domain)

    def _auth_headers(self, token: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _fetch_messages(self, token: str) -> List[Dict[str, Any]]:
        if not token:
            return []
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/messages",
                headers=self._auth_headers(token),
                timeout=30,
                verify=False,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            if isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("member") or data.get("data") or []
                return messages if isinstance(messages, list) else []
        except Exception:
            return []
        return []

    def _fetch_message_detail(self, token: str, message_id: str) -> Optional[Dict[str, Any]]:
        if not token or not message_id:
            return None
        normalized_id = str(message_id).split("/")[-1]
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/messages/{normalized_id}",
                headers=self._auth_headers(token),
                timeout=30,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, dict) else None
        except Exception:
            return None
        return None

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        messages = self._fetch_messages(mailbox.token)
        codes: List[str] = []
        for message in messages[:12]:
            message_id = str(message.get("id") or message.get("@id") or "").strip()
            if seen_ids is not None and message_id:
                if message_id in seen_ids:
                    continue
                seen_ids.add(message_id)

            detail = self._fetch_message_detail(mailbox.token, message_id)
            if not detail:
                continue
            if not is_mail_recent_enough(detail, not_before_ts):
                continue

            content = _flatten_mail_content(detail)
            code = extract_verification_code(content)
            if code:
                codes.append(code)
        return list(dict.fromkeys(codes))

    def describe(self) -> str:
        return f"{self.provider_name}({self.api_base}, domains={','.join(self.domains)})"


class TempMailLolProvider(MailProviderBase):
    provider_name = "tempmail_lol"

    def __init__(self, *, proxy: str, logger: logging.Logger, api_base: str):
        super().__init__(proxy=proxy, logger=logger)
        self.api_base = str(api_base or "https://api.tempmail.lol/v2").rstrip("/")

    def create_mailbox(self) -> Optional[Mailbox]:
        session = self._session()
        try:
            resp = session.post(
                f"{self.api_base}/inbox/create",
                json={},
                timeout=30,
                verify=False,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            data = resp.json() if resp.content else {}
            email = str(data.get("address") or data.get("email") or "").strip()
            token = str(data.get("token") or "").strip()
            if not email or not token:
                raise RuntimeError("address/email 或 token 为空")
        except Exception as exc:
            self.logger.warning("TempMail.lol 创建邮箱失败: %s", exc)
            return None

        self.logger.info("生成 TempMail.lol 邮箱成功: %s", email)
        return Mailbox(email=email, token=token)

    def _fetch_messages(self, token: str) -> List[Dict[str, Any]]:
        if not token:
            return []
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/inbox",
                params={"token": token},
                timeout=30,
                verify=False,
            )
            if resp.status_code != 200:
                return []
            data = resp.json() if resp.content else {}
            emails = data.get("emails") if isinstance(data, dict) else []
            return emails if isinstance(emails, list) else []
        except Exception:
            return []

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        messages = self._fetch_messages(mailbox.token)
        sorted_messages = sorted(
            messages,
            key=lambda item: item.get("date") or item.get("createdAt") or 0,
            reverse=True,
        )
        codes: List[str] = []
        for message in sorted_messages[:20]:
            message_id = str(message.get("id") or message.get("date") or message.get("createdAt") or "").strip()
            if seen_ids is not None and message_id:
                if message_id in seen_ids:
                    continue
                seen_ids.add(message_id)
            if not is_mail_recent_enough(message, not_before_ts):
                continue

            content = _flatten_mail_content(message)
            code = extract_verification_code(content)
            if code:
                codes.append(code)
        return list(dict.fromkeys(codes))

    def describe(self) -> str:
        return f"{self.provider_name}({self.api_base})"


class YYDSMailProvider(DomainAwareMailProvider):
    provider_name = "yyds_mail"

    def __init__(
        self,
        *,
        proxy: str,
        logger: logging.Logger,
        api_base: str,
        api_key: str = "",
        domain: str = "",
        domains: Optional[List[str]] = None,
        failure_threshold: int = 5,
        failure_cooldown_seconds: float = 45.0,
    ):
        super().__init__(
            proxy=proxy,
            logger=logger,
            domain=domain,
            domains=domains,
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
        self.api_base = str(api_base or "https://maliapi.215.im/v1").rstrip("/")
        self.api_key = str(api_key or "").strip()
        self.domain = self.domains[0] if self.domains else normalize_mail_domain(domain)

    def _request_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _temp_headers(self, token: str) -> Dict[str, str]:
        return {"Accept": "application/json", "Authorization": f"Bearer {token}"}

    def create_mailbox(self) -> Optional[Mailbox]:
        payload: Dict[str, Any] = {"address": f"oc{secrets.token_hex(5)}"}
        selected_domain = self.acquire_domain()
        if selected_domain:
            payload["domain"] = selected_domain

        session = self._session()
        try:
            resp = session.post(
                f"{self.api_base}/accounts",
                json=payload,
                headers=self._request_headers(),
                timeout=30,
                verify=False,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            body = resp.json() if resp.content else {}
            data = body.get("data") if isinstance(body, dict) else {}
            if not isinstance(data, dict):
                raise RuntimeError("返回 data 结构无效")
            email = str(data.get("address") or "").strip()
            token = str(data.get("token") or "").strip()
            account_id = str(data.get("id") or "").strip()
            if not email or not token:
                raise RuntimeError("address 或 token 为空")
        except Exception as exc:
            self.logger.warning("YYDS Mail 创建邮箱失败: %s", exc)
            return None

        mailbox_domain = selected_domain or normalize_mail_domain(email.partition("@")[2])
        self.logger.info("生成 YYDS Mail 邮箱成功: %s", email)
        return Mailbox(email=email, token=token, account_id=account_id, domain=mailbox_domain)

    def _fetch_messages(self, token: str) -> List[Dict[str, Any]]:
        if not token:
            return []
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/messages",
                headers=self._temp_headers(token),
                timeout=30,
                verify=False,
            )
            if resp.status_code != 200:
                return []
            body = resp.json() if resp.content else {}
            if not isinstance(body, dict):
                return []
            data = body.get("data")
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                messages = data.get("messages") or data.get("items") or data.get("list") or []
                return messages if isinstance(messages, list) else []
            messages = body.get("messages") or []
            return messages if isinstance(messages, list) else []
        except Exception:
            return []

    def _fetch_message_detail(self, token: str, message_id: str) -> Optional[Dict[str, Any]]:
        if not token or not message_id:
            return None
        normalized_id = str(message_id).split("/")[-1]
        session = self._session()
        try:
            resp = session.get(
                f"{self.api_base}/messages/{quote(normalized_id, safe='')}",
                headers=self._temp_headers(token),
                timeout=30,
                verify=False,
            )
            if resp.status_code != 200:
                return None
            body = resp.json() if resp.content else {}
            data = body.get("data") if isinstance(body, dict) else {}
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def poll_verification_codes(
        self,
        mailbox: Mailbox,
        *,
        email: str = "",
        seen_ids: Optional[set[str]] = None,
        not_before_ts: Optional[float] = None,
    ) -> List[str]:
        messages = self._fetch_messages(mailbox.token)
        codes: List[str] = []
        for message in messages[:20]:
            message_id = str(message.get("id") or "").split("/")[-1].strip()
            if seen_ids is not None and message_id:
                if message_id in seen_ids:
                    continue
                seen_ids.add(message_id)

            if is_mail_recent_enough(message, not_before_ts):
                inline_content = _flatten_mail_content(message)
                inline_code = extract_verification_code(inline_content)
                if inline_code:
                    codes.append(inline_code)
                    continue

            detail = self._fetch_message_detail(mailbox.token, message_id)
            if not detail:
                continue
            if not is_mail_recent_enough(detail, not_before_ts):
                continue

            content = _flatten_mail_content(detail)
            code = extract_verification_code(content)
            if code:
                codes.append(code)
        return list(dict.fromkeys(codes))

    def describe(self) -> str:
        detail = self.api_base
        if self.domains:
            detail += f", domains={','.join(self.domains)}"
        elif self.domain:
            detail += f", domain={self.domain}"
        return f"{self.provider_name}({detail})"


def build_mail_provider(conf: Dict[str, Any], proxy: str, logger: logging.Logger) -> MailProviderBase:
    raw_provider = str(pick_conf(conf, "mail", "provider", "mail_provider", default="") or "").strip()
    failure_threshold = int(pick_conf(conf, "run", "failure_threshold_for_cooldown", default=5) or 5)
    failure_cooldown_seconds = float(pick_conf(conf, "run", "failure_cooldown_seconds", default=45.0) or 45.0)

    if not raw_provider:
        if pick_conf(conf, "mail", "api_base", default=conf.get("mail_api_base")) or pick_conf(
            conf, "mail", "domain", default=conf.get("mail_domain")
        ):
            provider_name = "self_hosted_mail_api"
        elif pick_conf(conf, "duckmail", "bearer", default=conf.get("duckmail_bearer")):
            provider_name = "duckmail"
        elif pick_conf(conf, "yyds_mail", "api_key", default=conf.get("yyds_mail_api_key")) or pick_conf(
            conf, "yyds_mail", "domain", default=conf.get("yyds_mail_domain")
        ):
            provider_name = "yyds_mail"
        elif pick_conf(conf, "tempmail_lol", "api_base", default=conf.get("tempmail_lol_api_base")):
            provider_name = "tempmail_lol"
        else:
            provider_name = "self_hosted_mail_api"
    else:
        provider_name = normalize_mail_provider(raw_provider)

    if provider_name == "self_hosted_mail_api":
        return SelfHostedMailApiProvider(
            proxy=proxy,
            logger=logger,
            api_base=str(pick_conf(conf, "mail", "api_base", default=conf.get("mail_api_base", "")) or "").strip(),
            api_key=str(pick_conf(conf, "mail", "api_key", default=conf.get("mail_api_key", "")) or "").strip(),
            domain=str(pick_conf(conf, "mail", "domain", default=conf.get("mail_domain", "")) or "").strip(),
            domains=pick_conf_list(conf, "mail", "domains", "mail_domains"),
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
    if provider_name == "duckmail":
        return DuckMailProvider(
            proxy=proxy,
            logger=logger,
            api_base=str(
                pick_conf(conf, "duckmail", "api_base", default=conf.get("duckmail_api_base", "https://api.duckmail.sbs"))
                or "https://api.duckmail.sbs"
            ).strip(),
            bearer=str(pick_conf(conf, "duckmail", "bearer", default=conf.get("duckmail_bearer", "")) or "").strip(),
            domain=str(pick_conf(conf, "duckmail", "domain", default=conf.get("duckmail_domain", "duckmail.sbs")) or "duckmail.sbs").strip(),
            domains=pick_conf_list(conf, "duckmail", "domains", "duckmail_domains"),
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
    if provider_name == "cfmail":
        return CfmailProvider(
            proxy=proxy,
            logger=logger,
            api_base=str(pick_conf(conf, "cfmail", "api_base", default=conf.get("cfmail_api_base", "")) or "").strip(),
            api_key=str(pick_conf(conf, "cfmail", "api_key", default=conf.get("cfmail_api_key", "")) or "").strip(),
            domain=str(pick_conf(conf, "cfmail", "domain", default=conf.get("cfmail_domain", "")) or "").strip(),
            domains=pick_conf_list(conf, "cfmail", "domains", "cfmail_domains"),
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )
    if provider_name == "tempmail_lol":
        return TempMailLolProvider(
            proxy=proxy,
            logger=logger,
            api_base=str(
                pick_conf(
                    conf,
                    "tempmail_lol",
                    "api_base",
                    default=conf.get("tempmail_lol_api_base", "https://api.tempmail.lol/v2"),
                )
                or "https://api.tempmail.lol/v2"
            ).strip(),
        )
    if provider_name == "yyds_mail":
        return YYDSMailProvider(
            proxy=proxy,
            logger=logger,
            api_base=str(
                pick_conf(
                    conf,
                    "yyds_mail",
                    "api_base",
                    default=conf.get("yyds_mail_api_base", "https://maliapi.215.im/v1"),
                )
                or "https://maliapi.215.im/v1"
            ).strip(),
            api_key=str(pick_conf(conf, "yyds_mail", "api_key", default=conf.get("yyds_mail_api_key", "")) or "").strip(),
            domain=str(pick_conf(conf, "yyds_mail", "domain", default=conf.get("yyds_mail_domain", "")) or "").strip(),
            domains=pick_conf_list(conf, "yyds_mail", "domains", "yyds_mail_domains"),
            failure_threshold=failure_threshold,
            failure_cooldown_seconds=failure_cooldown_seconds,
        )

    raise RuntimeError(f"不支持的 mail.provider={provider_name}")


class ProtocolRegistrar:
    def __init__(self, proxy: str, logger: logging.Logger, conf: Optional[Dict[str, Any]] = None):
        self.proxy = proxy
        self.session = create_session(proxy=proxy)
        self.device_id = str(uuid.uuid4())
        self.logger = logger
        self.flow_trace: Optional[FlowTraceRecorder] = getattr(logger, "flow_trace", None)
        self.conf = conf or {}
        self.sentinel_gen = SentinelTokenGenerator(device_id=self.device_id)
        self.code_verifier: Optional[str] = None
        self.state: Optional[str] = None
        self.registration_auth_code = ""
        self.registration_tokens: Optional[Dict[str, Any]] = None
        self.last_failure_stage = ""
        self.last_failure_detail = ""
        self.chatgpt_base = str(
            pick_conf(self.conf, "registration", "chatgpt_base", default="https://chatgpt.com") or "https://chatgpt.com"
        ).rstrip("/")
        self.step_retry_attempts = flow_step_retry_attempts(self.conf)
        self.step_retry_delay = lambda attempt: flow_step_retry_delay(self.conf, attempt)
        self.entry_mode = parse_choice(
            pick_conf(self.conf, "registration", "entry_mode", default="chatgpt_web"),
            allowed=("direct_auth", "chatgpt_web"),
            fallback="chatgpt_web",
        )
        self.entry_mode_fallback = parse_bool(
            pick_conf(self.conf, "registration", "entry_mode_fallback", default=True),
            fallback=True,
        )
        self.transient_markers = parse_marker_config(
            pick_conf(self.conf, "flow", "transient_markers", default=TRANSIENT_FLOW_MARKERS_DEFAULT),
            fallback=TRANSIENT_FLOW_MARKERS_DEFAULT,
        )
        self.register_otp_validate_order = parse_otp_validate_order(
            pick_conf(self.conf, "flow", "register_otp_validate_order", default="normal,sentinel")
        )
        self.phone_markers = parse_marker_config(
            pick_conf(self.conf, "registration", "phone_verification_markers", default=PHONE_VERIFICATION_MARKERS_DEFAULT),
            fallback=PHONE_VERIFICATION_MARKERS_DEFAULT,
        )
        self.register_phone_action = parse_choice(
            pick_conf(
                self.conf,
                "registration",
                "register_create_account_phone_action",
                default="warn_and_continue",
            ),
            allowed=("warn_and_continue", "fail_fast"),
            fallback="warn_and_continue",
        )

    def _set_failure(self, stage: str, detail: str = "") -> None:
        self.last_failure_stage = str(stage or "").strip()
        self.last_failure_detail = str(detail or "").strip()

    def _capture_registration_tokens(
        self,
        response_payload: Dict[str, Any],
        response_headers: Optional[Dict[str, Any]] = None,
        response_url: str = "",
        response_text: str = "",
    ) -> None:
        callback_params = extract_oauth_callback_params_from_response(
            response_payload,
            response_headers=response_headers,
            response_url=response_url,
            response_text=response_text,
        )
        auth_code = str((callback_params or {}).get("code") or "").strip()
        continue_url = extract_continue_url_from_response(
            response_payload,
            response_headers=response_headers,
            response_url=response_url,
        )
        if not auth_code:
            callback_params = extract_oauth_callback_params_from_session_cookies(self.session)
            auth_code = str((callback_params or {}).get("code") or "").strip()
        if not auth_code and continue_url:
            callback_params = extract_oauth_callback_params_from_consent_session(
                session=self.session,
                consent_url=continue_url,
                oauth_issuer=OPENAI_AUTH_BASE,
                device_id=self.device_id,
                flow_trace=self.flow_trace,
            )
            auth_code = str((callback_params or {}).get("code") or "").strip()
        if not auth_code:
            callback_params = extract_oauth_callback_params_from_consent_session(
                session=self.session,
                consent_url=f"{OPENAI_AUTH_BASE}/sign-in-with-chatgpt/codex/consent",
                oauth_issuer=OPENAI_AUTH_BASE,
                device_id=self.device_id,
                flow_trace=self.flow_trace,
            )
            auth_code = str((callback_params or {}).get("code") or "").strip()
        self.registration_auth_code = str(auth_code or "")
        self.registration_tokens = build_chatgpt_session_token_result(
            session=self.session,
            auth_code=auth_code,
            callback_params=callback_params,
            chatgpt_base=self.chatgpt_base,
            logger=self.logger,
            flow_trace=self.flow_trace,
        )
        if self.flow_trace is not None:
            self.flow_trace.record(
                "registration_capture_tokens",
                auth_code=auth_code,
                continue_url=continue_url,
                has_tokens=bool(self.registration_tokens),
                email=(self.registration_tokens or {}).get("email", ""),
                account_id=(self.registration_tokens or {}).get("account_id", ""),
            )

    def _is_transient_error(self, reason: str | None) -> bool:
        return is_transient_flow_error(reason, markers=self.transient_markers)

    def _run_step_with_retry(
        self,
        step_name: str,
        action: Callable[[], tuple[bool, str]],
    ) -> tuple[bool, str]:
        max_attempts = max(1, int(self.step_retry_attempts))
        last_reason = ""
        for attempt in range(1, max_attempts + 1):
            ok, reason = action()
            if ok:
                return True, ""
            last_reason = str(reason or "")
            if attempt < max_attempts and self._is_transient_error(last_reason):
                self.logger.warning(
                    "步骤%s瞬时失败，第 %s/%s 次失败: %s，局部重试",
                    step_name,
                    attempt,
                    max_attempts,
                    last_reason or "unknown",
                )
                time.sleep(self.step_retry_delay(attempt))
                continue
            return False, last_reason
        return False, last_reason or f"{step_name}_failed"

    def _entry_mode_candidates(self) -> list[str]:
        ordered = [self.entry_mode]
        if self.entry_mode_fallback:
            fallback = "chatgpt_web" if self.entry_mode == "direct_auth" else "direct_auth"
            ordered.append(fallback)
        unique: list[str] = []
        for mode in ordered:
            if mode not in unique:
                unique.append(mode)
        return unique

    def _build_headers(self, referer: str, with_sentinel: bool = False) -> Dict[str, str]:
        h = dict(COMMON_HEADERS)
        h["referer"] = referer
        h["oai-device-id"] = self.device_id
        h.update(generate_datadog_trace())
        if with_sentinel:
            h["openai-sentinel-token"] = self.sentinel_gen.generate_token()
        return h

    def _init_session_via_direct_auth(self, client_id: str, redirect_uri: str) -> tuple[bool, str]:
        def _do_init() -> tuple[bool, str]:
            self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
            self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

            code_verifier, code_challenge = generate_pkce()
            self.code_verifier = code_verifier
            self.state = secrets.token_urlsafe(32)

            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid profile email offline_access",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": self.state,
                "screen_hint": "signup",
                "prompt": "login",
            }
            url = f"{OPENAI_AUTH_BASE}/oauth/authorize?{urlencode(params)}"
            try:
                resp = self.session.get(url, headers=NAVIGATE_HEADERS, allow_redirects=True, verify=False, timeout=30)
            except Exception as error:
                return False, f"oauth_authorize_failed:{error}"

            if resp.status_code not in (200, 302):
                return False, f"oauth_authorize_http_{resp.status_code}"
            has_login_session = any(c.name == "login_session" for c in self.session.cookies)
            if not has_login_session:
                return False, "login_session_missing"
            return True, ""

        return self._run_step_with_retry("0a_direct_auth", _do_init)

    def _init_session_via_chatgpt_web(self) -> tuple[bool, str]:
        chatgpt_base = self.chatgpt_base

        def _do_init() -> tuple[bool, str]:
            try:
                self.session.get(f"{chatgpt_base}/", headers=NAVIGATE_HEADERS, timeout=15, verify=False)
            except Exception as error:
                return False, f"chatgpt_home_failed:{error}"

            csrf_headers = {
                "accept": "application/json",
                "referer": f"{chatgpt_base}/auth/login",
                "user-agent": USER_AGENT,
            }
            try:
                csrf_resp = self.session.get(f"{chatgpt_base}/api/auth/csrf", headers=csrf_headers, timeout=15, verify=False)
            except Exception as error:
                return False, f"chatgpt_csrf_failed:{error}"
            if csrf_resp.status_code != 200:
                return False, f"chatgpt_csrf_http_{csrf_resp.status_code}"
            try:
                csrf_data = csrf_resp.json()
            except Exception as error:
                return False, f"chatgpt_csrf_parse_failed:{error}"
            csrf_token = str((csrf_data or {}).get("csrfToken") or "").strip() if isinstance(csrf_data, dict) else ""
            if not csrf_token:
                return False, "chatgpt_csrf_missing"

            signin_form = urlencode(
                {
                    "csrfToken": csrf_token,
                    "callbackUrl": f"{chatgpt_base}/",
                    "json": "true",
                }
            )
            signin_headers = {
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json",
                "origin": chatgpt_base,
                "referer": f"{chatgpt_base}/auth/login",
                "user-agent": USER_AGENT,
            }
            try:
                signin_resp = self.session.post(
                    f"{chatgpt_base}/api/auth/signin/openai",
                    headers=signin_headers,
                    data=signin_form,
                    timeout=15,
                    verify=False,
                    allow_redirects=False,
                )
            except Exception as error:
                return False, f"chatgpt_signin_openai_failed:{error}"

            auth_url = ""
            try:
                signin_payload = signin_resp.json()
            except Exception:
                signin_payload = {}
            if isinstance(signin_payload, dict):
                auth_url = str(signin_payload.get("url") or "").strip()
            if not auth_url and signin_resp.status_code in (301, 302, 303, 307, 308):
                auth_url = str(signin_resp.headers.get("Location") or "").strip()
            if not auth_url:
                return False, "chatgpt_signin_openai_missing_auth_url"

            try:
                self.session.get(auth_url, headers=NAVIGATE_HEADERS, timeout=20, verify=False)
            except Exception as error:
                return False, f"chatgpt_auth_follow_failed:{error}"

            has_login_session = any(c.name == "login_session" for c in self.session.cookies)
            if not has_login_session:
                return False, "login_session_missing"
            return True, ""

        return self._run_step_with_retry("0a_chatgpt_web", _do_init)

    def _submit_signup_email(self, email: str) -> tuple[bool, str]:
        def _do_submit() -> tuple[bool, str]:
            headers = self._build_headers(f"{OPENAI_AUTH_BASE}/create-account")
            sentinel = build_sentinel_token(self.session, self.device_id, flow="authorize_continue")
            if sentinel:
                headers["openai-sentinel-token"] = sentinel
            try:
                response = self.session.post(
                    f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue",
                    json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
                    headers=headers,
                    verify=False,
                    timeout=30,
                )
            except Exception as error:
                return False, f"authorize_continue_failed:{error}"
            if response.status_code != 200:
                return False, f"authorize_continue_http_{response.status_code}"
            return True, ""

        return self._run_step_with_retry("0b_authorize_continue", _do_submit)

    def step0_init_oauth_session(self, email: str, client_id: str, redirect_uri: str) -> bool:
        last_reason = "init_oauth_session_failed"
        for index, mode in enumerate(self._entry_mode_candidates(), start=1):
            if mode == "chatgpt_web":
                ok, reason = self._init_session_via_chatgpt_web()
            else:
                ok, reason = self._init_session_via_direct_auth(client_id=client_id, redirect_uri=redirect_uri)
            if not ok:
                last_reason = reason or f"{mode}_failed"
                if index < len(self._entry_mode_candidates()):
                    self.logger.warning("会话入口 %s 失败: %s，尝试下一个入口", mode, last_reason)
                continue

            ok, reason = self._submit_signup_email(email)
            if ok:
                if index > 1:
                    self.logger.info("入口回退成功: mode=%s", mode)
                return True
            last_reason = reason or "authorize_continue_failed"

        self.logger.warning("步骤0失败: %s", last_reason)
        self._set_failure("step0_init_oauth_session", last_reason)
        return False

    def step2_register_user(self, email: str, password: str) -> bool:
        def _do_register() -> tuple[bool, str]:
            headers = self._build_headers(
                f"{OPENAI_AUTH_BASE}/create-account/password",
                with_sentinel=True,
            )
            try:
                resp = self.session.post(
                    f"{OPENAI_AUTH_BASE}/api/accounts/user/register",
                    json={"username": email, "password": password},
                    headers=headers,
                    verify=False,
                    timeout=30,
                )
            except Exception as error:
                return False, f"user_register_failed:{error}"
            if resp.status_code == 200:
                return True, ""
            if resp.status_code in (301, 302):
                loc = str(resp.headers.get("Location") or "")
                ok_redirect = "email-otp" in loc or "email-verification" in loc
                if ok_redirect:
                    return True, ""
                return False, f"user_register_redirect_invalid:{loc}"
            return False, f"user_register_http_{resp.status_code}"

        ok, reason = self._run_step_with_retry("2_register_user", _do_register)
        if not ok:
            self._set_failure("step2_register_user", reason)
            self.logger.warning("步骤2失败: email=%s reason=%s", email, reason)
        return ok

    def step3_send_otp(self) -> bool:
        headers = dict(NAVIGATE_HEADERS)
        headers["referer"] = f"{OPENAI_AUTH_BASE}/create-account/password"

        def _do_send() -> tuple[bool, str]:
            try:
                r_send = self.session.get(
                    f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send",
                    headers=headers,
                    verify=False,
                    timeout=30,
                    allow_redirects=True,
                )
            except Exception as error:
                return False, f"email_otp_send_failed:{error}"
            if r_send.status_code not in (200, 204, 301, 302):
                return False, f"email_otp_send_http_{r_send.status_code}"
            return True, ""

        ok, reason = self._run_step_with_retry("3_send_otp", _do_send)
        if not ok:
            self._set_failure("step3_send_otp", reason)
            self.logger.warning("步骤3失败: send_otp reason=%s", reason)
            return False

        def _open_verify_page() -> tuple[bool, str]:
            try:
                r_page = self.session.get(
                    f"{OPENAI_AUTH_BASE}/email-verification",
                    headers=headers,
                    verify=False,
                    timeout=30,
                    allow_redirects=True,
                )
            except Exception as error:
                return False, f"email_verification_page_failed:{error}"
            if r_page.status_code >= 400:
                return False, f"email_verification_page_http_{r_page.status_code}"
            return True, ""

        ok, reason = self._run_step_with_retry("3_open_verification_page", _open_verify_page)
        if not ok:
            self._set_failure("step3_open_verification_page", reason)
            self.logger.warning("步骤3失败: open_verification_page reason=%s", reason)
        return ok

    def step4_validate_otp(self, code: str) -> bool:
        last_reason = "otp_validate_failed"
        tried_normal = False
        for mode in self.register_otp_validate_order:
            include_sentinel = mode == "sentinel"
            headers = self._build_headers(
                f"{OPENAI_AUTH_BASE}/email-verification",
                with_sentinel=include_sentinel,
            )
            if include_sentinel and tried_normal:
                self.logger.warning("步骤4告警: 普通 OTP 校验失败，尝试 Sentinel fallback")

            def _do_validate() -> tuple[bool, str]:
                try:
                    response = self.session.post(
                        f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate",
                        json={"code": code},
                        headers=headers,
                        verify=False,
                        timeout=30,
                    )
                except Exception as error:
                    return False, f"email_otp_validate_failed:{error}"
                if response.status_code == 200:
                    return True, ""
                return False, f"email_otp_validate_http_{response.status_code}"

            ok, reason = self._run_step_with_retry(f"4_validate_otp_{mode}", _do_validate)
            if ok:
                if include_sentinel:
                    self.logger.info("步骤4成功: OTP Sentinel fallback 命中")
                return True
            last_reason = reason or last_reason
            tried_normal = tried_normal or not include_sentinel

        self.logger.warning("步骤4失败: code=%s reason=%s", code, last_reason)
        self._set_failure("step4_validate_otp", last_reason)
        return False

    def step5_create_account(self, first_name: str, last_name: str, birthdate: str) -> bool:
        body = {"name": f"{first_name} {last_name}", "birthdate": birthdate}

        def _do_create() -> tuple[bool, str]:
            headers = self._build_headers(f"{OPENAI_AUTH_BASE}/about-you", with_sentinel=True)
            try:
                response = self.session.post(
                    f"{OPENAI_AUTH_BASE}/api/accounts/create_account",
                    json=body,
                    headers=headers,
                    verify=False,
                    timeout=30,
                )
            except Exception as error:
                return False, f"create_account_failed:{error}"

            response_payload: Dict[str, Any] = {}
            if str(response.headers.get("content-type") or "").startswith("application/json"):
                try:
                    payload = response.json()
                except Exception:
                    payload = {}
                if isinstance(payload, dict):
                    response_payload = payload

            if requires_phone_verification(
                response_payload,
                response.text,
                markers=self.phone_markers,
            ):
                if self.register_phone_action == "fail_fast":
                    return False, "create_account_phone_verification_required"
                # self.logger.warning("步骤5告警: 命中手机验证风控，按策略保留成功态继续后续 OAuth")

            if self.flow_trace is not None:
                self.flow_trace.record(
                    "registration_create_account_response",
                    status_code=response.status_code,
                    response=build_response_trace_payload(
                        response,
                        reveal_sensitive=self.flow_trace.reveal_sensitive,
                        body_limit=self.flow_trace.body_limit,
                    ),
                    phone_verification=requires_phone_verification(
                        response_payload,
                        response.text,
                        markers=self.phone_markers,
                    ),
                )

            if response.status_code == 200:
                self._capture_registration_tokens(
                    response_payload,
                    response_headers=response.headers,
                    response_url=str(response.url or ""),
                    response_text=response.text,
                )
                return True, ""
            if response.status_code in (301, 302):
                self._capture_registration_tokens(
                    response_payload,
                    response_headers=response.headers,
                    response_url=str(response.url or ""),
                    response_text=response.text,
                )
                return True, ""
            if response.status_code == 400 and "already_exists" in response.text.lower():
                return True, ""
            return False, f"create_account_http_{response.status_code}"

        ok, reason = self._run_step_with_retry("5_create_account", _do_create)
        if not ok:
            self._set_failure("step5_create_account", reason)
            self.logger.warning("步骤5失败: reason=%s", reason)
        return ok

    def register(
        self,
        email: str,
        password: str,
        client_id: str,
        redirect_uri: str,
        mailbox: Mailbox,
        mail_provider: MailProviderBase,
        otp_timeout_seconds: int = 120,
        otp_poll_interval_seconds: float = 3.0,
    ) -> bool:
        self.last_failure_stage = ""
        self.last_failure_detail = ""
        self.registration_auth_code = ""
        self.registration_tokens = None
        first_name, last_name = generate_random_name()
        birthdate = generate_random_birthday()
        if not self.step0_init_oauth_session(email, client_id, redirect_uri):
            if not self.last_failure_stage:
                self._set_failure("step0_init_oauth_session")
            self.logger.warning("注册失败: step0_init_oauth_session | email=%s", email)
            return False
        time.sleep(1)
        if not self.step2_register_user(email, password):
            if not self.last_failure_stage:
                self._set_failure("step2_register_user")
            self.logger.warning("注册失败: step2_register_user | email=%s", email)
            return False
        time.sleep(1)
        otp_requested_at = time.time()
        if not self.step3_send_otp():
            if not self.last_failure_stage:
                self._set_failure("step3_send_otp")
            self.logger.warning("注册失败: step3_send_otp | email=%s", email)
            return False
        code = mail_provider.wait_for_verification_code(
            mailbox,
            email=email,
            timeout=max(30, int(otp_timeout_seconds or 120)),
            not_before_ts=otp_requested_at,
            poll_interval_seconds=otp_poll_interval_seconds,
        )
        if not code:
            self._set_failure("register_mail_otp_timeout", f"provider={mail_provider.provider_name}")
            self.logger.warning("注册失败: 未收到验证码 | email=%s", email)
            return False
        if not self.step4_validate_otp(code):
            if not self.last_failure_stage:
                self._set_failure("step4_validate_otp")
            self.logger.warning("注册失败: step4_validate_otp | email=%s", email)
            return False
        time.sleep(1)
        ok = self.step5_create_account(first_name, last_name, birthdate)
        if not ok:
            if not self.last_failure_stage:
                self._set_failure("step5_create_account")
            self.logger.warning("注册失败: step5_create_account | email=%s", email)
        return ok

    def exchange_codex_tokens(self, client_id: str, redirect_uri: str) -> Optional[Dict[str, Any]]:
        if not self.code_verifier:
            self.logger.warning("注册会话缺少 code_verifier，无法直接换取 OAuth token")
            return None

        consent_url = f"{OPENAI_AUTH_BASE}/sign-in-with-chatgpt/codex/consent"
        return exchange_codex_tokens_from_session(
            session=self.session,
            device_id=self.device_id,
            code_verifier=self.code_verifier,
            consent_url=consent_url,
            oauth_issuer=OPENAI_AUTH_BASE,
            oauth_client_id=client_id,
            oauth_redirect_uri=redirect_uri,
            proxy=self.proxy,
        )


def codex_exchange_code(
    code: str,
    code_verifier: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    proxy: str,
) -> Optional[Dict[str, Any]]:
    session = create_session(proxy=proxy)
    try:
        resp = session.post(
            f"{oauth_issuer}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth_redirect_uri,
                "client_id": oauth_client_id,
                "code_verifier": code_verifier,
            },
            verify=False,
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else None
        return None
    except Exception:
        return None


def request_with_local_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    retry_attempts: int,
    error_prefix: str,
    transient_markers: tuple[str, ...] = TRANSIENT_FLOW_MARKERS_DEFAULT,
    logger: Optional[logging.Logger] = None,
    flow_trace: Optional[FlowTraceRecorder] = None,
    **request_kwargs: Any,
) -> tuple[Optional[requests.Response], str]:
    request_fn = getattr(session, method)
    safe_attempts = max(1, int(retry_attempts))
    for attempt in range(1, safe_attempts + 1):
        started_at = time.time()
        if flow_trace is not None:
            flow_trace.record(
                "http_attempt",
                error_prefix=error_prefix,
                attempt=attempt,
                total_attempts=safe_attempts,
                request={
                    "method": method.upper(),
                    "url": url,
                    "headers": request_kwargs.get("headers", {}),
                    "json": request_kwargs.get("json"),
                    "data": request_kwargs.get("data"),
                    "timeout": request_kwargs.get("timeout"),
                    "allow_redirects": request_kwargs.get("allow_redirects"),
                    "verify": request_kwargs.get("verify"),
                },
                session_cookies=describe_session_cookies(session, reveal_sensitive=flow_trace.reveal_sensitive),
            )
        try:
            response = request_fn(url, **request_kwargs)
        except Exception as error:
            reason = f"{error_prefix}_exception:{error}"
            if flow_trace is not None:
                flow_trace.record(
                    "http_exception",
                    error_prefix=error_prefix,
                    attempt=attempt,
                    total_attempts=safe_attempts,
                    elapsed_ms=round((time.time() - started_at) * 1000, 2),
                    reason=reason,
                    error=repr(error),
                    session_cookies=describe_session_cookies(session, reveal_sensitive=flow_trace.reveal_sensitive),
                )
            if attempt < safe_attempts and is_transient_flow_error(reason, transient_markers):
                if logger:
                    logger.warning(
                        "请求%s瞬时异常，第 %s/%s 次失败: %s，局部重试",
                        error_prefix,
                        attempt,
                        safe_attempts,
                        error,
                    )
                if flow_trace is not None:
                    sleep_seconds = min(0.8, 0.2 * attempt)
                    flow_trace.record(
                        "http_retry_scheduled",
                        error_prefix=error_prefix,
                        attempt=attempt,
                        total_attempts=safe_attempts,
                        reason=reason,
                        sleep_seconds=sleep_seconds,
                    )
                time.sleep(min(0.8, 0.2 * attempt))
                continue
            return None, reason

        reason = f"{error_prefix}_http_{response.status_code}"
        if flow_trace is not None:
            flow_trace.record(
                "http_response",
                error_prefix=error_prefix,
                attempt=attempt,
                total_attempts=safe_attempts,
                elapsed_ms=round((time.time() - started_at) * 1000, 2),
                response=build_response_trace_payload(
                    response,
                    reveal_sensitive=flow_trace.reveal_sensitive,
                    body_limit=flow_trace.body_limit,
                ),
                session_cookies=describe_session_cookies(session, reveal_sensitive=flow_trace.reveal_sensitive),
            )
        if attempt < safe_attempts and is_transient_flow_error(reason, transient_markers):
            if logger:
                logger.warning(
                    "请求%s返回 HTTP %s，第 %s/%s 次重试",
                    error_prefix,
                    response.status_code,
                    attempt,
                    safe_attempts,
                )
            if flow_trace is not None:
                sleep_seconds = min(0.8, 0.2 * attempt)
                flow_trace.record(
                    "http_retry_scheduled",
                    error_prefix=error_prefix,
                    attempt=attempt,
                    total_attempts=safe_attempts,
                    reason=reason,
                    sleep_seconds=sleep_seconds,
                )
            time.sleep(min(0.8, 0.2 * attempt))
            continue
        return response, ""
    return None, f"{error_prefix}_failed"


def validate_otp_with_fallback(
    *,
    session: requests.Session,
    oauth_issuer: str,
    device_id: str,
    code: str,
    base_headers: Dict[str, str],
    retry_attempts: int,
    otp_validate_order: tuple[str, ...],
    transient_markers: tuple[str, ...],
    logger: Optional[logging.Logger] = None,
    flow_trace: Optional[FlowTraceRecorder] = None,
) -> tuple[Optional[requests.Response], str]:
    last_reason = "oauth_email_otp_validate_failed"
    tried_normal = False

    for mode in otp_validate_order:
        headers = dict(base_headers)
        if flow_trace is not None:
            flow_trace.record(
                "oauth_otp_validate_mode_start",
                mode=mode,
                tried_normal=tried_normal,
            )
        if mode == "sentinel":
            if tried_normal and logger:
                logger.warning("OAuth: 普通 OTP 校验失败，尝试 Sentinel fallback")
            sentinel_token = build_sentinel_token(session, device_id, flow="authorize_continue")
            if not sentinel_token:
                last_reason = "oauth_email_otp_validate_sentinel_failed"
                if flow_trace is not None:
                    flow_trace.record("oauth_otp_validate_mode_failed", mode=mode, reason=last_reason)
                continue
            headers["openai-sentinel-token"] = sentinel_token

        response, error = request_with_local_retry(
            session,
            "post",
            f"{oauth_issuer}/api/accounts/email-otp/validate",
            retry_attempts=retry_attempts,
            error_prefix="oauth_email_otp_validate",
            transient_markers=transient_markers,
            logger=logger,
            flow_trace=flow_trace,
            json={"code": code},
            headers=headers,
            verify=False,
            timeout=30,
        )
        if response is None:
            last_reason = error or last_reason
            if flow_trace is not None:
                flow_trace.record("oauth_otp_validate_mode_failed", mode=mode, reason=last_reason)
            tried_normal = tried_normal or mode == "normal"
            continue
        if response.status_code == 200:
            if flow_trace is not None:
                flow_trace.record("oauth_otp_validate_mode_success", mode=mode, status_code=response.status_code)
            return response, ""
        last_reason = f"oauth_email_otp_validate_http_{response.status_code}"
        if flow_trace is not None:
            flow_trace.record("oauth_otp_validate_mode_failed", mode=mode, reason=last_reason)
        tried_normal = tried_normal or mode == "normal"

    return None, last_reason


def exchange_codex_tokens_from_session(
    session: requests.Session,
    device_id: str,
    code_verifier: str,
    consent_url: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    proxy: str,
) -> Optional[Dict[str, Any]]:
    auth_code = extract_auth_code_from_consent_session(
        session=session,
        consent_url=consent_url,
        oauth_issuer=oauth_issuer,
        device_id=device_id,
    )
    if not auth_code:
        return None

    return codex_exchange_code(
        auth_code,
        code_verifier,
        oauth_issuer=oauth_issuer,
        oauth_client_id=oauth_client_id,
        oauth_redirect_uri=oauth_redirect_uri,
        proxy=proxy,
    )


def extract_oauth_callback_params_from_consent_session(
    session: requests.Session,
    consent_url: str,
    oauth_issuer: str,
    device_id: str = "",
    flow_trace: Optional[FlowTraceRecorder] = None,
) -> Optional[Dict[str, str]]:
    if not consent_url:
        return None

    if consent_url.startswith("/"):
        consent_url = f"{oauth_issuer}{consent_url}"

    def _decode_auth_session(session_obj: requests.Session) -> Optional[Dict[str, Any]]:
        for c in session_obj.cookies:
            if c.name == "oai-client-auth-session":
                val = c.value
                first_part = val.split(".")[0] if "." in val else val
                pad = 4 - len(first_part) % 4
                if pad != 4:
                    first_part += "=" * pad
                try:
                    raw = base64.urlsafe_b64decode(first_part)
                    data = json.loads(raw.decode("utf-8"))
                    return data if isinstance(data, dict) else None
                except Exception:
                    pass
        return None

    def _follow_and_extract_callback_params(
        session_obj: requests.Session,
        url: str,
        max_depth: int = 10,
    ) -> Optional[Dict[str, str]]:
        if max_depth <= 0:
            return None
        try:
            r = session_obj.get(
                url,
                headers=NAVIGATE_HEADERS,
                verify=False,
                timeout=15,
                allow_redirects=False,
            )
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                callback_params = extract_oauth_callback_params_from_url(loc)
                if callback_params:
                    return callback_params
                if loc.startswith("/"):
                    loc = f"{oauth_issuer}{loc}"
                return _follow_and_extract_callback_params(session_obj, loc, max_depth - 1)
            if r.status_code == 200:
                return extract_oauth_callback_params_from_url(str(r.url))
        except requests.exceptions.ConnectionError as e:
            m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if m:
                return extract_oauth_callback_params_from_url(m.group(1))
        except Exception:
            pass
        return None

    callback_params = None
    if flow_trace is not None:
        flow_trace.record("registration_consent_follow_start", consent_url=consent_url)

    try:
        resp_consent = session.get(
            consent_url,
            headers=NAVIGATE_HEADERS,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        if resp_consent.status_code in (301, 302, 303, 307, 308):
            loc = resp_consent.headers.get("Location", "")
            callback_params = extract_oauth_callback_params_from_url(loc)
            if not callback_params:
                callback_params = _follow_and_extract_callback_params(session, loc)
    except requests.exceptions.ConnectionError as e:
        m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
        if m:
            callback_params = extract_oauth_callback_params_from_url(m.group(1))
    except Exception:
        pass

    if not callback_params:
        session_data = _decode_auth_session(session)
        workspace_id = None
        if session_data:
            workspaces = session_data.get("workspaces", [])
            if isinstance(workspaces, list) and workspaces:
                workspace_id = (workspaces[0] or {}).get("id")

        if workspace_id:
            h_consent = dict(COMMON_HEADERS)
            h_consent["referer"] = consent_url
            h_consent["oai-device-id"] = device_id
            h_consent.update(generate_datadog_trace())

            try:
                resp_ws = session.post(
                    f"{oauth_issuer}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers=h_consent,
                    verify=False,
                    timeout=30,
                    allow_redirects=False,
                )
                if resp_ws.status_code in (301, 302, 303, 307, 308):
                    loc = resp_ws.headers.get("Location", "")
                    callback_params = extract_oauth_callback_params_from_url(loc)
                    if not callback_params:
                        callback_params = _follow_and_extract_callback_params(session, loc)
                elif resp_ws.status_code == 200:
                    ws_data = resp_ws.json()
                    ws_next = str(ws_data.get("continue_url") or "")
                    ws_page = str(((ws_data.get("page") or {}).get("type")) or "")

                    if "organization" in ws_next or "organization" in ws_page:
                        org_url = ws_next if ws_next.startswith("http") else f"{oauth_issuer}{ws_next}"

                        org_id = None
                        project_id = None
                        ws_orgs = (ws_data.get("data") or {}).get("orgs", []) if isinstance(ws_data, dict) else []
                        if ws_orgs:
                            org_id = (ws_orgs[0] or {}).get("id")
                            projects = (ws_orgs[0] or {}).get("projects", [])
                            if projects:
                                project_id = (projects[0] or {}).get("id")

                        if org_id:
                            body = {"org_id": org_id}
                            if project_id:
                                body["project_id"] = project_id

                            h_org = dict(COMMON_HEADERS)
                            h_org["referer"] = org_url
                            h_org["oai-device-id"] = device_id
                            h_org.update(generate_datadog_trace())

                            resp_org = session.post(
                                f"{oauth_issuer}/api/accounts/organization/select",
                                json=body,
                                headers=h_org,
                                verify=False,
                                timeout=30,
                                allow_redirects=False,
                            )
                            if resp_org.status_code in (301, 302, 303, 307, 308):
                                loc = resp_org.headers.get("Location", "")
                                callback_params = extract_oauth_callback_params_from_url(loc)
                                if not callback_params:
                                    callback_params = _follow_and_extract_callback_params(session, loc)
                            elif resp_org.status_code == 200:
                                org_data = resp_org.json()
                                org_next = str(org_data.get("continue_url") or "")
                                if org_next:
                                    full_next = org_next if org_next.startswith("http") else f"{oauth_issuer}{org_next}"
                                    callback_params = _follow_and_extract_callback_params(session, full_next)
                        else:
                            callback_params = _follow_and_extract_callback_params(session, org_url)
                    elif ws_next:
                        full_next = ws_next if ws_next.startswith("http") else f"{oauth_issuer}{ws_next}"
                        callback_params = _follow_and_extract_callback_params(session, full_next)
            except Exception:
                pass

    if not callback_params:
        try:
            resp_fallback = session.get(
                consent_url,
                headers=NAVIGATE_HEADERS,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            callback_params = extract_oauth_callback_params_from_url(str(resp_fallback.url))
            if not callback_params and resp_fallback.history:
                for hist in resp_fallback.history:
                    loc = hist.headers.get("Location", "")
                    callback_params = extract_oauth_callback_params_from_url(loc)
                    if callback_params:
                        break
        except requests.exceptions.ConnectionError as e:
            m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if m:
                callback_params = extract_oauth_callback_params_from_url(m.group(1))
        except Exception:
            pass

    if flow_trace is not None:
        flow_trace.record(
            "registration_consent_follow_result",
            consent_url=consent_url,
            auth_code=str((callback_params or {}).get("code") or ""),
        )

    return callback_params


def extract_auth_code_from_consent_session(
    session: requests.Session,
    consent_url: str,
    oauth_issuer: str,
    device_id: str = "",
    flow_trace: Optional[FlowTraceRecorder] = None,
) -> Optional[str]:
    callback_params = extract_oauth_callback_params_from_consent_session(
        session=session,
        consent_url=consent_url,
        oauth_issuer=oauth_issuer,
        device_id=device_id,
        flow_trace=flow_trace,
    )
    return str((callback_params or {}).get("code") or "").strip() or None


def perform_codex_oauth_login_http(
    email: str,
    password: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    proxy: str,
    mail_provider: Optional[MailProviderBase] = None,
    mailbox: Optional[Mailbox] = None,
    otp_timeout_seconds: int = 120,
    otp_poll_interval_seconds: float = 2.0,
    local_retry_attempts: int = 1,
    transient_markers: tuple[str, ...] = TRANSIENT_FLOW_MARKERS_DEFAULT,
    otp_validate_order: tuple[str, ...] = ("normal", "sentinel"),
    phone_markers: tuple[str, ...] = PHONE_VERIFICATION_MARKERS_DEFAULT,
    password_phone_action: str = "warn_and_continue",
    otp_phone_action: str = "warn_and_continue",
    logger: Optional[logging.Logger] = None,
    flow_trace: Optional[FlowTraceRecorder] = None,
) -> Optional[Dict[str, Any]]:
    active_trace = flow_trace or getattr(logger, "flow_trace", None)

    def fail(stage: str, detail: str = "") -> Optional[Dict[str, Any]]:
        if active_trace is not None:
            active_trace.record(
                "oauth_flow_fail",
                email=email,
                stage=stage,
                detail=detail,
                session_cookies=describe_session_cookies(session, reveal_sensitive=active_trace.reveal_sensitive),
            )
        if logger:
            logger.warning("OAuth流程失败: stage=%s email=%s detail=%s", stage, email, detail or "-")
        return None

    safe_local_retry_attempts = max(1, int(local_retry_attempts))
    safe_transient_markers = parse_marker_config(
        transient_markers,
        fallback=TRANSIENT_FLOW_MARKERS_DEFAULT,
    )
    safe_otp_validate_order = parse_otp_validate_order(otp_validate_order)
    safe_password_phone_action = parse_choice(
        password_phone_action,
        allowed=("warn_and_continue", "fail_fast"),
        fallback="warn_and_continue",
    )
    safe_otp_phone_action = parse_choice(
        otp_phone_action,
        allowed=("warn_and_continue", "fail_fast"),
        fallback="warn_and_continue",
    )
    safe_phone_markers = parse_marker_config(phone_markers, fallback=PHONE_VERIFICATION_MARKERS_DEFAULT)

    session = create_session(proxy=proxy)
    device_id = str(uuid.uuid4())
    if active_trace is not None:
        active_trace.record(
            "oauth_flow_start",
            email=email,
            oauth_issuer=oauth_issuer,
            oauth_client_id=oauth_client_id,
            oauth_redirect_uri=oauth_redirect_uri,
            local_retry_attempts=safe_local_retry_attempts,
            otp_validate_order=safe_otp_validate_order,
            password_phone_action=safe_password_phone_action,
            otp_phone_action=safe_otp_phone_action,
        )

    session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
    session.cookies.set("oai-did", device_id, domain="auth.openai.com")

    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    authorize_params = {
        "response_type": "code",
        "client_id": oauth_client_id,
        "redirect_uri": oauth_redirect_uri,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    authorize_url = f"{oauth_issuer}/oauth/authorize?{urlencode(authorize_params)}"

    authorize_resp, authorize_error = request_with_local_retry(
        session,
        "get",
        authorize_url,
        retry_attempts=safe_local_retry_attempts,
        error_prefix="authorize_bootstrap_request",
        transient_markers=safe_transient_markers,
        logger=logger,
        flow_trace=active_trace,
        headers=NAVIGATE_HEADERS,
        allow_redirects=True,
        verify=False,
        timeout=30,
    )
    if authorize_resp is None:
        return fail("authorize_bootstrap_request", authorize_error)

    headers = dict(COMMON_HEADERS)
    headers["referer"] = f"{oauth_issuer}/log-in"
    headers["oai-device-id"] = device_id
    headers.update(generate_datadog_trace())

    sentinel_email = build_sentinel_token(session, device_id, flow="authorize_continue")
    if not sentinel_email:
        return fail("authorize_continue_sentinel")
    headers["openai-sentinel-token"] = sentinel_email

    resp, continue_error = request_with_local_retry(
        session,
        "post",
        f"{oauth_issuer}/api/accounts/authorize/continue",
        retry_attempts=safe_local_retry_attempts,
        error_prefix="authorize_continue_request",
        transient_markers=safe_transient_markers,
        logger=logger,
        flow_trace=active_trace,
        json={"username": {"kind": "email", "value": email}, "screen_hint": "login"},
        headers=headers,
        verify=False,
        timeout=30,
    )
    if resp is None:
        return fail("authorize_continue_request", continue_error)

    if resp.status_code != 200:
        return fail("authorize_continue_status", f"http={resp.status_code}")

    authorize_continue_url = ""
    try:
        continue_payload = resp.json()
        authorize_continue_url = str(continue_payload.get("continue_url") or "")
    except Exception:
        authorize_continue_url = ""
        continue_payload = {}
    if active_trace is not None:
        active_trace.record(
            "oauth_authorize_continue_parsed",
            continue_url=authorize_continue_url,
            payload=continue_payload,
        )

    if authorize_continue_url:
        follow_resp, follow_error = request_with_local_retry(
            session,
            "get",
            authorize_continue_url,
            retry_attempts=safe_local_retry_attempts,
            error_prefix="authorize_continue_follow_request",
            transient_markers=safe_transient_markers,
            logger=logger,
            flow_trace=active_trace,
            headers=NAVIGATE_HEADERS,
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
        if follow_resp is None:
            return fail("authorize_continue_follow_request", follow_error)

    headers["referer"] = f"{oauth_issuer}/log-in/password"
    headers.update(generate_datadog_trace())

    sentinel_pwd = build_sentinel_token(session, device_id, flow="password_verify")
    if not sentinel_pwd:
        return fail("password_verify_sentinel")
    headers["openai-sentinel-token"] = sentinel_pwd

    otp_requested_at = time.time()
    resp, verify_error = request_with_local_retry(
        session,
        "post",
        f"{oauth_issuer}/api/accounts/password/verify",
        retry_attempts=safe_local_retry_attempts,
        error_prefix="password_verify_request",
        transient_markers=safe_transient_markers,
        logger=logger,
        flow_trace=active_trace,
        json={"password": password},
        headers=headers,
        verify=False,
        timeout=30,
        allow_redirects=False,
    )
    if resp is None:
        return fail("password_verify_request", verify_error)

    if resp.status_code != 200:
        return fail("password_verify_status", f"http={resp.status_code}")

    continue_url = None
    page_type = ""
    password_payload: Dict[str, Any] = {}
    try:
        data = resp.json()
        if isinstance(data, dict):
            password_payload = data
        continue_url = str(data.get("continue_url") or "")
        page_type = str(((data.get("page") or {}).get("type")) or "")
    except Exception:
        pass

    if requires_phone_verification(password_payload, resp.text, markers=safe_phone_markers):
        if safe_password_phone_action == "fail_fast":
            return fail("oauth_phone_verification_required", "password_verify")
        if logger:
            logger.warning("OAuth 命中手机验证信号，按策略继续后续路径")
    if active_trace is not None:
        active_trace.record(
            "oauth_password_verify_parsed",
            continue_url=continue_url,
            page_type=page_type,
            phone_verification=requires_phone_verification(password_payload, resp.text, markers=safe_phone_markers),
            payload=password_payload,
        )

    if not continue_url:
        return fail("missing_continue_url")

    if page_type == "email_otp_verification" or "email-verification" in continue_url:
        if not mail_provider or not mailbox:
            return fail("oauth_mailbox_required")

        otp_entry_url = continue_url if continue_url.startswith("http") else f"{oauth_issuer}/email-verification"
        otp_entry_resp, otp_entry_error = request_with_local_retry(
            session,
            "get",
            otp_entry_url,
            retry_attempts=safe_local_retry_attempts,
            error_prefix="email_verification_bootstrap_request",
            transient_markers=safe_transient_markers,
            logger=logger,
            flow_trace=active_trace,
            headers=NAVIGATE_HEADERS,
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
        if otp_entry_resp is None:
            return fail("email_verification_bootstrap_request", otp_entry_error)

        tried_codes = set()
        seen_ids: set[str] = set()
        start_time = time.time()

        h_val = dict(COMMON_HEADERS)
        h_val["referer"] = f"{oauth_issuer}/email-verification"
        h_val["oai-device-id"] = device_id
        h_val.update(generate_datadog_trace())

        code = None
        otp_timeout = max(30, int(otp_timeout_seconds or 120))
        poll_interval = max(1.0, float(otp_poll_interval_seconds or 2.0))
        if active_trace is not None:
            active_trace.record(
                "oauth_otp_poll_start",
                otp_entry_url=otp_entry_url,
                otp_timeout=otp_timeout,
                poll_interval=poll_interval,
            )
        while time.time() - start_time < otp_timeout:
            candidate_codes = [
                candidate
                for candidate in mail_provider.poll_verification_codes(
                    mailbox,
                    email=email,
                    seen_ids=seen_ids,
                    not_before_ts=otp_requested_at,
                )
                if candidate and candidate not in tried_codes
            ]
            if not candidate_codes:
                time.sleep(poll_interval)
                continue
            if active_trace is not None:
                active_trace.record("oauth_otp_candidates", candidate_count=len(candidate_codes), candidates=candidate_codes)

            for try_code in candidate_codes:
                tried_codes.add(try_code)
                resp_val, validate_error = validate_otp_with_fallback(
                    session=session,
                    oauth_issuer=oauth_issuer,
                    device_id=device_id,
                    code=try_code,
                    base_headers=h_val,
                    retry_attempts=safe_local_retry_attempts,
                    otp_validate_order=safe_otp_validate_order,
                    transient_markers=safe_transient_markers,
                    logger=logger,
                    flow_trace=active_trace,
                )
                if resp_val is not None and resp_val.status_code == 200:
                    code = try_code
                    try:
                        data = resp_val.json()
                        if isinstance(data, dict) and requires_phone_verification(data, resp_val.text, markers=safe_phone_markers):
                            if safe_otp_phone_action == "fail_fast":
                                return fail("oauth_phone_verification_required", "email_otp_validate")
                            if logger:
                                logger.warning("OAuth 验证码后命中手机验证信号，按策略继续")
                        continue_url = str(data.get("continue_url") or "")
                        page_type = str(((data.get("page") or {}).get("type")) or "")
                    except Exception:
                        pass
                    if active_trace is not None:
                        active_trace.record(
                            "oauth_otp_success",
                            code=try_code,
                            continue_url=continue_url,
                            page_type=page_type,
                        )
                    break
                if resp_val is None and logger:
                    logger.warning("OAuth OTP 校验失败: code=%s reason=%s", try_code, validate_error)
                if active_trace is not None:
                    active_trace.record("oauth_otp_failure", code=try_code, reason=validate_error)

            if code:
                break
            time.sleep(poll_interval)

        if not code:
            return fail("oauth_mail_otp_timeout", f"provider={mail_provider.provider_name}")

        if "about-you" in continue_url:
            h_about = dict(NAVIGATE_HEADERS)
            h_about["referer"] = f"{oauth_issuer}/email-verification"
            resp_about, about_error = request_with_local_retry(
                session,
                "get",
                f"{oauth_issuer}/about-you",
                retry_attempts=safe_local_retry_attempts,
                error_prefix="about_you_request",
                transient_markers=safe_transient_markers,
                logger=logger,
                flow_trace=active_trace,
                headers=h_about,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            if resp_about is None:
                return fail("about_you_request", about_error)

            if "consent" in str(resp_about.url) or "organization" in str(resp_about.url):
                continue_url = str(resp_about.url)
            else:
                first_name, last_name = generate_random_name()
                birthdate = generate_random_birthday()

                h_create = dict(COMMON_HEADERS)
                h_create["referer"] = f"{oauth_issuer}/about-you"
                h_create["oai-device-id"] = device_id
                h_create.update(generate_datadog_trace())

                resp_create, create_error = request_with_local_retry(
                    session,
                    "post",
                    f"{oauth_issuer}/api/accounts/create_account",
                    retry_attempts=safe_local_retry_attempts,
                    error_prefix="oauth_create_account",
                    transient_markers=safe_transient_markers,
                    logger=logger,
                    flow_trace=active_trace,
                    json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                    headers=h_create,
                    verify=False,
                    timeout=30,
                )
                if resp_create is None:
                    return fail("oauth_create_account", create_error)

                if resp_create.status_code == 200:
                    try:
                        data = resp_create.json()
                        continue_url = str(data.get("continue_url") or "")
                    except Exception:
                        pass
                elif resp_create.status_code == 400 and "already_exists" in resp_create.text:
                    continue_url = f"{oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                if active_trace is not None:
                    active_trace.record(
                        "oauth_create_account_parsed",
                        status_code=resp_create.status_code,
                        continue_url=continue_url,
                    )

        if "consent" in page_type:
            continue_url = f"{oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        if not continue_url or "email-verification" in continue_url:
            return fail("continue_url_invalid", continue_url)

    tokens = exchange_codex_tokens_from_session(
        session=session,
        device_id=device_id,
        code_verifier=code_verifier,
        consent_url=continue_url,
        oauth_issuer=oauth_issuer,
        oauth_client_id=oauth_client_id,
        oauth_redirect_uri=oauth_redirect_uri,
        proxy=proxy,
    )
    if active_trace is not None:
        active_trace.record(
            "oauth_flow_complete",
            success=bool(tokens),
            continue_url=continue_url,
            token_keys=sorted((tokens or {}).keys()),
        )
    return tokens


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def find_jwt_in_data(data: Any, depth: int = 0, max_depth: int = 5) -> str:
    if depth > max_depth:
        return ""
    if isinstance(data, str):
        candidate = str(data or "").strip()
        payload = decode_jwt_payload(candidate)
        if payload and any(key in payload for key in ("exp", "iat", "sub", "email")):
            return candidate
        return ""
    if isinstance(data, dict):
        for value in data.values():
            candidate = find_jwt_in_data(value, depth=depth + 1, max_depth=max_depth)
            if candidate:
                return candidate
        return ""
    if isinstance(data, (list, tuple, set)):
        for item in data:
            candidate = find_jwt_in_data(item, depth=depth + 1, max_depth=max_depth)
            if candidate:
                return candidate
        return ""
    return ""


def build_chatgpt_session_token_result(
    session: requests.Session,
    auth_code: Optional[str],
    callback_params: Optional[Dict[str, str]] = None,
    chatgpt_base: str = "https://chatgpt.com",
    logger: Optional[logging.Logger] = None,
    flow_trace: Optional[FlowTraceRecorder] = None,
) -> Optional[Dict[str, Any]]:
    base = str(chatgpt_base or "https://chatgpt.com").rstrip("/")
    active_trace = flow_trace or getattr(logger, "flow_trace", None)
    session_referer = f"{base}/"

    effective_callback_params = {
        str(key): str(value)
        for key, value in (callback_params or {}).items()
        if str(key).strip() and str(value).strip()
    }
    if auth_code and "code" not in effective_callback_params:
        effective_callback_params["code"] = str(auth_code)

    if effective_callback_params.get("code"):
        ordered_items: list[tuple[str, str]] = []
        for key in ("code", "scope", "state"):
            value = effective_callback_params.pop(key, "")
            if value:
                ordered_items.append((key, value))
        for key, value in effective_callback_params.items():
            ordered_items.append((key, value))
        callback_url = f"{base}/api/auth/callback/openai?{urlencode(ordered_items)}"
        if active_trace is not None:
            active_trace.record("chatgpt_callback_start", callback_url=callback_url)
        try:
            callback_resp = session.get(
                callback_url,
                headers=NAVIGATE_HEADERS,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
        except Exception as error:
            if logger:
                logger.warning("ChatGPT callback 请求失败: %s", error)
            return None
        if callback_resp.status_code >= 400:
            if logger:
                logger.warning("ChatGPT callback 返回异常状态: %s", callback_resp.status_code)
            return None
        session_referer = str(getattr(callback_resp, "url", "") or "").strip() or session_referer
        if active_trace is not None:
            active_trace.record(
                "chatgpt_callback_response",
                response=build_response_trace_payload(
                    callback_resp,
                    reveal_sensitive=active_trace.reveal_sensitive,
                    body_limit=active_trace.body_limit,
                ),
            )

    session_headers = {
        "accept": "application/json",
        "referer": session_referer,
        "user-agent": USER_AGENT,
    }
    try:
        session_resp = session.get(
            f"{base}/api/auth/session",
            headers=session_headers,
            verify=False,
            timeout=30,
        )
    except Exception as error:
        if logger:
            logger.warning("ChatGPT session 请求失败: %s", error)
        return None

    if session_resp.status_code != 200:
        if logger:
            logger.warning("ChatGPT session 返回异常状态: %s", session_resp.status_code)
        return None
    if active_trace is not None:
        active_trace.record(
            "chatgpt_session_response",
            response=build_response_trace_payload(
                session_resp,
                reveal_sensitive=active_trace.reveal_sensitive,
                body_limit=active_trace.body_limit,
            ),
        )

    try:
        session_data = session_resp.json()
    except Exception as error:
        if logger:
            logger.warning("ChatGPT session JSON 解析失败: %s", error)
        return None

    if not isinstance(session_data, dict):
        return None

    access_token = str(session_data.get("accessToken") or session_data.get("access_token") or "").strip()
    if not access_token:
        access_token = find_jwt_in_data(session_data)
    if not access_token:
        return None

    payload = decode_jwt_payload(access_token)
    auth_info = payload.get("https://api.openai.com/auth", {})
    account_id = extract_chatgpt_account_id(auth_info) if isinstance(auth_info, dict) else None
    user_info = session_data.get("user") or {}
    email = str(payload.get("email") or (user_info.get("email") if isinstance(user_info, dict) else "") or "").strip()
    exp = payload.get("exp")

    return {
        "access_token": access_token,
        "refresh_token": "",
        "id_token": "",
        "email": email,
        "account_id": str(account_id or ""),
        "exp": exp if isinstance(exp, (int, float)) else 0,
    }


class RegisterRuntime:
    def __init__(self, conf: Dict[str, Any], target_tokens: int, logger: logging.Logger):
        self.conf = conf
        self.target_tokens = target_tokens
        self.logger = logger

        self.file_lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.health_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        self.token_success_count = 0
        self.stop_event = threading.Event()
        self.provider_consecutive_failures = 0
        self.provider_cooldown_until = 0.0
        self.failure_stage_counts: Counter[str] = Counter()
        self.failure_detail_counts: Counter[str] = Counter()
        self.success_counts: Counter[str] = Counter()
        self.last_oauth_failure_detail = ""

        run_workers = int(pick_conf(conf, "run", "workers", default=1) or 1)
        self.concurrent_workers = max(1, run_workers)
        self.proxy = str(pick_conf(conf, "run", "proxy", default="") or "")
        self.mail_provider = build_mail_provider(conf, proxy=self.proxy, logger=logger)
        self.mail_provider_name = self.mail_provider.provider_name
        self.mail_otp_timeout_seconds = int(pick_conf(conf, "mail", "otp_timeout_seconds", default=120) or 120)
        self.mail_poll_interval_seconds = float(pick_conf(conf, "mail", "poll_interval_seconds", default=3.0) or 3.0)

        self.oauth_issuer = str(pick_conf(conf, "oauth", "issuer", default="https://auth.openai.com") or "https://auth.openai.com")
        self.oauth_client_id = str(
            pick_conf(conf, "oauth", "client_id", default="app_EMoamEEZ73f0CkXaXp7hrann") or "app_EMoamEEZ73f0CkXaXp7hrann"
        )
        self.oauth_redirect_uri = str(
            pick_conf(conf, "oauth", "redirect_uri", default="http://localhost:1455/auth/callback")
            or "http://localhost:1455/auth/callback"
        )
        self.oauth_retry_attempts = int(pick_conf(conf, "oauth", "retry_attempts", default=3) or 3)
        self.oauth_retry_backoff_base = float(pick_conf(conf, "oauth", "retry_backoff_base", default=2.0) or 2.0)
        self.oauth_retry_backoff_max = float(pick_conf(conf, "oauth", "retry_backoff_max", default=15.0) or 15.0)
        self.oauth_outer_retry_attempts = flow_outer_retry_attempts(conf, fallback=self.oauth_retry_attempts)
        self.oauth_local_retry_attempts = oauth_local_retry_attempts(conf, fallback=3)
        self.flow_transient_markers = parse_marker_config(
            pick_conf(conf, "flow", "transient_markers", default=TRANSIENT_FLOW_MARKERS_DEFAULT),
            fallback=TRANSIENT_FLOW_MARKERS_DEFAULT,
        )
        self.oauth_otp_validate_order = parse_otp_validate_order(
            pick_conf(conf, "flow", "oauth_otp_validate_order", default="normal,sentinel")
        )
        self.oauth_phone_markers = parse_marker_config(
            pick_conf(conf, "registration", "phone_verification_markers", default=PHONE_VERIFICATION_MARKERS_DEFAULT),
            fallback=PHONE_VERIFICATION_MARKERS_DEFAULT,
        )
        self.oauth_password_phone_action = parse_choice(
            pick_conf(conf, "flow", "oauth_password_phone_action", default="warn_and_continue"),
            allowed=("warn_and_continue", "fail_fast"),
            fallback="warn_and_continue",
        )
        self.oauth_otp_phone_action = parse_choice(
            pick_conf(conf, "flow", "oauth_otp_phone_action", default="warn_and_continue"),
            allowed=("warn_and_continue", "fail_fast"),
            fallback="warn_and_continue",
        )
        self.oauth_otp_timeout_seconds = int(
            pick_conf(conf, "oauth", "otp_timeout_seconds", default=self.mail_otp_timeout_seconds) or self.mail_otp_timeout_seconds
        )
        self.oauth_otp_poll_interval_seconds = float(
            pick_conf(conf, "oauth", "otp_poll_interval_seconds", default=max(1.0, min(self.mail_poll_interval_seconds, 3.0)))
            or max(1.0, min(self.mail_poll_interval_seconds, 3.0))
        )
        self.failure_threshold_for_cooldown = int(
            pick_conf(conf, "run", "failure_threshold_for_cooldown", default=5) or 5
        )
        self.failure_cooldown_seconds = float(
            pick_conf(conf, "run", "failure_cooldown_seconds", default=45.0) or 45.0
        )
        self.loop_jitter_min_seconds = float(pick_conf(conf, "run", "loop_jitter_min_seconds", default=2.0) or 2.0)
        self.loop_jitter_max_seconds = float(pick_conf(conf, "run", "loop_jitter_max_seconds", default=6.0) or 6.0)

        upload_base = str(pick_conf(conf, "upload", "cli_proxy_api_base", "base_url", default="") or "").strip()
        if not upload_base:
            upload_base = str(pick_conf(conf, "clean", "base_url", default="") or "").strip()
        self.cli_proxy_api_base = upload_base.rstrip("/")

        upload_token = str(pick_conf(conf, "upload", "token", "cpa_password", default="") or "").strip()
        if not upload_token:
            upload_token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
        self.upload_api_token = upload_token

        self.upload_url = f"{self.cli_proxy_api_base}/v0/management/auth-files" if self.cli_proxy_api_base else ""

        output_cfg = conf.get("output")
        if not isinstance(output_cfg, dict):
            output_cfg = {}

        save_local_raw = output_cfg.get("save_local", True)
        if isinstance(save_local_raw, bool):
            self.save_local = save_local_raw
        else:
            self.save_local = str(save_local_raw).strip().lower() in ("1", "true", "yes", "on")

        self.run_dir = os.getcwd()
        if self.save_local:
            self.fixed_out_dir = os.path.join(self.run_dir, "output_fixed")
            self.tokens_parent_dir = os.path.join(self.run_dir, "output_tokens")
            os.makedirs(self.fixed_out_dir, exist_ok=True)
            os.makedirs(self.tokens_parent_dir, exist_ok=True)
            self.tokens_out_dir = self._ensure_unique_dir(self.tokens_parent_dir, f"{target_tokens}个账号")

            self.accounts_file = self._resolve_output_path(str(output_cfg.get("accounts_file", "accounts.txt")))
            self.csv_file = self._resolve_output_path(str(output_cfg.get("csv_file", "registered_accounts.csv")))
            self.ak_file = self._resolve_output_path(str(output_cfg.get("ak_file", "ak.txt")))
            self.rk_file = self._resolve_output_path(str(output_cfg.get("rk_file", "rk.txt")))
        else:
            self.fixed_out_dir = ""
            self.tokens_parent_dir = ""
            self.tokens_out_dir = ""
            self.accounts_file = ""
            self.csv_file = ""
            self.ak_file = ""
            self.rk_file = ""

    def _resolve_output_path(self, value: str) -> str:
        if os.path.isabs(value):
            return value
        return os.path.join(self.fixed_out_dir, value)

    def _ensure_unique_dir(self, parent_dir: str, base_name: str) -> str:
        os.makedirs(parent_dir, exist_ok=True)

        candidates = [os.path.join(parent_dir, base_name)] + [
            os.path.join(parent_dir, f"{base_name}-{idx}") for idx in range(1, 1000000)
        ]
        for candidate in candidates:
            try:
                os.makedirs(candidate)
                return candidate
            except FileExistsError:
                continue
        raise RuntimeError(f"无法创建唯一目录: {parent_dir}/{base_name}")

    def get_token_success_count(self) -> int:
        with self.counter_lock:
            return self.token_success_count

    def wait_for_provider_availability(self, worker_id: int = 0) -> None:
        if self.stop_event.is_set() and self.get_token_success_count() >= self.target_tokens:
            return
        self.mail_provider.wait_for_availability(worker_id=worker_id)

    def note_attempt_success(self, success_key: str = "register_oauth_success") -> None:
        with self.stats_lock:
            self.success_counts[str(success_key or "register_oauth_success")] += 1

    def note_attempt_failure(self, stage: str, email: str = "", detail: str = "") -> None:
        normalized_stage = str(stage or "unknown").strip() or "unknown"
        normalized_detail = str(detail or "").strip()
        with self.stats_lock:
            self.failure_stage_counts[normalized_stage] += 1
            if normalized_detail:
                self.failure_detail_counts[f"{normalized_stage}:{normalized_detail}"] += 1
        self.logger.warning(
            "失败归类: stage=%s detail=%s email=%s",
            normalized_stage,
            normalized_detail or "-",
            email or "-",
        )

    def snapshot_failure_stats(self) -> tuple[List[tuple[str, int]], List[tuple[str, int]], List[tuple[str, int]]]:
        with self.stats_lock:
            return (
                sorted(self.failure_stage_counts.items(), key=lambda item: (-item[1], item[0])),
                sorted(self.failure_detail_counts.items(), key=lambda item: (-item[1], item[0])),
                sorted(self.success_counts.items(), key=lambda item: (-item[1], item[0])),
            )

    def claim_token_slot(self) -> tuple[bool, int]:
        with self.counter_lock:
            if self.token_success_count >= self.target_tokens:
                return False, self.token_success_count
            self.token_success_count += 1
            if self.token_success_count >= self.target_tokens:
                self.stop_event.set()
            return True, self.token_success_count

    def release_token_slot(self) -> None:
        with self.counter_lock:
            if self.token_success_count > 0:
                self.token_success_count -= 1
            if self.token_success_count < self.target_tokens:
                self.stop_event.clear()

    def save_token_json(self, email: str, access_token: str, refresh_token: str = "", id_token: str = "") -> bool:
        try:
            payload = decode_jwt_payload(access_token)
            auth_info = payload.get("https://api.openai.com/auth", {})
            account_id = auth_info.get("chatgpt_account_id", "") if isinstance(auth_info, dict) else ""

            exp_timestamp = payload.get("exp", 0)
            expired_str = ""
            if exp_timestamp:
                exp_dt = dt.datetime.fromtimestamp(exp_timestamp, tz=dt.timezone(dt.timedelta(hours=8)))
                expired_str = exp_dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")

            now = dt.datetime.now(tz=dt.timezone(dt.timedelta(hours=8)))
            token_data = {
                "type": "codex",
                "email": email,
                "expired": expired_str,
                "id_token": id_token or "",
                "account_id": account_id,
                "access_token": access_token,
                "last_refresh": now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
                "refresh_token": refresh_token or "",
            }

            if self.save_local:
                filename = os.path.join(self.tokens_out_dir, f"{email}.json")
                ensure_parent_dir(filename)
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(token_data, f, ensure_ascii=False)

                if self.upload_url and self.upload_api_token:
                    uploaded = self.upload_token_json(filename)
                    if not uploaded:
                        self.logger.warning("Token 已保存到本地，但上传 CPA 失败: %s", email)
                        return False
            else:
                if self.upload_url and self.upload_api_token:
                    uploaded = self.upload_token_data(f"{email}.json", token_data)
                    if not uploaded:
                        self.logger.warning("Token 直传 CPA 失败: %s", email)
                        return False

            return True
        except Exception as e:
            self.logger.warning("保存 Token JSON 失败: %s", e)
            return False

    def upload_token_json(self, filename: str) -> bool:
        if not self.upload_url or not self.upload_api_token:
            return True
        try:
            s = create_session(proxy=self.proxy)
            with open(filename, "rb") as f:
                files = {"file": (os.path.basename(filename), f, "application/json")}
                headers = {"Authorization": f"Bearer {self.upload_api_token}"}
                resp = s.post(self.upload_url, files=files, headers=headers, verify=False, timeout=30)
                if not (200 <= resp.status_code < 300):
                    self.logger.warning("上传 token 失败: %s %s", resp.status_code, resp.text[:200])
                    return False
                return True
        except Exception as e:
            self.logger.warning("上传 token 异常: %s", e)
            return False

    def upload_token_data(self, filename: str, token_data: Dict[str, Any]) -> bool:
        if not self.upload_url or not self.upload_api_token:
            return True
        try:
            s = create_session(proxy=self.proxy)
            content = json.dumps(token_data, ensure_ascii=False).encode("utf-8")
            files = {"file": (filename, content, "application/json")}
            headers = {"Authorization": f"Bearer {self.upload_api_token}"}
            resp = s.post(self.upload_url, files=files, headers=headers, verify=False, timeout=30)
            if not (200 <= resp.status_code < 300):
                self.logger.warning("上传 token 失败: %s %s", resp.status_code, resp.text[:200])
                return False
            return True
        except Exception as e:
            self.logger.warning("上传 token 异常: %s", e)
            return False

    def save_tokens(self, email: str, tokens: Dict[str, Any]) -> bool:
        access_token = str(tokens.get("access_token") or "")
        refresh_token = str(tokens.get("refresh_token") or "")
        id_token = str(tokens.get("id_token") or "")

        if self.save_local:
            try:
                with self.file_lock:
                    if access_token:
                        ensure_parent_dir(self.ak_file)
                        with open(self.ak_file, "a", encoding="utf-8") as f:
                            f.write(f"{access_token}\n")
                    if refresh_token:
                        ensure_parent_dir(self.rk_file)
                        with open(self.rk_file, "a", encoding="utf-8") as f:
                            f.write(f"{refresh_token}\n")
            except Exception as e:
                self.logger.warning("AK/RK 保存失败: %s", e)
                return False

        if access_token:
            return self.save_token_json(email, access_token, refresh_token, id_token)
        return False

    def save_account(self, email: str, password: str) -> None:
        if not self.save_local:
            return

        with self.file_lock:
            ensure_parent_dir(self.accounts_file)
            ensure_parent_dir(self.csv_file)

            with open(self.accounts_file, "a", encoding="utf-8") as f:
                f.write(f"{email}:{password}\n")

            file_exists = os.path.exists(self.csv_file)
            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["email", "password", "timestamp"])
                writer.writerow([email, password, time.strftime("%Y-%m-%d %H:%M:%S")])

    def collect_token_emails(self) -> set[str]:
        emails = set()
        if not os.path.isdir(self.tokens_out_dir):
            return emails
        for name in os.listdir(self.tokens_out_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.tokens_out_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                email = data.get("email") or name[:-5]
                if email:
                    emails.add(str(email))
            except Exception:
                continue
        return emails

    def reconcile_account_outputs_from_tokens(self) -> int:
        if not self.save_local:
            return 0

        token_emails = self.collect_token_emails()

        pwd_map: Dict[str, str] = {}
        if os.path.exists(self.accounts_file):
            try:
                with open(self.accounts_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or ":" not in line:
                            continue
                        email, pwd = line.split(":", 1)
                        pwd_map[email] = pwd
            except Exception:
                pass

        ordered_emails = sorted(token_emails)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        with self.file_lock:
            ensure_parent_dir(self.accounts_file)
            ensure_parent_dir(self.csv_file)

            with open(self.accounts_file, "w", encoding="utf-8") as f:
                for email in ordered_emails:
                    f.write(f"{email}:{pwd_map.get(email, '')}\n")

            with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["email", "password", "timestamp"])
                for email in ordered_emails:
                    writer.writerow([email, pwd_map.get(email, ""), timestamp])

        return len(ordered_emails)

    def oauth_login_with_retry(self, mailbox: Mailbox, password: str) -> Optional[Dict[str, Any]]:
        attempts = max(1, self.oauth_outer_retry_attempts)
        self.last_oauth_failure_detail = ""
        flow_trace: Optional[FlowTraceRecorder] = getattr(self.logger, "flow_trace", None)
        for attempt in range(1, attempts + 1):
            if self.stop_event.is_set() and self.get_token_success_count() >= self.target_tokens:
                return None

            self.logger.info("OAuth 尝试 %s/%s: %s", attempt, attempts, mailbox.email)
            if flow_trace is not None:
                flow_trace.record("oauth_outer_attempt_start", email=mailbox.email, attempt=attempt, total_attempts=attempts)
            tokens = perform_codex_oauth_login_http(
                email=mailbox.email,
                password=password,
                oauth_issuer=self.oauth_issuer,
                oauth_client_id=self.oauth_client_id,
                oauth_redirect_uri=self.oauth_redirect_uri,
                proxy=self.proxy,
                mail_provider=self.mail_provider,
                mailbox=mailbox,
                otp_timeout_seconds=self.oauth_otp_timeout_seconds,
                otp_poll_interval_seconds=self.oauth_otp_poll_interval_seconds,
                local_retry_attempts=self.oauth_local_retry_attempts,
                transient_markers=self.flow_transient_markers,
                otp_validate_order=self.oauth_otp_validate_order,
                phone_markers=self.oauth_phone_markers,
                password_phone_action=self.oauth_password_phone_action,
                otp_phone_action=self.oauth_otp_phone_action,
                logger=self.logger,
                flow_trace=flow_trace,
            )
            if tokens:
                self.last_oauth_failure_detail = ""
                if flow_trace is not None:
                    flow_trace.record("oauth_outer_attempt_success", email=mailbox.email, attempt=attempt)
                return tokens
            self.last_oauth_failure_detail = f"oauth_attempt_{attempt}_failed"
            if flow_trace is not None:
                flow_trace.record(
                    "oauth_outer_attempt_failed",
                    email=mailbox.email,
                    attempt=attempt,
                    detail=self.last_oauth_failure_detail,
                )
            if attempt < attempts:
                backoff = min(self.oauth_retry_backoff_max, self.oauth_retry_backoff_base ** (attempt - 1))
                jitter = random.uniform(0.2, 0.8)
                self.logger.warning(
                    "OAuth 失败，准备重试: email=%s attempt=%s/%s sleep=%.1fs",
                    mailbox.email,
                    attempt,
                    attempts,
                    backoff + jitter,
                )
                if flow_trace is not None:
                    flow_trace.record(
                        "oauth_outer_attempt_retry_scheduled",
                        email=mailbox.email,
                        attempt=attempt,
                        sleep_seconds=round(backoff + jitter, 2),
                    )
                time.sleep(backoff + jitter)
        self.last_oauth_failure_detail = self.last_oauth_failure_detail or f"oauth_attempts_exhausted:{attempts}"
        return None


def register_one(runtime: RegisterRuntime, worker_id: int = 0) -> tuple[Optional[str], Optional[bool], float, float]:
    if runtime.stop_event.is_set() and runtime.get_token_success_count() >= runtime.target_tokens:
        return None, None, 0.0, 0.0

    runtime.wait_for_provider_availability(worker_id=worker_id)
    t_start = time.time()
    mailbox = runtime.mail_provider.create_mailbox()
    if not mailbox:
        note_target_failure = getattr(runtime.mail_provider, "note_target_failure", None)
        if callable(note_target_failure):
            note_target_failure(
                getattr(runtime.mail_provider, "last_selected_target", ""),
                stage="create_mailbox",
                detail=f"provider={runtime.mail_provider_name}",
            )
        else:
            note_domain_failure = getattr(runtime.mail_provider, "note_domain_failure", None)
            if callable(note_domain_failure):
                note_domain_failure(
                    getattr(runtime.mail_provider, "last_selected_domain", ""),
                    stage="create_mailbox",
                    detail=f"provider={runtime.mail_provider_name}",
                )
        runtime.note_attempt_failure(stage="create_mailbox", detail=f"provider={runtime.mail_provider_name}")
        return None, False, 0.0, time.time() - t_start
    email = mailbox.email

    password = generate_random_password()
    registrar = ProtocolRegistrar(proxy=runtime.proxy, logger=runtime.logger, conf=runtime.conf)
    reg_ok = registrar.register(
        email=email,
        password=password,
        client_id=runtime.oauth_client_id,
        redirect_uri=runtime.oauth_redirect_uri,
        mailbox=mailbox,
        mail_provider=runtime.mail_provider,
        otp_timeout_seconds=runtime.mail_otp_timeout_seconds,
        otp_poll_interval_seconds=runtime.mail_poll_interval_seconds,
    )
    t_reg = time.time() - t_start
    if not reg_ok:
        runtime.logger.warning("注册流程失败: %s", email)
        register_detail = registrar.last_failure_detail or registrar.last_failure_stage or "unknown"
        if registrar.last_failure_stage == "register_mail_otp_timeout":
            failure_target = mailbox.failure_target or mailbox.account_name or mailbox.domain
            note_target_failure = getattr(runtime.mail_provider, "note_target_failure", None)
            if callable(note_target_failure):
                note_target_failure(
                    failure_target,
                    stage="register",
                    detail=register_detail,
                )
            else:
                note_domain_failure = getattr(runtime.mail_provider, "note_domain_failure", None)
                if callable(note_domain_failure):
                    note_domain_failure(
                        mailbox.domain,
                        stage="register",
                        detail=register_detail,
                    )
        runtime.note_attempt_failure(stage="register", email=email, detail=register_detail)
        return email, False, t_reg, time.time() - t_start

    tokens = getattr(registrar, "registration_tokens", None)
    flow_trace = getattr(runtime.logger, "flow_trace", None)
    if flow_trace is not None:
        flow_trace.record(
            "register_one_token_source",
            email=email,
            source="registration" if tokens else "oauth_retry",
        )
    if not tokens:
        tokens = runtime.oauth_login_with_retry(mailbox=mailbox, password=password)
    t_total = time.time() - t_start
    if not tokens:
        oauth_detail = runtime.last_oauth_failure_detail or f"attempts={runtime.oauth_outer_retry_attempts}"
        runtime.note_attempt_failure(stage="oauth", email=email, detail=oauth_detail)
        return email, False, t_reg, t_total

    claimed, current = runtime.claim_token_slot()
    if not claimed:
        return email, None, t_reg, t_total

    saved = runtime.save_tokens(email, tokens)
    if not saved:
        runtime.release_token_slot()
        runtime.note_attempt_failure(stage="save_tokens", email=email, detail="save_token_json_or_upload_failed")
        return email, False, t_reg, t_total

    runtime.save_account(email, password)
    success_target = mailbox.failure_target or mailbox.account_name or mailbox.domain
    note_target_success = getattr(runtime.mail_provider, "note_target_success", None)
    if callable(note_target_success):
        note_target_success(success_target)
    else:
        note_domain_success = getattr(runtime.mail_provider, "note_domain_success", None)
        if callable(note_domain_success):
            note_domain_success(mailbox.domain)
    runtime.note_attempt_success()
    runtime.logger.info(
        "注册+OAuth 成功: %s | 注册 %.1fs + OAuth %.1fs = %.1fs | token %s/%s",
        email,
        t_reg,
        t_total - t_reg,
        t_total,
        current,
        runtime.target_tokens,
    )
    return email, True, t_reg, t_total


def run_batch_register(conf: Dict[str, Any], target_tokens: int, logger: logging.Logger) -> tuple[int, int, int]:
    if target_tokens <= 0:
        return 0, 0, 0

    try:
        runtime = RegisterRuntime(conf=conf, target_tokens=target_tokens, logger=logger)
    except Exception as e:
        logger.error("邮件提供方初始化失败: %s", e)
        return 0, 0, 0

    workers = runtime.concurrent_workers

    logger.info(
        "开始补号: 目标 token=%s, 并发=%s, 邮箱提供方=%s",
        target_tokens,
        workers,
        runtime.mail_provider_name,
    )
    logger.info("Mail Provider Config: %s", runtime.mail_provider.describe())

    ok = 0
    fail = 0
    skip = 0
    attempts = 0
    reg_times: List[float] = []
    total_times: List[float] = []
    lock = threading.Lock()
    batch_start = time.time()

    if workers == 1:
        while runtime.get_token_success_count() < target_tokens:
            attempts += 1
            email, success, t_reg, t_total = register_one(runtime, worker_id=1)
            if success is True:
                ok += 1
                reg_times.append(t_reg)
                total_times.append(t_total)
            elif success is False:
                fail += 1
            else:
                skip += 1
            logger.info(
                "补号进度: token %s/%s | ✅%s ❌%s ⏭️%s | 用时 %.1fs",
                runtime.get_token_success_count(),
                target_tokens,
                ok,
                fail,
                skip,
                time.time() - batch_start,
            )
            if runtime.get_token_success_count() >= target_tokens:
                break
            jitter_min = min(runtime.loop_jitter_min_seconds, runtime.loop_jitter_max_seconds)
            jitter_max = max(runtime.loop_jitter_min_seconds, runtime.loop_jitter_max_seconds)
            time.sleep(random.uniform(jitter_min, jitter_max))
    else:
        def worker_task(task_index: int, worker_id: int):
            if task_index > 1:
                jitter = random.uniform(0.2, 1.0)
                time.sleep(jitter)
            if runtime.stop_event.is_set() and runtime.get_token_success_count() >= target_tokens:
                return task_index, None, None, 0.0, 0.0
            email, success, t_reg, t_total = register_one(runtime, worker_id=worker_id)
            return task_index, email, success, t_reg, t_total

        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {}
        next_task_index = 1

        def submit_one() -> bool:
            nonlocal next_task_index
            remaining = target_tokens - runtime.get_token_success_count()
            if remaining <= 0:
                return False
            if len(futures) >= remaining:
                return False

            wid = ((next_task_index - 1) % workers) + 1
            fut = executor.submit(worker_task, next_task_index, wid)
            futures[fut] = next_task_index
            next_task_index += 1
            return True

        try:
            for _ in range(min(workers, target_tokens)):
                if not submit_one():
                    break

            while futures:
                if runtime.get_token_success_count() >= target_tokens:
                    runtime.stop_event.set()

                done_set, _ = wait(list(futures.keys()), return_when=FIRST_COMPLETED, timeout=1.0)
                if not done_set:
                    continue

                for fut in done_set:
                    _ = futures.pop(fut, None)
                    attempts += 1
                    try:
                        _, _, success, t_reg, t_total = fut.result()
                    except Exception as exc:
                        success, t_reg, t_total = False, 0.0, 0.0
                        runtime.note_attempt_failure(stage="worker_exception", detail=type(exc).__name__)

                    with lock:
                        if success is True:
                            ok += 1
                            reg_times.append(t_reg)
                            total_times.append(t_total)
                        elif success is False:
                            fail += 1
                        else:
                            skip += 1

                        logger.info(
                            "补号进度: token %s/%s | ✅%s ❌%s ⏭️%s | 用时 %.1fs",
                            runtime.get_token_success_count(),
                            target_tokens,
                            ok,
                            fail,
                            skip,
                            time.time() - batch_start,
                        )

                    if runtime.get_token_success_count() < target_tokens and not runtime.stop_event.is_set():
                        submit_one()
        finally:
            runtime.stop_event.set()
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except TypeError:
                executor.shutdown(wait=True)

    synced = runtime.reconcile_account_outputs_from_tokens()
    elapsed = time.time() - batch_start
    avg_reg = (sum(reg_times) / len(reg_times)) if reg_times else 0
    avg_total = (sum(total_times) / len(total_times)) if total_times else 0
    logger.info(
        "补号完成: token=%s/%s, fail=%s, skip=%s, attempts=%s, elapsed=%.1fs, avg(注册)=%.1fs, avg(总)=%.1fs, 收敛账号=%s",
        runtime.get_token_success_count(),
        target_tokens,
        fail,
        skip,
        attempts,
        elapsed,
        avg_reg,
        avg_total,
        synced,
    )
    failure_stage_stats, failure_detail_stats, success_stats = runtime.snapshot_failure_stats()
    if success_stats:
        logger.info("成功分类汇总: %s", ", ".join(f"{name}={count}" for name, count in success_stats))
    if failure_stage_stats:
        logger.info("失败阶段汇总: %s", ", ".join(f"{name}={count}" for name, count in failure_stage_stats))
    if failure_detail_stats:
        top_failure_details = failure_detail_stats[:8]
        logger.info(
            "失败细节汇总(Top %s): %s",
            len(top_failure_details),
            ", ".join(f"{name}={count}" for name, count in top_failure_details),
        )
    return runtime.get_token_success_count(), fail, synced


def fetch_auth_files(base_url: str, token: str, timeout: int) -> List[Dict[str, Any]]:
    resp = requests.get(f"{base_url}/v0/management/auth-files", headers=mgmt_headers(token), timeout=timeout)
    resp.raise_for_status()
    raw = resp.json()
    data = raw if isinstance(raw, dict) else {}
    files = data.get("files", [])
    return files if isinstance(files, list) else []


def build_probe_payload(auth_index: str, user_agent: str, chatgpt_account_id: Optional[str] = None) -> Dict[str, Any]:
    call_header = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent or DEFAULT_MGMT_UA,
    }
    if chatgpt_account_id:
        call_header["Chatgpt-Account-Id"] = chatgpt_account_id
    return {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_header,
    }


async def probe_account_async(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    token: str,
    item: Dict[str, Any],
    user_agent: str,
    timeout: int,
    retries: int,
    used_percent_threshold: int = 80,
) -> Dict[str, Any]:
    auth_index = item.get("auth_index")
    name = item.get("name") or item.get("id")
    account = item.get("account") or item.get("email") or ""
    disabled = is_item_disabled(item)
    result = {
        "name": name,
        "account": account,
        "auth_index": auth_index,
        "type": get_item_type(item),
        "provider": item.get("provider"),
        "disabled": disabled,
        "status_code": None,
        "invalid_401": False,
        "invalid_used_percent": False,
        "used_percent": None,
        "is_quota": False,
        "is_healthy": False,
        "action": "keep",
        "error": None,
    }
    if not auth_index:
        result["error"] = "missing auth_index"
        return result

    chatgpt_account_id = extract_chatgpt_account_id(item)
    payload = build_probe_payload(str(auth_index), user_agent, chatgpt_account_id)

    for attempt in range(retries + 1):
        try:
            async with semaphore:
                async with session.post(
                    f"{base_url}/v0/management/api-call",
                    headers={**mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"management api-call http {resp.status}: {text[:200]}")
                    data = safe_json_text(text)
                    sc = normalize_status_code(data.get("status_code"))
                    result["status_code"] = sc
                    result["invalid_401"] = sc == 401
                    body_obj, body_text = parse_usage_body(data.get("body"))
                    usage = analyze_usage_status(
                        status_code=sc,
                        body_obj=body_obj,
                        body_text=body_text,
                        used_percent_threshold=used_percent_threshold,
                    )
                    result["used_percent"] = usage["used_percent"]
                    result["invalid_used_percent"] = usage["over_threshold"]
                    result["is_quota"] = usage["is_quota"]
                    result["is_healthy"] = usage["is_healthy"]
                    result["action"] = decide_clean_action(
                        status_code=sc,
                        disabled=disabled,
                        is_quota=bool(usage["is_quota"]),
                        over_threshold=bool(usage["over_threshold"]),
                    )

                    if sc is None:
                        result["error"] = "missing status_code in api-call response"
                    return result
        except Exception as e:
            result["error"] = str(e)
            if attempt >= retries:
                return result
    return result


async def delete_account_async(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    token: str,
    name: str,
    timeout: int,
) -> Dict[str, Any]:
    if not name:
        return {"name": None, "deleted": False, "error": "missing name"}
    encoded_name = quote(name, safe="")
    url = f"{base_url}/v0/management/auth-files?name={encoded_name}"
    try:
        async with semaphore:
            async with session.delete(url, headers=mgmt_headers(token), timeout=timeout) as resp:
                text = await resp.text()
                data = safe_json_text(text)
                ok = resp.status == 200 and data.get("status") == "ok"
                return {
                    "name": name,
                    "deleted": ok,
                    "status_code": resp.status,
                    "error": None if ok else f"delete failed, response={text[:200]}",
                }
    except Exception as e:
        return {"name": name, "deleted": False, "error": str(e)}


async def update_account_disabled_async(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    token: str,
    name: str,
    disabled: bool,
    timeout: int,
) -> Dict[str, Any]:
    if not name:
        return {"name": None, "updated": False, "error": "missing name"}

    payload = {"name": name, "disabled": bool(disabled)}
    headers = {**mgmt_headers(token), "Content-Type": "application/json"}
    fallback_status_codes = {404, 405, 501}
    urls = [
        f"{base_url}/v0/management/auth-files",
        f"{base_url}/v0/management/auth-files/status",
    ]

    last_error = "unknown"
    for idx, url in enumerate(urls):
        try:
            async with semaphore:
                async with session.patch(url, headers=headers, json=payload, timeout=timeout) as resp:
                    text = await resp.text()
            data = safe_json_text(text)
            if resp.status in fallback_status_codes and idx == 0:
                last_error = f"primary_patch_http_{resp.status}"
                continue
            if resp.status >= 400:
                return {
                    "name": name,
                    "updated": False,
                    "status_code": resp.status,
                    "error": f"patch failed, response={text[:200]}",
                }
            if isinstance(data, dict):
                status = str(data.get("status") or "").strip().lower()
                if status and status != "ok":
                    return {
                        "name": name,
                        "updated": False,
                        "status_code": resp.status,
                        "error": f"patch status={status}",
                    }
            return {
                "name": name,
                "updated": True,
                "status_code": resp.status,
                "error": None,
            }
        except Exception as e:
            last_error = str(e)

    return {"name": name, "updated": False, "error": last_error}


def select_probe_candidates(
    candidates: List[Dict[str, Any]],
    sample_size: int,
    rng: Any = None,
) -> List[Dict[str, Any]]:
    candidate_list = list(candidates)
    normalized_size = max(0, int(sample_size or 0))
    if normalized_size <= 0 or normalized_size >= len(candidate_list):
        return candidate_list
    sampler = rng if rng is not None else random
    return list(sampler.sample(candidate_list, normalized_size))


async def run_probe_async(
    base_url: str,
    token: str,
    target_type: str,
    workers: int,
    timeout: int,
    retries: int,
    user_agent: str,
    used_percent_threshold: int = 80,
    sample_size: int = 0,
    logger: Optional[logging.Logger] = None,
) -> tuple[List[Dict[str, Any]], int, int, int, List[Dict[str, Any]]]:
    files = fetch_auth_files(base_url, token, timeout)
    candidates: List[Dict[str, Any]] = []
    for f in files:
        if str(get_item_type(f)).lower() != target_type.lower():
            continue
        candidates.append(f)

    if not candidates:
        if logger:
            logger.info("未找到 type=%s 的候选账号，跳过探测与策略判定", target_type)
        return [], len(files), 0, 0, files

    selected_candidates = select_probe_candidates(candidates, sample_size)
    normalized_sample_size = max(0, int(sample_size or 0))
    if logger and normalized_sample_size > 0:
        if len(selected_candidates) < len(candidates):
            logger.info(
                "本轮随机抽样探测: 已抽样=%s/%s, target_type=%s",
                len(selected_candidates),
                len(candidates),
                target_type,
            )
        else:
            logger.info(
                "本轮探测按全量处理: 抽样数量=%s, 候选总数=%s, target_type=%s",
                normalized_sample_size,
                len(candidates),
                target_type,
            )

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, workers))

    probe_results = []
    total_candidates = len(selected_candidates)
    checked = 0
    delete_count = 0
    disable_count = 0
    enable_count = 0

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [
            asyncio.create_task(
                probe_account_async(
                    session=session,
                    semaphore=semaphore,
                    base_url=base_url,
                    token=token,
                    item=item,
                    user_agent=user_agent,
                    timeout=timeout,
                    retries=retries,
                    used_percent_threshold=used_percent_threshold,
                )
            )
            for item in selected_candidates
        ]
        for task in asyncio.as_completed(tasks):
            result = await task
            probe_results.append(result)
            checked += 1
            action = str(result.get("action") or "keep")
            if action == "delete":
                delete_count += 1
            elif action == "disable":
                disable_count += 1
            elif action == "enable":
                enable_count += 1

            if logger and (checked % 50 == 0 or checked == total_candidates):
                logger.info(
                    "账号探测进度: 已检查=%s/%s, 待删=%s, 待禁用=%s, 待启用=%s",
                    checked,
                    total_candidates,
                    delete_count,
                    disable_count,
                    enable_count,
                )

    return probe_results, len(files), len(candidates), len(selected_candidates), files


async def run_delete_async(
    base_url: str,
    token: str,
    names_to_delete: List[str],
    delete_workers: int,
    timeout: int,
) -> tuple[int, int]:
    if not names_to_delete:
        return 0, 0

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, delete_workers))

    delete_results = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [
            asyncio.create_task(
                delete_account_async(
                    session=session,
                    semaphore=semaphore,
                    base_url=base_url,
                    token=token,
                    name=name,
                    timeout=timeout,
                )
            )
            for name in names_to_delete
        ]
        for task in asyncio.as_completed(tasks):
            delete_results.append(await task)

    success = [r for r in delete_results if r.get("deleted")]
    failed = [r for r in delete_results if not r.get("deleted")]
    return len(success), len(failed)


async def run_update_disabled_async(
    base_url: str,
    token: str,
    names: List[str],
    *,
    disabled: bool,
    workers: int,
    timeout: int,
) -> tuple[int, int]:
    if not names:
        return 0, 0

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, workers))

    results: List[Dict[str, Any]] = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [
            asyncio.create_task(
                update_account_disabled_async(
                    session=session,
                    semaphore=semaphore,
                    base_url=base_url,
                    token=token,
                    name=name,
                    disabled=disabled,
                    timeout=timeout,
                )
            )
            for name in names
        ]
        for task in asyncio.as_completed(tasks):
            results.append(await task)

    success = [r for r in results if r.get("updated")]
    failed = [r for r in results if not r.get("updated")]
    return len(success), len(failed)


async def run_clean_401_async(
    *,
    base_url: str,
    token: str,
    target_type: str,
    workers: int,
    delete_workers: int,
    timeout: int,
    retries: int,
    user_agent: str,
    used_percent_threshold: int,
    sample_size: int,
    logger: logging.Logger,
) -> Dict[str, Any]:
    probe_results, total_files, target_files, probed_files, files = await run_probe_async(
        base_url=base_url,
        token=token,
        target_type=target_type,
        workers=workers,
        timeout=timeout,
        retries=retries,
        user_agent=user_agent,
        used_percent_threshold=used_percent_threshold,
        sample_size=sample_size,
        logger=logger,
    )

    delete_names = sorted({str(r.get("name")) for r in probe_results if r.get("name") and r.get("action") == "delete"})
    disable_names = sorted({str(r.get("name")) for r in probe_results if r.get("name") and r.get("action") == "disable"})
    enable_names = sorted({str(r.get("name")) for r in probe_results if r.get("name") and r.get("action") == "enable"})

    invalid_401_count = len([r for r in probe_results if r.get("invalid_401")])
    invalid_used_percent_count = len([r for r in probe_results if r.get("invalid_used_percent")])
    quota_count = len([r for r in probe_results if r.get("is_quota")])
    healthy_disabled_count = len([r for r in probe_results if r.get("is_healthy") and r.get("disabled")])

    logger.info(
        "探测完成: 总账号=%s, %s账号=%s, 本轮探测=%s, 401失效=%s, used_percent超标=%s, quota=%s, healthy+disabled=%s",
        total_files,
        target_type,
        target_files,
        probed_files,
        invalid_401_count,
        invalid_used_percent_count,
        quota_count,
        healthy_disabled_count,
    )
    logger.info(
        "清理策略决策: 待删=%s, 待禁用=%s, 待启用=%s",
        len(delete_names),
        len(disable_names),
        len(enable_names),
    )

    deleted_ok, deleted_fail = await run_delete_async(
        base_url=base_url,
        token=token,
        names_to_delete=delete_names,
        delete_workers=delete_workers,
        timeout=timeout,
    )

    disabled_ok, disabled_fail = await run_update_disabled_async(
        base_url=base_url,
        token=token,
        names=disable_names,
        disabled=True,
        workers=delete_workers,
        timeout=timeout,
    )
    enabled_ok, enabled_fail = await run_update_disabled_async(
        base_url=base_url,
        token=token,
        names=enable_names,
        disabled=False,
        workers=delete_workers,
        timeout=timeout,
    )
    logger.info(
        "清理动作汇总: 删除(成功=%s 失败=%s) 禁用(成功=%s 失败=%s) 启用(成功=%s 失败=%s)",
        deleted_ok,
        deleted_fail,
        disabled_ok,
        disabled_fail,
        enabled_ok,
        enabled_fail,
    )

    refreshed_files = files
    try:
        refreshed_files = fetch_auth_files(base_url, token, timeout)
    except Exception as e:
        logger.warning("清理动作后重新拉取 auth-files 失败，回退旧列表: %s", e)
    return {
        "action_total": len(delete_names) + len(disable_names) + len(enable_names),
        "delete_plan": len(delete_names),
        "delete_ok": deleted_ok,
        "delete_fail": deleted_fail,
        "disable_plan": len(disable_names),
        "disable_ok": disabled_ok,
        "disable_fail": disabled_fail,
        "enable_plan": len(enable_names),
        "enable_ok": enabled_ok,
        "enable_fail": enabled_fail,
        "files": refreshed_files,
        "total_files": total_files,
        "target_files": target_files,
        "probed_files": probed_files,
        "invalid_401_count": invalid_401_count,
        "invalid_used_percent_count": invalid_used_percent_count,
    }


def run_clean_401(conf: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    base_url = str(pick_conf(conf, "clean", "base_url", default="") or "").rstrip("/")
    token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
    target_type = str(pick_conf(conf, "clean", "target_type", default="codex") or "codex")
    workers = int(pick_conf(conf, "clean", "workers", default=20) or 20)
    delete_workers = int(pick_conf(conf, "clean", "delete_workers", default=40) or 40)
    timeout = int(pick_conf(conf, "clean", "timeout", default=10) or 10)
    retries = int(pick_conf(conf, "clean", "retries", default=1) or 1)
    user_agent = str(pick_conf(conf, "clean", "user_agent", default=DEFAULT_MGMT_UA) or DEFAULT_MGMT_UA)
    used_percent_threshold = int(pick_conf(conf, "clean", "used_percent_threshold", default=80) or 80)
    sample_size = max(0, int(pick_conf(conf, "clean", "sample_size", default=0) or 0))

    if not base_url or not token:
        raise RuntimeError("clean 配置缺少 base_url 或 token/cpa_password")

    if aiohttp is None:
        logger.warning("未安装 aiohttp，跳过异步清理流程，回退为仅拉取账号列表继续执行补号。建议安装: pip install -r requirements.txt")
        try:
            files = fetch_auth_files(base_url, token, timeout)
        except Exception as e:
            raise RuntimeError(f"未安装 aiohttp，且拉取 auth-files 失败: {e}") from e
        total_files, candidates = get_candidates_count_from_files(files, target_type)
        return {
            "action_total": 0,
            "delete_plan": 0,
            "delete_ok": 0,
            "delete_fail": 0,
            "disable_plan": 0,
            "disable_ok": 0,
            "disable_fail": 0,
            "enable_plan": 0,
            "enable_ok": 0,
            "enable_fail": 0,
            "files": files,
            "total_files": total_files,
            "target_files": candidates,
            "probed_files": 0,
            "invalid_401_count": 0,
            "invalid_used_percent_count": 0,
        }

    logger.info(
        "开始清理账号: base_url=%s target_type=%s used_percent_threshold=%s sample_size=%s",
        base_url,
        target_type,
        used_percent_threshold,
        sample_size,
    )
    return asyncio.run(
        run_clean_401_async(
            base_url=base_url,
            token=token,
            target_type=target_type,
            workers=workers,
            delete_workers=delete_workers,
            timeout=timeout,
            retries=retries,
            user_agent=user_agent,
            used_percent_threshold=used_percent_threshold,
            sample_size=sample_size,
            logger=logger,
        )
    )


def get_counts_after_cleanup(
    *,
    base_url: str,
    token: str,
    target_type: str,
    timeout: int,
    deleted_ok: int,
    pre_total: int,
    pre_candidates: int,
    logger: logging.Logger,
    retries: int = 4,
    delay_seconds: float = 1.0,
) -> tuple[int, int]:
    observed_total = pre_total
    observed_candidates = pre_candidates

    for attempt in range(1, max(1, retries) + 1):
        observed_total, observed_candidates = get_candidates_count(
            base_url=base_url,
            token=token,
            target_type=target_type,
            timeout=timeout,
        )
        if deleted_ok <= 0:
            return observed_total, observed_candidates
        if observed_total < pre_total or observed_candidates < pre_candidates:
            return observed_total, observed_candidates
        if attempt < retries:
            time.sleep(delay_seconds)

    if deleted_ok > 0 and observed_total >= pre_total and observed_candidates >= pre_candidates:
        corrected_total = max(0, pre_total - deleted_ok)
        corrected_candidates = max(0, pre_candidates - deleted_ok)
        logger.warning(
            "删除后统计未及时反映（疑似缓存/延迟），按删除成功数保守修正: observed_total=%s observed_candidates=%s deleted_ok=%s corrected_total=%s corrected_candidates=%s",
            observed_total,
            observed_candidates,
            deleted_ok,
            corrected_total,
            corrected_candidates,
        )
        return corrected_total, corrected_candidates

    return observed_total, observed_candidates


def resolve_loop_interval_seconds(conf: Dict[str, Any], cli_value: Optional[float] = None) -> float:
    raw_value: Any
    if cli_value is not None:
        raw_value = cli_value
    else:
        raw_value = pick_conf(conf, "maintainer", "loop_interval_seconds", default=DEFAULT_LOOP_INTERVAL_SECONDS)

    try:
        interval = float(raw_value)
    except Exception:
        interval = DEFAULT_LOOP_INTERVAL_SECONDS
    return max(MIN_LOOP_INTERVAL_SECONDS, interval)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    app_data_dir = Path(os.environ.get("APP_DATA_DIR", str(script_dir)))
    default_cfg = Path(os.environ.get("APP_CONFIG_PATH", str(app_data_dir / "config.json")))
    default_log_dir = Path(os.environ.get("APP_LOG_DIR", str(app_data_dir / "logs")))

    parser = argparse.ArgumentParser(description="账号池自动维护（三合一：清理+补号+收敛）")
    parser.add_argument("--config", default=str(default_cfg), help="统一配置文件路径")
    parser.add_argument(
        "--min-candidates",
        type=int,
        default=None,
        help="候选账号最小阈值（默认读取 maintainer.min_candidates / 顶层 min_candidates，最终默认 100）",
    )
    parser.add_argument("--timeout", type=int, default=15, help="统计 candidates 时接口超时秒数")
    parser.add_argument("--log-dir", default=str(default_log_dir), help="日志目录")
    parser.add_argument("--loop", action="store_true", help="开启循环维护模式（按固定间隔重复执行清理+补号）")
    parser.add_argument("--loop-interval", type=float, default=None, help="循环模式的检查间隔秒数（默认读取 maintainer.loop_interval_seconds，兜底 60s）")
    return parser.parse_args()


def run_maintainer_once(args: argparse.Namespace, logger: logging.Logger, config_path: Path) -> int:
    if not config_path.exists():
        logger.error("配置文件不存在: %s", config_path)
        return 2

    conf = load_json(config_path)

    base_url = str(pick_conf(conf, "clean", "base_url", default="") or "").rstrip("/")
    token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
    target_type = str(pick_conf(conf, "clean", "target_type", default="codex") or "codex")

    cfg_min_candidates = pick_conf(conf, "maintainer", "min_candidates", default=None)
    if cfg_min_candidates is None:
        cfg_min_candidates = conf.get("min_candidates")

    if args.min_candidates is not None:
        min_candidates = int(args.min_candidates)
    elif cfg_min_candidates is not None:
        min_candidates = int(cfg_min_candidates)
    else:
        min_candidates = 100

    if min_candidates < 0:
        logger.error("min_candidates 不能小于 0（当前值=%s）", min_candidates)
        return 2
    if not base_url or not token:
        logger.error("缺少 clean.base_url 或 clean.token/cpa_password")
        return 2

    try:
        clean_summary = run_clean_401(conf, logger)
        deleted_ok = int(clean_summary.get("delete_ok", 0) or 0)
        pre_total_files = int(clean_summary.get("total_files", 0) or 0)
        pre_candidates = int(clean_summary.get("target_files", 0) or 0)
        logger.info(
            "清理阶段汇总: 动作总计=%s | 删除 %s/%s | 禁用 %s/%s | 启用 %s/%s",
            clean_summary.get("action_total", 0),
            clean_summary.get("delete_ok", 0),
            clean_summary.get("delete_plan", 0),
            clean_summary.get("disable_ok", 0),
            clean_summary.get("disable_plan", 0),
            clean_summary.get("enable_ok", 0),
            clean_summary.get("enable_plan", 0),
        )
    except Exception as e:
        logger.error("清理无效账号失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 3

    try:
        total_after_clean, candidates_after_clean = get_counts_after_cleanup(
            base_url=base_url,
            token=token,
            target_type=target_type,
            timeout=args.timeout,
            deleted_ok=deleted_ok,
            pre_total=pre_total_files,
            pre_candidates=pre_candidates,
            logger=logger,
        )
    except Exception as e:
        logger.error("删除后统计失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 4

    logger.info(
        "清理后统计: 总账号=%s, candidates=%s, 阈值=%s",
        total_after_clean,
        candidates_after_clean,
        min_candidates,
    )

    if candidates_after_clean >= min_candidates:
        logger.info("当前 candidates 已达标，无需补号。")
        logger.info("=== 账号池自动维护结束（成功）===")
        return 0

    gap = min_candidates - candidates_after_clean
    logger.info("当前 candidates 未达标，缺口=%s，开始补号。", gap)

    try:
        filled, failed, synced = run_batch_register(conf=conf, target_tokens=gap, logger=logger)
        logger.info("补号阶段汇总: 成功token=%s, 失败=%s, 收敛账号=%s", filled, failed, synced)
    except Exception as e:
        logger.error("补号阶段失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 5

    try:
        total_final, candidates_final = get_candidates_count(
            base_url=base_url,
            token=token,
            target_type=target_type,
            timeout=args.timeout,
        )
    except Exception as e:
        logger.error("补号后统计失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 6

    logger.info(
        "补号后统计: 总账号=%s, codex账号=%s, codex目标=%s",
        total_final,
        candidates_final,
        min_candidates,
    )
    if candidates_final < min_candidates:
        logger.warning("最终 codex账号数 仍低于阈值，请检查邮箱/OAuth/上传链路。")
    logger.info("=== 账号池自动维护结束（成功）===")
    return 0


def run_maintainer_loop(args: argparse.Namespace, logger: logging.Logger, config_path: Path) -> int:
    logger.info("=== 账号池循环维护开始 ===")
    loop_round = 0
    while True:
        loop_round += 1
        logger.info(">>> 循环轮次 #%s 开始", loop_round)
        round_start = time.time()
        exit_code = run_maintainer_once(args=args, logger=logger, config_path=config_path)
        elapsed = time.time() - round_start
        if exit_code == 0:
            logger.info(">>> 循环轮次 #%s 完成（成功），耗时 %.1fs", loop_round, elapsed)
        else:
            logger.warning(">>> 循环轮次 #%s 完成（失败 code=%s），耗时 %.1fs", loop_round, exit_code, elapsed)

        conf: Dict[str, Any] = {}
        if config_path.exists():
            try:
                conf = load_json(config_path)
            except Exception as e:
                logger.warning("循环模式读取配置失败，使用默认间隔: %s", e)
        sleep_seconds = resolve_loop_interval_seconds(conf, args.loop_interval)
        logger.info("循环模式休眠 %.1fs 后再次检查号池", sleep_seconds)
        time.sleep(sleep_seconds)


def main() -> int:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    args = parse_args()
    config_path = Path(args.config).resolve()
    logger, log_path = setup_logger(Path(args.log_dir).resolve())
    logger.info("=== 账号池自动维护开始（二合一）===")
    logger.info("配置文件: %s", config_path)
    logger.info("日志文件: %s", log_path)

    if args.loop:
        return run_maintainer_loop(args=args, logger=logger, config_path=config_path)
    return run_maintainer_once(args=args, logger=logger, config_path=config_path)


if __name__ == "__main__":
    raise SystemExit(main())
