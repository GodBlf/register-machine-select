#!/usr/bin/env python3
"""Standalone tempmail.lol example client for skill reuse."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, Optional


DEFAULT_BASE_URL = "https://api.tempmail.lol/v2"
DEFAULT_PATTERN = r"(?<!\d)(\d{6})(?!\d)"
DEFAULT_USER_AGENT = "curl/8.0.0"


class TempmailLolError(RuntimeError):
    """Raised when the tempmail.lol API returns an invalid result."""


def _build_headers(user_agent: str, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    if extra:
        headers.update(extra)
    return headers


def request_json(
    method: str,
    url: str,
    *,
    user_agent: str,
    data: Optional[Dict[str, Any]] = None,
    timeout: int = 20,
) -> Any:
    body: Optional[bytes] = None
    headers = _build_headers(user_agent)

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise TempmailLolError(f"{method} {url} failed: HTTP {exc.code} {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        raise TempmailLolError(f"{method} {url} failed: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TempmailLolError(f"{method} {url} returned non-JSON: {raw[:200]}") from exc


def create_inbox(base_url: str, *, timeout: int, user_agent: str) -> Dict[str, str]:
    payload = request_json(
        "POST",
        f"{base_url.rstrip('/')}/inbox/create",
        user_agent=user_agent,
        data={},
        timeout=timeout,
    )

    address = str(payload.get("address", "")).strip()
    token = str(payload.get("token", "")).strip()

    if not address or not token:
        raise TempmailLolError(f"create response missing address/token: {payload}")

    return {
        "email": address,
        "address": address,
        "token": token,
        "service_id": token,
    }


def get_inbox(base_url: str, token: str, *, timeout: int, user_agent: str) -> Dict[str, Any]:
    query = urllib.parse.urlencode({"token": token})
    payload = request_json(
        "GET",
        f"{base_url.rstrip('/')}/inbox?{query}",
        user_agent=user_agent,
        timeout=timeout,
    )

    if not isinstance(payload, dict):
        raise TempmailLolError(f"inbox response must be an object: {payload!r}")

    return payload


def _message_key(message: Dict[str, Any]) -> str:
    for field in ("date", "id"):
        value = message.get(field)
        if value:
            return str(value)
    return json.dumps(message, sort_keys=True, ensure_ascii=False)


def _combine_fields(message: Dict[str, Any]) -> str:
    return "\n".join(
        [
            str(message.get("from", "")),
            str(message.get("subject", "")),
            str(message.get("body", "")),
            str(message.get("html") or ""),
        ]
    ).strip()


def find_code(
    messages: Iterable[Dict[str, Any]],
    *,
    seen: set[str],
    pattern: str,
    sender_filter: Optional[str],
) -> Optional[Dict[str, Any]]:
    sender_filter_lower = sender_filter.lower() if sender_filter else None

    for message in messages:
        if not isinstance(message, dict):
            continue

        key = _message_key(message)
        if key in seen:
            continue
        seen.add(key)

        content = _combine_fields(message)
        if sender_filter_lower and sender_filter_lower not in content.lower():
            continue

        match = re.search(pattern, content)
        if match:
            return {
                "code": match.group(1),
                "message": message,
            }

    return None


def wait_for_code(
    base_url: str,
    token: str,
    *,
    timeout: int,
    poll_interval: float,
    pattern: str,
    sender_filter: Optional[str],
    user_agent: str,
) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout
    seen: set[str] = set()

    while time.time() < deadline:
        inbox = get_inbox(base_url, token, timeout=timeout, user_agent=user_agent)

        if not inbox or inbox.get("expired") is True:
            return None

        messages = inbox.get("emails", [])
        if isinstance(messages, list):
            result = find_code(
                messages,
                seen=seen,
                pattern=pattern,
                sender_filter=sender_filter,
            )
            if result:
                return result

        remaining = deadline - time.time()
        if remaining <= 0:
            break

        time.sleep(min(poll_interval, max(0.0, remaining)))

    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Minimal tempmail.lol helper.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds")
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="HTTP User-Agent header. Do not leave this empty.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Create a disposable inbox")
    create_parser.set_defaults(command="create")

    wait_parser = subparsers.add_parser("wait-code", help="Poll an inbox token until a code appears")
    wait_parser.add_argument("--token", required=True, help="Inbox token returned by create")
    wait_parser.add_argument("--pattern", default=DEFAULT_PATTERN, help="Regex with one capture group")
    wait_parser.add_argument("--sender-filter", default=None, help="Optional substring filter")
    wait_parser.add_argument("--poll-interval", type=float, default=3.0, help="Polling interval in seconds")
    wait_parser.add_argument("--wait-timeout", type=int, default=120, help="Total wait time in seconds")
    wait_parser.set_defaults(command="wait-code")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "create":
            result = create_inbox(args.base_url, timeout=args.timeout, user_agent=args.user_agent)
            print(json.dumps(result, ensure_ascii=False))
            return 0

        result = wait_for_code(
            args.base_url,
            args.token,
            timeout=args.wait_timeout,
            poll_interval=args.poll_interval,
            pattern=args.pattern,
            sender_filter=args.sender_filter,
            user_agent=args.user_agent,
        )
        if not result:
            return 1

        print(json.dumps(result, ensure_ascii=False))
        return 0
    except TempmailLolError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
