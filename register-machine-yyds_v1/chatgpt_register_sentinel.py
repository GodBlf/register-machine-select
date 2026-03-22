"""
ChatGPT 批量自动注册工具 (并发版) - YYDS Mail 临时邮箱版
依赖: pip install curl_cffi
功能: 使用 YYDS Mail (215.im) 临时邮箱，并发自动注册 ChatGPT 账号，自动获取 OTP 验证码
"""

import os
import re
import uuid
import json
import random
import string
import time
import sys
import threading
import traceback
import secrets
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode

from curl_cffi import requests as curl_requests

# ================= 加载配置 =================
def _load_config():
    """从 config.json 加载配置，环境变量优先级更高"""
    config = {
        "total_accounts": 3,
        "yydsmail_api_base": "https://maliapi.215.im/v1",
        "yydsmail_api_key": "",
        "proxy": "",
        "output_file": "registered_accounts.txt",
        "enable_oauth": True,
        "oauth_required": True,
        "oauth_issuer": "https://auth.openai.com",
        "oauth_client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
        "oauth_redirect_uri": "http://localhost:1455/auth/callback",
        "ak_file": "ak.txt",
        "rk_file": "rk.txt",
        "token_json_dir": "codex_tokens",
        "upload_api_url": "",
        "upload_api_token": "",
        "cpa_cleanup_enabled": True,
    }

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"⚠️ 加载 config.json 失败: {e}")

    # 环境变量优先级更高
    config["yydsmail_api_base"] = os.environ.get("YYDSMAIL_API_BASE", config["yydsmail_api_base"])
    config["yydsmail_api_key"] = os.environ.get("YYDSMAIL_API_KEY", config["yydsmail_api_key"])
    config["proxy"] = os.environ.get("PROXY", config["proxy"])
    config["total_accounts"] = int(os.environ.get("TOTAL_ACCOUNTS", config["total_accounts"]))
    config["enable_oauth"] = os.environ.get("ENABLE_OAUTH", config["enable_oauth"])
    config["oauth_required"] = os.environ.get("OAUTH_REQUIRED", config["oauth_required"])
    config["oauth_issuer"] = os.environ.get("OAUTH_ISSUER", config["oauth_issuer"])
    config["oauth_client_id"] = os.environ.get("OAUTH_CLIENT_ID", config["oauth_client_id"])
    config["oauth_redirect_uri"] = os.environ.get("OAUTH_REDIRECT_URI", config["oauth_redirect_uri"])
    config["ak_file"] = os.environ.get("AK_FILE", config["ak_file"])
    config["rk_file"] = os.environ.get("RK_FILE", config["rk_file"])
    config["token_json_dir"] = os.environ.get("TOKEN_JSON_DIR", config["token_json_dir"])
    config["upload_api_url"] = os.environ.get("UPLOAD_API_URL", config["upload_api_url"])
    config["upload_api_token"] = os.environ.get("UPLOAD_API_TOKEN", config["upload_api_token"])

    return config


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


_CONFIG = _load_config()
YYDSMAIL_API_BASE = _CONFIG["yydsmail_api_base"].rstrip("/")
YYDSMAIL_API_KEY = _CONFIG["yydsmail_api_key"]
DEFAULT_TOTAL_ACCOUNTS = _CONFIG["total_accounts"]
DEFAULT_PROXY = _CONFIG["proxy"]
DEFAULT_OUTPUT_FILE = _CONFIG["output_file"]
ENABLE_OAUTH = _as_bool(_CONFIG.get("enable_oauth", True))
OAUTH_REQUIRED = _as_bool(_CONFIG.get("oauth_required", True))
OAUTH_ISSUER = _CONFIG["oauth_issuer"].rstrip("/")
OAUTH_CLIENT_ID = _CONFIG["oauth_client_id"]
OAUTH_REDIRECT_URI = _CONFIG["oauth_redirect_uri"]
AK_FILE = _CONFIG["ak_file"]
RK_FILE = _CONFIG["rk_file"]
TOKEN_JSON_DIR = _CONFIG["token_json_dir"]
UPLOAD_API_URL = _CONFIG["upload_api_url"]
UPLOAD_API_TOKEN = _CONFIG["upload_api_token"]
CPA_CLEANUP_ENABLED = _as_bool(_CONFIG.get("cpa_cleanup_enabled", True))

if not YYDSMAIL_API_KEY:
    print("⚠️ 警告: 未设置 YYDSMAIL_API_KEY，请在 config.json 中设置或设置环境变量")
    print("   文件: config.json -> yydsmail_api_key")
    print("   环境变量: export YYDSMAIL_API_KEY='AC-your_api_key_here'")

# 全局线程锁
_print_lock = threading.Lock()
_file_lock = threading.Lock()


# Chrome 指纹配置: impersonate 与 sec-ch-ua 必须匹配真实浏览器
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]


def _random_chrome_version():
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


def _random_delay(low=0.3, high=1.0):
    time.sleep(random.uniform(low, high))


def _make_trace_headers():
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


def _generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class SentinelTokenGenerator:
    """纯 Python 版本 sentinel token 生成器（PoW）"""

    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str):
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

    def _get_config(self):
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            time.gmtime(),
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        nav_val = f"{nav_prop}-undefined"

        return [
            "1920x1080",
            now_str,
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            "en-US,en",
            random.random(),
            nav_val,
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time_origin,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed if seed is not None else self.requirements_seed
        difficulty = str(difficulty or "0")
        start_time = time.time()
        config = self._get_config()

        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data


def fetch_sentinel_challenge(session, device_id, flow="authorize_continue", user_agent=None,
                             sec_ch_ua=None, impersonate=None):
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    kwargs = {
        "data": json.dumps(req_body),
        "headers": headers,
        "timeout": 20,
    }
    if impersonate:
        kwargs["impersonate"] = impersonate

    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
    except Exception:
        return None

    if resp.status_code != 200:
        return None

    try:
        return resp.json()
    except Exception:
        return None


def build_sentinel_token(session, device_id, flow="authorize_continue", user_agent=None,
                         sec_ch_ua=None, impersonate=None):
    challenge = fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )
    if not challenge:
        return None

    c_value = challenge.get("token", "")
    if not c_value:
        return None

    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    return json.dumps({
        "p": p_value,
        "t": "",
        "c": c_value,
        "id": device_id,
        "flow": flow,
    }, separators=(",", ":"))


def _extract_code_from_url(url: str):
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None


def _decode_jwt_payload(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def _save_codex_tokens(email: str, tokens: dict):
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    id_token = tokens.get("id_token", "")

    if access_token:
        with _file_lock:
            with open(AK_FILE, "a", encoding="utf-8") as f:
                f.write(f"{access_token}\n")

    if refresh_token:
        with _file_lock:
            with open(RK_FILE, "a", encoding="utf-8") as f:
                f.write(f"{refresh_token}\n")

    if not access_token:
        return

    payload = _decode_jwt_payload(access_token)
    auth_info = payload.get("https://api.openai.com/auth", {})
    account_id = auth_info.get("chatgpt_account_id", "")

    exp_timestamp = payload.get("exp")
    expired_str = ""
    if isinstance(exp_timestamp, int) and exp_timestamp > 0:
        from datetime import datetime, timezone, timedelta

        exp_dt = datetime.fromtimestamp(exp_timestamp, tz=timezone(timedelta(hours=8)))
        expired_str = exp_dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")

    from datetime import datetime, timezone, timedelta

    now = datetime.now(tz=timezone(timedelta(hours=8)))
    token_data = {
        "type": "codex",
        "email": email,
        "expired": expired_str,
        "id_token": id_token,
        "account_id": account_id,
        "access_token": access_token,
        "last_refresh": now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        "refresh_token": refresh_token,
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    token_dir = TOKEN_JSON_DIR if os.path.isabs(TOKEN_JSON_DIR) else os.path.join(base_dir, TOKEN_JSON_DIR)
    os.makedirs(token_dir, exist_ok=True)

    token_path = os.path.join(token_dir, f"{email}.json")
    with _file_lock:
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f, ensure_ascii=False)



def _upload_token_json(filepath):
    """上传单个 token JSON 文件到 CPA 管理平台"""
    mp = None
    try:
        from curl_cffi import CurlMime
        filename = os.path.basename(filepath)
        mp = CurlMime()
        mp.addpart(name="file", content_type="application/json",
                   filename=filename, local_path=filepath)
        session = curl_requests.Session()
        if DEFAULT_PROXY:
            session.proxies = {"http": DEFAULT_PROXY, "https": DEFAULT_PROXY}
        resp = session.post(UPLOAD_API_URL, multipart=mp,
                            headers={"Authorization": f"Bearer {UPLOAD_API_TOKEN}"},
                            verify=False, timeout=30)
        if resp.status_code == 200:
            print(f"  [CPA] ✅ {filename} 已上传到 CPA 管理平台")
            return True
        else:
            print(f"  [CPA] ❌ {filename} 上传失败: {resp.status_code} - {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  [CPA] ❌ {os.path.basename(filepath)} 上传异常: {e}")
        return False
    finally:
        if mp:
            mp.close()


def _upload_all_tokens_to_cpa():
    """批量上传 codex_tokens 目录下所有 JSON 文件到 CPA，上传成功后删除文件"""
    if not UPLOAD_API_URL:
        print("\n[CPA] ⚠️ 未配置 upload_api_url，跳过 CPA 上传")
        return

    base_dir = os.path.dirname(os.path.abspath(__file__))
    token_dir = TOKEN_JSON_DIR if os.path.isabs(TOKEN_JSON_DIR) else os.path.join(base_dir, TOKEN_JSON_DIR)

    if not os.path.isdir(token_dir):
        print(f"\n[CPA] ⚠️ codex_tokens 目录不存在: {token_dir}")
        return

    json_files = [f for f in os.listdir(token_dir) if f.endswith(".json")]
    if not json_files:
        print(f"\n[CPA] ⚠️ codex_tokens 目录下没有 JSON 文件")
        return

    print(f"\n{'='*60}")
    print(f"  [CPA] 开始上传 {len(json_files)} 个账号到 CPA 管理平台")
    print(f"{'='*60}")

    uploaded = 0
    failed = 0
    for filename in json_files:
        filepath = os.path.join(token_dir, filename)
        if _upload_token_json(filepath):
            try:
                os.remove(filepath)
                print(f"  [CPA] 🗑️ 已删除本地文件: {filename}")
            except Exception as e:
                print(f"  [CPA] ⚠️ 删除文件失败 {filename}: {e}")
            uploaded += 1
        else:
            failed += 1

    print(f"\n  [CPA] 上传完成: 成功 {uploaded} 个, 失败 {failed} 个")
    print(f"{'='*60}")


# ================= CPA Codex 清理引擎 (内嵌) =================

from datetime import datetime as _cpa_datetime
from concurrent.futures import Future as _cpa_Future
from urllib.parse import urlparse as _cpa_urlparse, urlunparse as _cpa_urlunparse

_CPA_STATUS_KEYWORDS = {
    "token_invalidated",
    "token_revoked",
    "usage_limit_reached",
}

_CPA_MESSAGE_KEYWORDS = [
    "额度获取失败：401",
    '"status":401',
    '"status": 401',
    "your authentication token has been invalidated.",
    "encountered invalidated oauth token for user",
    "token_invalidated",
    "token_revoked",
    "usage_limit_reached",
]

_CPA_PROBE_TARGET_URL = "https://chatgpt.com/backend-api/codex/responses/compact"
_CPA_PROBE_MODEL = "gpt-5.1-codex"


def _cpa_normalize_api_root(raw_url):
    value = (raw_url or "").strip()
    if not value:
        return ""
    parsed = _cpa_urlparse(value)
    path = parsed.path or ""
    if path.endswith("/management.html"):
        path = path[: -len("/management.html")] + "/v0/management"
    for suffix in ("/api-call", "/auth-files"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
    normalized = _cpa_urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "", ""))
    return normalized.rstrip("/")


class _CpaCleanupConfig:
    def __init__(self, management_url, management_token, management_timeout=15,
                 active_probe=True, probe_timeout=8, probe_workers=12,
                 delete_workers=8, max_active_probes=120):
        self.management_url = management_url
        self.management_token = management_token
        self.management_timeout = management_timeout
        self.active_probe = active_probe
        self.probe_timeout = probe_timeout
        self.probe_workers = probe_workers
        self.delete_workers = delete_workers
        self.max_active_probes = max_active_probes

    @classmethod
    def from_mapping(cls, data):
        def to_int(name, default, minimum):
            try:
                parsed = int(data.get(name, default))
            except Exception:
                parsed = default
            return max(minimum, parsed)

        def to_bool(name, default):
            raw = data.get(name, default)
            if isinstance(raw, bool):
                return raw
            text = str(raw).strip().lower()
            if text in {"1", "true", "yes", "on"}:
                return True
            if text in {"0", "false", "no", "off"}:
                return False
            return default

        return cls(
            management_url=_cpa_normalize_api_root(str(data.get("management_url", "") or "")),
            management_token=str(data.get("management_token", "") or "").strip(),
            management_timeout=to_int("management_timeout", 15, 1),
            active_probe=to_bool("active_probe", True),
            probe_timeout=to_int("probe_timeout", 8, 1),
            probe_workers=to_int("probe_workers", 12, 1),
            delete_workers=to_int("delete_workers", 8, 1),
            max_active_probes=to_int("max_active_probes", 120, 0),
        )

    def validate(self):
        if not self.management_url:
            return False, "management_url 不能为空"
        if not self.management_token:
            return False, "management_token 不能为空"
        if not self.management_url.startswith(("http://", "https://")):
            return False, "management_url 必须以 http:// 或 https:// 开头"
        return True, ""


class _CpaManagementGateway:
    def __init__(self, config):
        self.config = config

    @property
    def _headers(self):
        return {"Authorization": f"Bearer {self.config.management_token}"}

    @property
    def auth_files_endpoint(self):
        return self.config.management_url.rstrip("/") + "/auth-files"

    @property
    def api_call_endpoint(self):
        return self.config.management_url.rstrip("/") + "/api-call"

    def list_auth_files(self):
        resp = curl_requests.get(self.auth_files_endpoint, headers=self._headers,
                                 timeout=self.config.management_timeout)
        if resp.status_code == 404:
            raise RuntimeError(
                f"auth-files 接口不存在: {self.auth_files_endpoint} (HTTP 404). "
                "请确认 management_url 是管理 API 根路径"
            )
        resp.raise_for_status()
        payload = resp.json()
        files = payload.get("files", []) if isinstance(payload, dict) else []
        return files if isinstance(files, list) else []

    def delete_auth_file(self, name):
        resp = curl_requests.delete(
            self.auth_files_endpoint,
            params={"name": name},
            headers=self._headers,
            timeout=self.config.management_timeout,
        )
        if 200 <= resp.status_code < 300:
            return True, ""
        detail = ""
        try:
            detail = json.dumps(resp.json(), ensure_ascii=False)
        except Exception:
            detail = resp.text
        return False, f"HTTP {resp.status_code}: {detail}"

    def probe_auth_index(self, auth_index):
        payload = {
            "auth_index": auth_index,
            "method": "POST",
            "url": _CPA_PROBE_TARGET_URL,
            "header": {
                "Authorization": "Bearer $TOKEN$",
                "Content-Type": "application/json",
                "User-Agent": "codex_cli_rs/0.101.0",
            },
            "data": json.dumps(
                {"model": _CPA_PROBE_MODEL, "input": [{"role": "user", "content": "ping"}]},
                ensure_ascii=False,
            ),
        }
        resp = curl_requests.post(
            self.api_call_endpoint,
            headers=self._headers,
            json=payload,
            timeout=self.config.probe_timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict):
            return 0, ""
        return int(body.get("status_code", 0) or 0), str(body.get("body", "") or "")


def _cpa_safe_status_message(file_obj):
    return str(file_obj.get("status_message", "") or "")


def _cpa_reason_from_status(file_obj):
    status_message = _cpa_safe_status_message(file_obj)
    if not status_message:
        return ""
    lower_msg = status_message.lower()
    for keyword in _CPA_MESSAGE_KEYWORDS:
        if keyword in lower_msg:
            return keyword
    try:
        parsed = json.loads(status_message)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        if int(parsed.get("status", 0) or 0) == 401:
            return "status_401"
        err = parsed.get("error", {})
        if isinstance(err, dict):
            code = str(err.get("code", "") or "")
            if code in _CPA_STATUS_KEYWORDS:
                return code
    return ""


def _cpa_looks_401(file_obj):
    try:
        if int(file_obj.get("status", 0) or 0) == 401:
            return True
    except Exception:
        pass
    text = _cpa_safe_status_message(file_obj).lower()
    return "401" in text or "unauthorized" in text


class _CpaCleanupOrchestrator:
    def __init__(self, config, log=None):
        self.config = config
        self.gateway = _CpaManagementGateway(config)
        self.log = log or (lambda msg: None)

    def _log(self, message):
        self.log(message)

    def _probe_one(self, file_obj):
        name = str(file_obj.get("name", "") or "")
        auth_index = str(file_obj.get("auth_index", "") or "").strip()
        if not auth_index:
            return name, ""
        try:
            status_code, body = self.gateway.probe_auth_index(auth_index)
        except Exception as exc:
            return name, f"probe_error:{exc}"
        body_lower = body.lower()
        if status_code == 401:
            return name, "probe_status_401"
        if "401" in body_lower or "unauthorized" in body_lower:
            return name, "probe_body_401"
        for keyword in _CPA_MESSAGE_KEYWORDS:
            if keyword in body_lower:
                return name, f"probe_{keyword}"
        return name, ""

    def _delete_batch(self, hits):
        deleted = 0
        failures = []
        total = len(hits)

        def task(item):
            ok, err = self.gateway.delete_auth_file(item["name"])
            return item["name"], ok, err

        with ThreadPoolExecutor(max_workers=self.config.delete_workers) as pool:
            future_map = {pool.submit(task, item): item for item in hits}
            done = 0
            for future in as_completed(future_map):
                done += 1
                name, ok, err = future.result()
                if ok:
                    deleted += 1
                    self._log(f"[CPA清理] 删除成功: {name} ({done}/{total})")
                else:
                    failures.append({"name": name, "error": err})
                    self._log(f"[CPA清理] 删除失败: {name} -> {err}")
        return deleted, failures

    def _cleanup_401_only(self, exclude_names):
        try:
            files = self.gateway.list_auth_files()
        except Exception as exc:
            self._log(f"[CPA清理] 401补删列表读取失败: {exc}")
            return 0, [{"name": "<list>", "error": str(exc)}]
        targets = []
        for file_obj in files:
            name = str(file_obj.get("name", "") or "")
            if not name or name in exclude_names:
                continue
            if _cpa_looks_401(file_obj):
                targets.append({"name": name, "keyword": "status_401",
                                "status_message": _cpa_safe_status_message(file_obj)})
        if not targets:
            self._log("[CPA清理] 401补删: 无目标")
            return 0, []
        self._log(f"[CPA清理] 401补删: 待删除 {len(targets)} 个")
        deleted, failures = self._delete_batch(targets)
        return deleted, failures

    def run(self):
        self._log("[CPA清理] 开始清理")
        self._log(f"[CPA清理] 配置: active_probe={self.config.active_probe}, "
                  f"probe_workers={self.config.probe_workers}, delete_workers={self.config.delete_workers}, "
                  f"max_active_probes={self.config.max_active_probes}")

        files = self.gateway.list_auth_files()
        self._log(f"[CPA清理] 拉取 auth-files 成功，总数: {len(files)}")

        fixed_hits = []
        probe_candidates = []

        for file_obj in files:
            reason = _cpa_reason_from_status(file_obj)
            name = str(file_obj.get("name", "") or "")
            if not name:
                continue
            if reason:
                fixed_hits.append({"name": name, "keyword": reason,
                                   "status_message": _cpa_safe_status_message(file_obj)})
                continue
            provider = str(file_obj.get("provider", "") or "").strip().lower()
            auth_index = str(file_obj.get("auth_index", "") or "").strip()
            if self.config.active_probe and provider == "codex" and auth_index:
                probe_candidates.append(file_obj)

        if self.config.active_probe and self.config.max_active_probes > 0 and len(probe_candidates) > self.config.max_active_probes:
            self._log(f"[CPA清理] 主动探测候选 {len(probe_candidates)}，仅探测前 {self.config.max_active_probes} 个")
            probe_candidates = probe_candidates[: self.config.max_active_probes]

        probed_hits = []
        if self.config.active_probe and self.config.max_active_probes != 0 and probe_candidates:
            self._log(f"[CPA清理] 开始主动探测，候选 {len(probe_candidates)} 个")
            with ThreadPoolExecutor(max_workers=self.config.probe_workers) as pool:
                future_map = {pool.submit(self._probe_one, item): item for item in probe_candidates}
                done = 0
                total = len(probe_candidates)
                for future in as_completed(future_map):
                    done += 1
                    name, reason = future.result()
                    if reason:
                        if not reason.startswith("probe_error"):
                            status_message = _cpa_safe_status_message(future_map[future])
                            probed_hits.append({"name": name, "keyword": reason,
                                                "status_message": status_message})
                            self._log(f"[CPA清理] 探测命中: {name} -> {reason}")
                        else:
                            self._log(f"[CPA清理] 探测异常: {name} -> {reason}")
                    if done % 20 == 0 or done == total:
                        self._log(f"[CPA清理] 探测进度: {done}/{total}")
        else:
            self._log("[CPA清理] 主动探测已关闭或无候选")

        merged_by_name = {}
        for item in fixed_hits + probed_hits:
            if item["name"] not in merged_by_name:
                merged_by_name[item["name"]] = item

        matched = list(merged_by_name.values())
        self._log(f"[CPA清理] 命中删除规则: {len(matched)}")

        deleted_main = 0
        failures = []
        if matched:
            deleted_main, failures = self._delete_batch(matched)
        else:
            self._log("[CPA清理] 主流程无删除目标")

        deleted_401, failures_401 = self._cleanup_401_only(set(merged_by_name.keys()))
        failures.extend(failures_401)

        result = {
            "scanned_total": len(files),
            "matched_total": len(matched),
            "deleted_main": deleted_main,
            "deleted_401": deleted_401,
            "deleted_total": deleted_main + deleted_401,
            "failures": failures,
        }
        self._log(f"[CPA清理] 完成: scanned={result['scanned_total']}, matched={result['matched_total']}, "
                  f"deleted_main={result['deleted_main']}, deleted_401={result['deleted_401']}, "
                  f"deleted_total={result['deleted_total']}")
        if result["failures"]:
            self._log(f"[CPA清理] 失败数: {len(result['failures'])}")
        return result


def _cpa_execute_cleanup(payload, log=None):
    config = _CpaCleanupConfig.from_mapping(payload)
    ok, msg = config.validate()
    if not ok:
        raise ValueError(msg)
    orchestrator = _CpaCleanupOrchestrator(config=config, log=log)
    return orchestrator.run()


def _run_cpa_cleanup_before_register():
    """在注册前执行 CPA 无效号清理，失败不阻断注册流程"""
    print(f"\n{'='*60}")
    print("  [CPA清理] 注册前清理 CPA 无效号...")
    print(f"{'='*60}")
    try:
        payload = {
            "management_url": UPLOAD_API_URL,
            "management_token": UPLOAD_API_TOKEN,
            "active_probe": True,
            "probe_workers": 12,
            "delete_workers": 8,
            "max_active_probes": 120,
        }
        result = _cpa_execute_cleanup(payload, log=lambda msg: print(f"  {msg}"))
        print(f"\n  [CPA清理] 清理完成: 扫描 {result['scanned_total']} 个, "
              f"命中 {result['matched_total']} 个, 删除 {result['deleted_total']} 个")
        if result["failures"]:
            print(f"  [CPA清理] 失败: {len(result['failures'])} 个")
    except Exception as e:
        print(f"  [CPA清理] ⚠️ 清理失败 (不影响注册): {e}")
        traceback.print_exc()
    print(f"{'='*60}\n")


def _generate_password(length=14):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%&*"
    pwd = [random.choice(lower), random.choice(upper),
           random.choice(digits), random.choice(special)]
    all_chars = lower + upper + digits + special
    pwd += [random.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(pwd)
    return "".join(pwd)


# ================= YYDS Mail 邮箱函数 =================

# 域名缓存，避免每次创建邮箱都请求
_yydsmail_domains_cache = []
_yydsmail_domains_lock = threading.Lock()


def _fetch_yydsmail_domains():
    """获取 YYDS Mail 可用域名列表（带缓存）"""
    global _yydsmail_domains_cache
    with _yydsmail_domains_lock:
        if _yydsmail_domains_cache:
            return _yydsmail_domains_cache
    try:
        headers = {}
        if YYDSMAIL_API_KEY:
            headers["X-API-Key"] = YYDSMAIL_API_KEY
        session = curl_requests.Session()
        res = session.get(f"{YYDSMAIL_API_BASE}/domains", headers=headers, timeout=15)
        if res.status_code == 200:
            data = res.json()
            domains = data if isinstance(data, list) else data.get("data", [])
            domain_names = []
            for d in domains:
                if isinstance(d, str):
                    domain_names.append(d)
                elif isinstance(d, dict):
                    name = d.get("domain") or d.get("name") or ""
                    if name:
                        domain_names.append(name)
            if domain_names:
                with _yydsmail_domains_lock:
                    _yydsmail_domains_cache = domain_names
                return domain_names
    except Exception as e:
        print(f"⚠️ 获取 YYDS Mail 域名列表失败: {e}")
    return []


def _create_yydsmail_session():
    """创建 YYDS Mail 请求会话"""
    session = curl_requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    return session


def create_temp_email():
    """创建 YYDS Mail 临时邮箱，返回 (email, mail_token)"""
    # 获取可用域名
    domains = _fetch_yydsmail_domains()
    if not domains:
        raise Exception("无法获取 YYDS Mail 可用域名列表")

    domain = random.choice(domains)
    chars = string.ascii_lowercase + string.digits
    length = random.randint(8, 13)
    prefix = "".join(random.choice(chars) for _ in range(length))

    session = _create_yydsmail_session()
    headers = {}
    if YYDSMAIL_API_KEY:
        headers["X-API-Key"] = YYDSMAIL_API_KEY

    try:
        payload = {"address": prefix, "domain": domain}
        res = session.post(
            f"{YYDSMAIL_API_BASE}/accounts",
            json=payload,
            headers=headers,
            timeout=15,
            impersonate="chrome131"
        )

        if res.status_code not in [200, 201]:
            raise Exception(f"创建邮箱失败: {res.status_code} - {res.text[:200]}")

        resp = res.json()
        data = resp.get("data", resp) if isinstance(resp, dict) else resp
        email = data.get("address", f"{prefix}@{domain}")
        mail_token = data.get("token")
        if not mail_token:
            raise Exception(f"创建邮箱成功但未返回 token, 响应: {resp}")

        return email, mail_token

    except Exception as e:
        raise Exception(f"YYDS Mail 创建邮箱失败: {e}")


def _fetch_emails_yydsmail(mail_token: str):
    """从 YYDS Mail 获取邮件列表"""
    try:
        headers = {"Authorization": f"Bearer {mail_token}"}
        session = _create_yydsmail_session()

        res = session.get(
            f"{YYDSMAIL_API_BASE}/messages",
            headers=headers,
            timeout=15,
            impersonate="chrome131"
        )

        if res.status_code == 200:
            resp = res.json()
            if isinstance(resp, list):
                return resp
            data = resp.get("data", resp)
            if isinstance(data, list):
                return data
            return data.get("messages") or []
        return []
    except Exception:
        return []


def _fetch_email_detail_yydsmail(mail_token: str, msg_id):
    """获取 YYDS Mail 单封邮件详情"""
    try:
        headers = {"Authorization": f"Bearer {mail_token}"}
        session = _create_yydsmail_session()

        res = session.get(
            f"{YYDSMAIL_API_BASE}/messages/{msg_id}",
            headers=headers,
            timeout=15,
            impersonate="chrome131"
        )

        if res.status_code == 200:
            resp = res.json()
            return resp.get("data", resp) if isinstance(resp, dict) else resp
    except Exception:
        pass
    return None


def _extract_verification_code(email_content: str):
    """从邮件内容提取 6 位验证码"""
    if not email_content:
        return None

    patterns = [
        r"Verification code:?\s*(\d{6})",
        r"code is\s*(\d{6})",
        r"代码为[:：]?\s*(\d{6})",
        r"验证码[:：]?\s*(\d{6})",
        r">\s*(\d{6})\s*<",
        r"(?<![#&])\b(\d{6})\b",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, email_content, re.IGNORECASE)
        for code in matches:
            if code == "177010":  # 已知误判
                continue
            return code
    return None


def wait_for_verification_email(mail_token: str, timeout: int = 120):
    """等待并提取 OpenAI 验证码"""
    start_time = time.time()

    while time.time() - start_time < timeout:
        messages = _fetch_emails_yydsmail(mail_token)
        if messages and len(messages) > 0:
            first_msg = messages[0]
            msg_id = first_msg.get("id")

            if msg_id:
                detail = _fetch_email_detail_yydsmail(mail_token, msg_id)
                if detail:
                    content = detail.get("text") or detail.get("html") or ""
                    code = _extract_verification_code(content)
                    if code:
                        return code

        time.sleep(3)

    return None


def _random_name():
    first = random.choice([
        "James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Sophia",
        "Lucas", "Mia", "Mason", "Isabella", "Logan", "Charlotte", "Alexander",
        "Amelia", "Benjamin", "Harper", "William", "Evelyn", "Henry", "Abigail",
        "Sebastian", "Emily", "Jack", "Elizabeth",
    ])
    last = random.choice([
        "Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor",
        "Clark", "Hall", "Young", "Anderson", "Thomas", "Jackson", "White",
        "Harris", "Martin", "Thompson", "Garcia", "Robinson", "Lewis",
        "Walker", "Allen", "King", "Wright", "Scott", "Green",
    ])
    return f"{first} {last}"


def _random_birthdate():
    y = random.randint(1985, 2002)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    return f"{y}-{m:02d}-{d:02d}"


class ChatGPTRegister:
    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"

    def __init__(self, proxy: str = None, tag: str = ""):
        self.tag = tag  # 线程标识，用于日志
        self.device_id = str(uuid.uuid4())
        self.auth_session_logging_id = str(uuid.uuid4())
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()

        self.session = curl_requests.Session(impersonate=self.impersonate)

        self.proxy = proxy
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8",
                "en,en-US;q=0.9", "en-US,en;q=0.8",
            ]),
            "sec-ch-ua": self.sec_ch_ua, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"', "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })

        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")
        self._callback_url = None

    def _log(self, step, method, url, status, body=None):
        prefix = f"[{self.tag}] " if self.tag else ""
        lines = [
            f"\n{'='*60}",
            f"{prefix}[Step] {step}",
            f"{prefix}[{method}] {url}",
            f"{prefix}[Status] {status}",
        ]
        if body:
            try:
                lines.append(f"{prefix}[Response] {json.dumps(body, indent=2, ensure_ascii=False)[:1000]}")
            except Exception:
                lines.append(f"{prefix}[Response] {str(body)[:1000]}")
        lines.append(f"{'='*60}")
        with _print_lock:
            print("\n".join(lines))

    def _print(self, msg):
        prefix = f"[{self.tag}] " if self.tag else ""
        with _print_lock:
            print(f"{prefix}{msg}")

    # ==================== YYDS Mail 临时邮箱 ====================

    def _create_yydsmail_session(self):
        """创建 YYDS Mail 请求会话"""
        session = curl_requests.Session()
        session.headers.update({
            "User-Agent": self.ua,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        return session

    def create_temp_email(self):
        """创建 YYDS Mail 临时邮箱，返回 (email, mail_token)"""
        domains = _fetch_yydsmail_domains()
        if not domains:
            raise Exception("无法获取 YYDS Mail 可用域名列表")

        domain = random.choice(domains)
        chars = string.ascii_lowercase + string.digits
        length = random.randint(8, 13)
        prefix = "".join(random.choice(chars) for _ in range(length))

        session = self._create_yydsmail_session()
        headers = {}
        if YYDSMAIL_API_KEY:
            headers["X-API-Key"] = YYDSMAIL_API_KEY

        try:
            payload = {"address": prefix, "domain": domain}
            res = session.post(
                f"{YYDSMAIL_API_BASE}/accounts",
                json=payload,
                headers=headers,
                timeout=15,
                impersonate=self.impersonate
            )

            if res.status_code not in [200, 201]:
                raise Exception(f"创建邮箱失败: {res.status_code} - {res.text[:200]}")

            resp = res.json()
            data = resp.get("data", resp) if isinstance(resp, dict) else resp
            email = data.get("address", f"{prefix}@{domain}")
            mail_token = data.get("token")
            if not mail_token:
                raise Exception(f"创建邮箱成功但未返回 token, 响应: {resp}")

            return email, mail_token

        except Exception as e:
            raise Exception(f"YYDS Mail 创建邮箱失败: {e}")

    def _fetch_emails_yydsmail(self, mail_token: str):
        """从 YYDS Mail 获取邮件列表"""
        try:
            headers = {"Authorization": f"Bearer {mail_token}"}
            session = self._create_yydsmail_session()

            res = session.get(
                f"{YYDSMAIL_API_BASE}/messages",
                headers=headers,
                timeout=15,
                impersonate=self.impersonate
            )

            if res.status_code == 200:
                resp = res.json()
                if isinstance(resp, list):
                    return resp
                data = resp.get("data", resp)
                if isinstance(data, list):
                    return data
                return data.get("messages") or []
            return []
        except Exception:
            return []

    def _fetch_email_detail_yydsmail(self, mail_token: str, msg_id):
        """获取 YYDS Mail 单封邮件详情"""
        try:
            headers = {"Authorization": f"Bearer {mail_token}"}
            session = self._create_yydsmail_session()

            res = session.get(
                f"{YYDSMAIL_API_BASE}/messages/{msg_id}",
                headers=headers,
                timeout=15,
                impersonate=self.impersonate
            )

            if res.status_code == 200:
                resp = res.json()
                return resp.get("data", resp) if isinstance(resp, dict) else resp
        except Exception:
            pass
        return None

    def _extract_verification_code(self, email_content: str):
        """从邮件内容提取 6 位验证码"""
        if not email_content:
            return None

        patterns = [
            r"Verification code:?\s*(\d{6})",
            r"code is\s*(\d{6})",
            r"代码为[:：]?\s*(\d{6})",
            r"验证码[:：]?\s*(\d{6})",
            r">\s*(\d{6})\s*<",
            r"(?<![#&])\b(\d{6})\b",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, email_content, re.IGNORECASE)
            for code in matches:
                if code == "177010":  # 已知误判
                    continue
                return code
        return None

    def wait_for_verification_email(self, mail_token: str, timeout: int = 120):
        """等待并提取 OpenAI 验证码"""
        self._print(f"[OTP] 等待验证码邮件 (最多 {timeout}s)...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            messages = self._fetch_emails_yydsmail(mail_token)
            if messages and len(messages) > 0:
                first_msg = messages[0]
                msg_id = first_msg.get("id")

                if msg_id:
                    detail = self._fetch_email_detail_yydsmail(mail_token, msg_id)
                    if detail:
                        content = detail.get("text") or detail.get("html") or ""
                        code = self._extract_verification_code(content)
                        if code:
                            self._print(f"[OTP] 验证码: {code}")
                            return code

            elapsed = int(time.time() - start_time)
            self._print(f"[OTP] 等待中... ({elapsed}s/{timeout}s)")
            time.sleep(3)

        self._print(f"[OTP] 超时 ({timeout}s)")
        return None

    # ==================== 注册流程 ====================

    def visit_homepage(self):
        url = f"{self.BASE}/"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log("0. Visit homepage", "GET", url, r.status_code,
                   {"cookies_count": len(self.session.cookies)})

    def get_csrf(self) -> str:
        url = f"{self.BASE}/api/auth/csrf"
        r = self.session.get(url, headers={"Accept": "application/json", "Referer": f"{self.BASE}/"})
        data = r.json()
        token = data.get("csrfToken", "")
        self._log("1. Get CSRF", "GET", url, r.status_code, data)
        if not token:
            raise Exception("Failed to get CSRF token")
        return token

    def signin(self, email: str, csrf: str) -> str:
        url = f"{self.BASE}/api/auth/signin/openai"
        params = {
            "prompt": "login", "ext-oai-did": self.device_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "screen_hint": "login_or_signup", "login_hint": email,
        }
        form_data = {"callbackUrl": f"{self.BASE}/", "csrfToken": csrf, "json": "true"}
        r = self.session.post(url, params=params, data=form_data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json", "Referer": f"{self.BASE}/", "Origin": self.BASE,
        })
        data = r.json()
        authorize_url = data.get("url", "")
        self._log("2. Signin", "POST", url, r.status_code, data)
        if not authorize_url:
            raise Exception("Failed to get authorize URL")
        return authorize_url

    def authorize(self, url: str) -> str:
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.BASE}/", "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }, allow_redirects=True, timeout=30, impersonate=self.impersonate)
        final_url = str(r.url)
        self._log("3. Authorize", "GET", url, r.status_code, {"final_url": final_url})
        return final_url

    def authorize_continue(self, email: str):
        """POST /api/accounts/authorize/continue — 推进 auth 状态机，建立 ChatGPT 客户端上下文"""
        sentinel_token = build_sentinel_token(
            self.session,
            self.device_id,
            flow="authorize_continue",
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate,
        )
        url = f"{self.AUTH}/api/accounts/authorize/continue"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/log-in",
            "Origin": self.AUTH,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers.update(_make_trace_headers())
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token

        r = self.session.post(
            url,
            json={"username": {"kind": "email", "value": email}},
            headers=headers,
            timeout=30,
            allow_redirects=False,
            impersonate=self.impersonate,
        )
        try:
            data = r.json()
        except Exception:
            data = {"text": r.text[:500]}
        self._log("3.5 Authorize Continue", "POST", url, r.status_code, data)
        return r.status_code, data

    def register(self, email: str, password: str):
        url = f"{self.AUTH}/api/accounts/user/register"
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="signup_password",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/create-account/password", "Origin": self.AUTH,
                    "User-Agent": self.ua, "oai-device-id": self.device_id}
        headers.update(_make_trace_headers())
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"username": email, "password": password},
                              headers=headers, impersonate=self.impersonate)
        try: data = r.json()
        except Exception: data = {"text": r.text[:500]}
        self._log("4. Register", "POST", url, r.status_code, data)
        return r.status_code, data

    def send_otp(self):
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.AUTH}/create-account/password", "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        try: data = r.json()
        except Exception: data = {"final_url": str(r.url), "status": r.status_code}
        self._log("5. Send OTP", "GET", url, r.status_code, data)
        return r.status_code, data

    def validate_otp(self, code: str):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        sentinel_token = build_sentinel_token(
            self.session, self.device_id, flow="email_otp_verification",
            user_agent=self.ua, sec_ch_ua=self.sec_ch_ua, impersonate=self.impersonate,
        )
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/email-verification", "Origin": self.AUTH,
                    "User-Agent": self.ua, "oai-device-id": self.device_id}
        headers.update(_make_trace_headers())
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"code": code}, headers=headers, impersonate=self.impersonate)
        try: data = r.json()
        except Exception: data = {"text": r.text[:500]}
        self._log("6. Validate OTP", "POST", url, r.status_code, data)
        return r.status_code, data

    def create_account(self, name: str, birthdate: str):
        url = f"{self.AUTH}/api/accounts/create_account"
        sentinel_token = build_sentinel_token(
            self.session,
            self.device_id,
            flow="create_account",
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate,
        )
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Referer": f"{self.AUTH}/about-you", "Origin": self.AUTH,
                    "User-Agent": self.ua, "oai-device-id": self.device_id}
        headers.update(_make_trace_headers())
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        r = self.session.post(url, json={"name": name, "birthdate": birthdate}, headers=headers,
                              impersonate=self.impersonate)
        try: data = r.json()
        except Exception: data = {"text": r.text[:500]}
        self._log("7. Create Account", "POST", url, r.status_code, data)
        if isinstance(data, dict):
            cb = data.get("continue_url") or data.get("url") or data.get("redirect_url")
            if cb:
                self._callback_url = cb
        return r.status_code, data

    def callback(self, url: str = None):
        if not url:
            url = self._callback_url
        if not url:
            self._print("[!] No callback URL, skipping.")
            return None, None
        r = self.session.get(url, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }, allow_redirects=True)
        self._log("8. Callback", "GET", url, r.status_code, {"final_url": str(r.url)})
        return r.status_code, {"final_url": str(r.url)}

    # ==================== 自动注册主流程 ====================

    def run_register(self, email, password, name, birthdate, mail_token):
        """原始重定向驱动流程 + sentinel tokens"""
        self.visit_homepage()
        _random_delay(0.3, 0.8)
        csrf = self.get_csrf()
        _random_delay(0.2, 0.5)
        auth_url = self.signin(email, csrf)
        _random_delay(0.3, 0.8)

        final_url = self.authorize(auth_url)
        final_path = urlparse(final_url).path
        _random_delay(0.3, 0.8)

        self._print(f"Authorize → {final_path}")

        need_otp = False

        if "create-account/password" in final_path:
            self._print("全新注册流程")
            _random_delay(0.5, 1.0)
            status, data = self.register(email, password)
            if status != 200:
                raise Exception(f"Register 失败 ({status}): {data}")
            _random_delay(0.3, 0.8)
            self.send_otp()
            need_otp = True
        elif "email-verification" in final_path or "email-otp" in final_path:
            self._print("跳到 OTP 验证阶段")
            need_otp = True
        elif "about-you" in final_path:
            self._print("跳到填写信息阶段")
            _random_delay(0.5, 1.0)
            self.create_account(name, birthdate)
            _random_delay(0.3, 0.5)
            self.callback()
            return True
        elif "callback" in final_path or "chatgpt.com" in final_url:
            self._print("账号已完成注册")
            return True
        else:
            self._print(f"未知跳转: {final_url}")
            self.register(email, password)
            self.send_otp()
            need_otp = True

        if need_otp:
            otp_code = self.wait_for_verification_email(mail_token)
            if not otp_code:
                raise Exception("未能获取验证码")

            _random_delay(0.3, 0.8)
            status, data = self.validate_otp(otp_code)
            if status != 200:
                self._print("验证码失败，重试...")
                self.send_otp()
                _random_delay(1.0, 2.0)
                otp_code = self.wait_for_verification_email(mail_token, timeout=60)
                if not otp_code:
                    raise Exception("重试后仍未获取验证码")
                _random_delay(0.3, 0.8)
                status, data = self.validate_otp(otp_code)
                if status != 200:
                    raise Exception(f"验证码失败 ({status}): {data}")

        _random_delay(0.5, 1.5)
        status, data = self.create_account(name, birthdate)
        if status != 200:
            raise Exception(f"Create account 失败 ({status}): {data}")
        _random_delay(0.2, 0.5)
        self.callback()
        return True

    def _decode_oauth_session_cookie(self):
        jar = getattr(self.session.cookies, "jar", None)
        if jar is not None:
            cookie_items = list(jar)
        else:
            cookie_items = []

        for c in cookie_items:
            name = getattr(c, "name", "") or ""
            if "oai-client-auth-session" not in name:
                continue

            raw_val = (getattr(c, "value", "") or "").strip()
            if not raw_val:
                continue

            candidates = [raw_val]
            try:
                from urllib.parse import unquote

                decoded = unquote(raw_val)
                if decoded != raw_val:
                    candidates.append(decoded)
            except Exception:
                pass

            for val in candidates:
                try:
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]

                    part = val.split(".")[0] if "." in val else val
                    pad = 4 - len(part) % 4
                    if pad != 4:
                        part += "=" * pad
                    raw = base64.urlsafe_b64decode(part)
                    data = json.loads(raw.decode("utf-8"))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    continue
        return None

    def _oauth_allow_redirect_extract_code(self, url: str, referer: str = None):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }
        if referer:
            headers["Referer"] = referer

        try:
            resp = self.session.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=30,
                impersonate=self.impersonate,
            )
            final_url = str(resp.url)
            code = _extract_code_from_url(final_url)
            if code:
                self._print("[OAuth] allow_redirect 命中最终 URL code")
                return code

            for r in getattr(resp, "history", []) or []:
                loc = r.headers.get("Location", "")
                code = _extract_code_from_url(loc)
                if code:
                    self._print("[OAuth] allow_redirect 命中 history Location code")
                    return code
                code = _extract_code_from_url(str(r.url))
                if code:
                    self._print("[OAuth] allow_redirect 命中 history URL code")
                    return code
        except Exception as e:
            maybe_localhost = re.search(r'(https?://localhost[^\s\'\"]+)', str(e))
            if maybe_localhost:
                code = _extract_code_from_url(maybe_localhost.group(1))
                if code:
                    self._print("[OAuth] allow_redirect 从 localhost 异常提取 code")
                    return code
            self._print(f"[OAuth] allow_redirect 异常: {e}")

        return None

    def _oauth_follow_for_code(self, start_url: str, referer: str = None, max_hops: int = 16):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.ua,
        }
        if referer:
            headers["Referer"] = referer

        current_url = start_url
        last_url = start_url

        for hop in range(max_hops):
            try:
                resp = self.session.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=30,
                    impersonate=self.impersonate,
                )
            except Exception as e:
                maybe_localhost = re.search(r'(https?://localhost[^\s\'\"]+)', str(e))
                if maybe_localhost:
                    code = _extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        self._print(f"[OAuth] follow[{hop + 1}] 命中 localhost 回调")
                        return code, maybe_localhost.group(1)
                self._print(f"[OAuth] follow[{hop + 1}] 请求异常: {e}")
                return None, last_url

            last_url = str(resp.url)
            self._print(f"[OAuth] follow[{hop + 1}] {resp.status_code} {last_url[:140]}")
            code = _extract_code_from_url(last_url)
            if code:
                return code, last_url

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if not loc:
                    return None, last_url
                if loc.startswith("/"):
                    loc = f"{OAUTH_ISSUER}{loc}"
                code = _extract_code_from_url(loc)
                if code:
                    return code, loc
                current_url = loc
                headers["Referer"] = last_url
                continue

            return None, last_url

        return None, last_url

    def _oauth_submit_workspace_and_org(self, consent_url: str):
        session_data = self._decode_oauth_session_cookie()
        if not session_data:
            jar = getattr(self.session.cookies, "jar", None)
            if jar is not None:
                cookie_names = [getattr(c, "name", "") for c in list(jar)]
            else:
                cookie_names = list(self.session.cookies.keys())
            self._print(f"[OAuth] 无法解码 oai-client-auth-session, cookies={cookie_names[:12]}")
            return None

        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            self._print("[OAuth] session 中没有 workspace 信息")
            return None

        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            self._print("[OAuth] workspace_id 为空")
            return None

        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": OAUTH_ISSUER,
            "Referer": consent_url,
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        h.update(_make_trace_headers())

        resp = self.session.post(
            f"{OAUTH_ISSUER}/api/accounts/workspace/select",
            json={"workspace_id": workspace_id},
            headers=h,
            allow_redirects=False,
            timeout=30,
            impersonate=self.impersonate,
        )
        self._print(f"[OAuth] workspace/select -> {resp.status_code}")

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if loc.startswith("/"):
                loc = f"{OAUTH_ISSUER}{loc}"
            code = _extract_code_from_url(loc)
            if code:
                return code
            code, _ = self._oauth_follow_for_code(loc, referer=consent_url)
            if not code:
                code = self._oauth_allow_redirect_extract_code(loc, referer=consent_url)
            return code

        if resp.status_code != 200:
            self._print(f"[OAuth] workspace/select 失败: {resp.status_code}")
            return None

        try:
            ws_data = resp.json()
        except Exception:
            self._print("[OAuth] workspace/select 响应不是 JSON")
            return None

        ws_next = ws_data.get("continue_url", "")
        orgs = ws_data.get("data", {}).get("orgs", [])
        ws_page = (ws_data.get("page") or {}).get("type", "")
        self._print(f"[OAuth] workspace/select page={ws_page or '-'} next={(ws_next or '-')[:140]}")

        org_id = None
        project_id = None
        if orgs:
            org_id = (orgs[0] or {}).get("id")
            projects = (orgs[0] or {}).get("projects", [])
            if projects:
                project_id = (projects[0] or {}).get("id")

        if org_id:
            org_body = {"org_id": org_id}
            if project_id:
                org_body["project_id"] = project_id

            h_org = dict(h)
            if ws_next:
                h_org["Referer"] = ws_next if ws_next.startswith("http") else f"{OAUTH_ISSUER}{ws_next}"

            resp_org = self.session.post(
                f"{OAUTH_ISSUER}/api/accounts/organization/select",
                json=org_body,
                headers=h_org,
                allow_redirects=False,
                timeout=30,
                impersonate=self.impersonate,
            )
            self._print(f"[OAuth] organization/select -> {resp_org.status_code}")
            if resp_org.status_code in (301, 302, 303, 307, 308):
                loc = resp_org.headers.get("Location", "")
                if loc.startswith("/"):
                    loc = f"{OAUTH_ISSUER}{loc}"
                code = _extract_code_from_url(loc)
                if code:
                    return code
                code, _ = self._oauth_follow_for_code(loc, referer=h_org.get("Referer"))
                if not code:
                    code = self._oauth_allow_redirect_extract_code(loc, referer=h_org.get("Referer"))
                return code

            if resp_org.status_code == 200:
                try:
                    org_data = resp_org.json()
                except Exception:
                    self._print("[OAuth] organization/select 响应不是 JSON")
                    return None

                org_next = org_data.get("continue_url", "")
                org_page = (org_data.get("page") or {}).get("type", "")
                self._print(f"[OAuth] organization/select page={org_page or '-'} next={(org_next or '-')[:140]}")
                if org_next:
                    if org_next.startswith("/"):
                        org_next = f"{OAUTH_ISSUER}{org_next}"
                    code, _ = self._oauth_follow_for_code(org_next, referer=h_org.get("Referer"))
                    if not code:
                        code = self._oauth_allow_redirect_extract_code(org_next, referer=h_org.get("Referer"))
                    return code

        if ws_next:
            if ws_next.startswith("/"):
                ws_next = f"{OAUTH_ISSUER}{ws_next}"
            code, _ = self._oauth_follow_for_code(ws_next, referer=consent_url)
            if not code:
                code = self._oauth_allow_redirect_extract_code(ws_next, referer=consent_url)
            return code

        return None

    def perform_codex_oauth_login_http(self, email: str, password: str, mail_token: str = None):
        self._print("[OAuth] 开始执行 Codex OAuth 纯协议流程...")

        # 兼容两种 domain 形式，确保 auth 域也带 oai-did
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(24)

        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        authorize_url = f"{OAUTH_ISSUER}/oauth/authorize?{urlencode(authorize_params)}"

        def _oauth_json_headers(referer: str):
            h = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": OAUTH_ISSUER,
                "Referer": referer,
                "User-Agent": self.ua,
                "oai-device-id": self.device_id,
            }
            h.update(_make_trace_headers())
            return h

        def _bootstrap_oauth_session():
            self._print("[OAuth] 1/7 GET /oauth/authorize")
            try:
                r = self.session.get(
                    authorize_url,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": f"{self.BASE}/",
                        "Upgrade-Insecure-Requests": "1",
                        "User-Agent": self.ua,
                    },
                    allow_redirects=True,
                    timeout=30,
                    impersonate=self.impersonate,
                )
            except Exception as e:
                self._print(f"[OAuth] /oauth/authorize 异常: {e}")
                return False, ""

            final_url = str(r.url)
            redirects = len(getattr(r, "history", []) or [])
            self._print(f"[OAuth] /oauth/authorize -> {r.status_code}, final={(final_url or '-')[:140]}, redirects={redirects}")

            has_login = any(getattr(c, "name", "") == "login_session" for c in self.session.cookies)
            self._print(f"[OAuth] login_session: {'已获取' if has_login else '未获取'}")

            if not has_login:
                self._print("[OAuth] 未拿到 login_session，尝试访问 oauth2 auth 入口")
                oauth2_url = f"{OAUTH_ISSUER}/api/oauth/oauth2/auth"
                try:
                    r2 = self.session.get(
                        oauth2_url,
                        headers={
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Referer": authorize_url,
                            "Upgrade-Insecure-Requests": "1",
                            "User-Agent": self.ua,
                        },
                        params=authorize_params,
                        allow_redirects=True,
                        timeout=30,
                        impersonate=self.impersonate,
                    )
                    final_url = str(r2.url)
                    redirects2 = len(getattr(r2, "history", []) or [])
                    self._print(f"[OAuth] /api/oauth/oauth2/auth -> {r2.status_code}, final={(final_url or '-')[:140]}, redirects={redirects2}")
                except Exception as e:
                    self._print(f"[OAuth] /api/oauth/oauth2/auth 异常: {e}")

                has_login = any(getattr(c, "name", "") == "login_session" for c in self.session.cookies)
                self._print(f"[OAuth] login_session(重试): {'已获取' if has_login else '未获取'}")

            return has_login, final_url

        def _post_authorize_continue(referer_url: str):
            sentinel_authorize = build_sentinel_token(
                self.session,
                self.device_id,
                flow="authorize_continue",
                user_agent=self.ua,
                sec_ch_ua=self.sec_ch_ua,
                impersonate=self.impersonate,
            )
            if not sentinel_authorize:
                self._print("[OAuth] authorize_continue 的 sentinel token 获取失败")
                return None

            headers_continue = _oauth_json_headers(referer_url)
            headers_continue["openai-sentinel-token"] = sentinel_authorize

            try:
                return self.session.post(
                    f"{OAUTH_ISSUER}/api/accounts/authorize/continue",
                    json={"username": {"kind": "email", "value": email}},
                    headers=headers_continue,
                    timeout=30,
                    allow_redirects=False,
                    impersonate=self.impersonate,
                )
            except Exception as e:
                self._print(f"[OAuth] authorize/continue 异常: {e}")
                return None

        has_login_session, authorize_final_url = _bootstrap_oauth_session()
        if not authorize_final_url:
            return None

        continue_referer = authorize_final_url if authorize_final_url.startswith(OAUTH_ISSUER) else f"{OAUTH_ISSUER}/log-in"

        self._print("[OAuth] 2/7 POST /api/accounts/authorize/continue")
        resp_continue = _post_authorize_continue(continue_referer)
        if resp_continue is None:
            return None

        self._print(f"[OAuth] /authorize/continue -> {resp_continue.status_code}")
        if resp_continue.status_code == 400 and "invalid_auth_step" in (resp_continue.text or ""):
            self._print("[OAuth] invalid_auth_step，重新 bootstrap 后重试一次")
            has_login_session, authorize_final_url = _bootstrap_oauth_session()
            if not authorize_final_url:
                return None
            continue_referer = authorize_final_url if authorize_final_url.startswith(OAUTH_ISSUER) else f"{OAUTH_ISSUER}/log-in"
            resp_continue = _post_authorize_continue(continue_referer)
            if resp_continue is None:
                return None
            self._print(f"[OAuth] /authorize/continue(重试) -> {resp_continue.status_code}")

        if resp_continue.status_code != 200:
            self._print(f"[OAuth] 邮箱提交失败: {resp_continue.text[:180]}")
            return None

        try:
            continue_data = resp_continue.json()
        except Exception:
            self._print("[OAuth] authorize/continue 响应解析失败")
            return None

        continue_url = continue_data.get("continue_url", "")
        page_type = (continue_data.get("page") or {}).get("type", "")
        self._print(f"[OAuth] continue page={page_type or '-'} next={(continue_url or '-')[:140]}")

        self._print("[OAuth] 3/7 POST /api/accounts/password/verify")
        sentinel_pwd = build_sentinel_token(
            self.session,
            self.device_id,
            flow="password_verify",
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate,
        )
        if not sentinel_pwd:
            self._print("[OAuth] password_verify 的 sentinel token 获取失败")
            return None

        headers_verify = _oauth_json_headers(f"{OAUTH_ISSUER}/log-in/password")
        headers_verify["openai-sentinel-token"] = sentinel_pwd

        try:
            resp_verify = self.session.post(
                f"{OAUTH_ISSUER}/api/accounts/password/verify",
                json={"password": password},
                headers=headers_verify,
                timeout=30,
                allow_redirects=False,
                impersonate=self.impersonate,
            )
        except Exception as e:
            self._print(f"[OAuth] password/verify 异常: {e}")
            return None

        self._print(f"[OAuth] /password/verify -> {resp_verify.status_code}")
        if resp_verify.status_code != 200:
            self._print(f"[OAuth] 密码校验失败: {resp_verify.text[:180]}")
            return None

        try:
            verify_data = resp_verify.json()
        except Exception:
            self._print("[OAuth] password/verify 响应解析失败")
            return None

        continue_url = verify_data.get("continue_url", "") or continue_url
        page_type = (verify_data.get("page") or {}).get("type", "") or page_type
        self._print(f"[OAuth] verify page={page_type or '-'} next={(continue_url or '-')[:140]}")

        need_oauth_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in (continue_url or "")
            or "email-otp" in (continue_url or "")
        )

        if need_oauth_otp:
            self._print("[OAuth] 4/7 检测到邮箱 OTP 验证")
            if not mail_token:
                self._print("[OAuth] OAuth 阶段需要邮箱 OTP，但未提供 mail_token")
                return None

            headers_otp = _oauth_json_headers(f"{OAUTH_ISSUER}/email-verification")
            tried_codes = set()
            otp_success = False
            otp_deadline = time.time() + 120

            while time.time() < otp_deadline and not otp_success:
                messages = self._fetch_emails_yydsmail(mail_token) or []
                candidate_codes = []

                for msg in messages[:12]:
                    msg_id = msg.get("id")
                    if not msg_id:
                        continue
                    detail = self._fetch_email_detail_yydsmail(mail_token, msg_id)
                    if not detail:
                        continue
                    content = detail.get("text") or detail.get("html") or ""
                    code = self._extract_verification_code(content)
                    if code and code not in tried_codes:
                        candidate_codes.append(code)

                if not candidate_codes:
                    elapsed = int(120 - max(0, otp_deadline - time.time()))
                    self._print(f"[OAuth] OTP 等待中... ({elapsed}s/120s)")
                    time.sleep(2)
                    continue

                for otp_code in candidate_codes:
                    tried_codes.add(otp_code)
                    self._print(f"[OAuth] 尝试 OTP: {otp_code}")
                    try:
                        resp_otp = self.session.post(
                            f"{OAUTH_ISSUER}/api/accounts/email-otp/validate",
                            json={"code": otp_code},
                            headers=headers_otp,
                            timeout=30,
                            allow_redirects=False,
                            impersonate=self.impersonate,
                        )
                    except Exception as e:
                        self._print(f"[OAuth] email-otp/validate 异常: {e}")
                        continue

                    self._print(f"[OAuth] /email-otp/validate -> {resp_otp.status_code}")
                    if resp_otp.status_code != 200:
                        self._print(f"[OAuth] OTP 无效，继续尝试下一条: {resp_otp.text[:160]}")
                        continue

                    try:
                        otp_data = resp_otp.json()
                    except Exception:
                        self._print("[OAuth] email-otp/validate 响应解析失败")
                        continue

                    continue_url = otp_data.get("continue_url", "") or continue_url
                    page_type = (otp_data.get("page") or {}).get("type", "") or page_type
                    self._print(f"[OAuth] OTP 验证通过 page={page_type or '-'} next={(continue_url or '-')[:140]}")
                    otp_success = True
                    break

                if not otp_success:
                    time.sleep(2)

            if not otp_success:
                self._print(f"[OAuth] OAuth 阶段 OTP 验证失败，已尝试 {len(tried_codes)} 个验证码")
                return None

        code = None
        consent_url = continue_url
        if consent_url and consent_url.startswith("/"):
            consent_url = f"{OAUTH_ISSUER}{consent_url}"

        if not consent_url and "consent" in page_type:
            consent_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"

        if consent_url:
            code = _extract_code_from_url(consent_url)

        if not code and consent_url:
            self._print("[OAuth] 5/7 跟随 continue_url 提取 code")
            code, _ = self._oauth_follow_for_code(consent_url, referer=f"{OAUTH_ISSUER}/log-in/password")

        consent_hint = (
            ("consent" in (consent_url or ""))
            or ("sign-in-with-chatgpt" in (consent_url or ""))
            or ("workspace" in (consent_url or ""))
            or ("organization" in (consent_url or ""))
            or ("consent" in page_type)
            or ("organization" in page_type)
        )

        if not code and consent_hint:
            if not consent_url:
                consent_url = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._print("[OAuth] 6/7 执行 workspace/org 选择")
            code = self._oauth_submit_workspace_and_org(consent_url)

        if not code:
            fallback_consent = f"{OAUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._print("[OAuth] 6/7 回退 consent 路径重试")
            code = self._oauth_submit_workspace_and_org(fallback_consent)
            if not code:
                code, _ = self._oauth_follow_for_code(fallback_consent, referer=f"{OAUTH_ISSUER}/log-in/password")

        if not code:
            self._print("[OAuth] 未获取到 authorization code")
            return None

        self._print("[OAuth] 7/7 POST /oauth/token")
        token_resp = self.session.post(
            f"{OAUTH_ISSUER}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": self.ua},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OAUTH_REDIRECT_URI,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": code_verifier,
            },
            timeout=60,
            impersonate=self.impersonate,
        )
        self._print(f"[OAuth] /oauth/token -> {token_resp.status_code}")

        if token_resp.status_code != 200:
            self._print(f"[OAuth] token 交换失败: {token_resp.status_code} {token_resp.text[:200]}")
            return None

        try:
            data = token_resp.json()
        except Exception:
            self._print("[OAuth] token 响应解析失败")
            return None

        if not data.get("access_token"):
            self._print("[OAuth] token 响应缺少 access_token")
            return None

        self._print("[OAuth] Codex Token 获取成功")
        return data


# ==================== 并发批量注册 ====================

def _register_one(idx, total, proxy, output_file):
    """单个注册任务 (在线程中运行) - 使用 YYDS Mail 临时邮箱"""
    reg = None
    try:
        reg = ChatGPTRegister(proxy=proxy, tag=f"{idx}")

        # 1. 创建 YYDS Mail 临时邮箱
        reg._print("[YYDSMail] 创建临时邮箱...")
        email, mail_token = reg.create_temp_email()
        tag = email.split("@")[0]
        reg.tag = tag  # 更新 tag

        chatgpt_password = _generate_password()
        name = _random_name()
        birthdate = _random_birthdate()

        with _print_lock:
            print(f"\n{'='*60}")
            print(f"  [{idx}/{total}] 注册: {email}")
            print(f"  ChatGPT密码: {chatgpt_password}")
            print(f"  姓名: {name} | 生日: {birthdate}")
            print(f"{'='*60}")

        # 2. 执行注册流程
        reg.run_register(email, chatgpt_password, name, birthdate, mail_token)

        # 3. OAuth（可选）
        oauth_ok = True
        if ENABLE_OAUTH:
            reg._print("[OAuth] 开始获取 Codex Token...")
            tokens = reg.perform_codex_oauth_login_http(email, chatgpt_password, mail_token=mail_token)
            oauth_ok = bool(tokens and tokens.get("access_token"))
            if oauth_ok:
                _save_codex_tokens(email, tokens)
                reg._print("[OAuth] Token 已保存")
            else:
                msg = "OAuth 获取失败"
                if OAUTH_REQUIRED:
                    raise Exception(f"{msg}（oauth_required=true）")
                reg._print(f"[OAuth] {msg}（按配置继续）")

        # 4. 线程安全写入结果
        with _file_lock:
            with open(output_file, "a", encoding="utf-8") as out:
                out.write(f"{email}----{chatgpt_password}----oauth={'ok' if oauth_ok else 'fail'}\n")

        with _print_lock:
            print(f"\n[OK] [{tag}] {email} 注册成功!")
        return True, email, None

    except Exception as e:
        error_msg = str(e)
        with _print_lock:
            print(f"\n[FAIL] [{idx}] 注册失败: {error_msg}")
            traceback.print_exc()
        return False, None, error_msg


def run_batch(total_accounts: int = 3, output_file="registered_accounts.txt",
              max_workers=3, proxy=None, cpa_cleanup=None):
    """并发批量注册 - YYDS Mail 临时邮箱版"""

    if not YYDSMAIL_API_KEY:
        print("❌ 错误: 未设置 YYDSMAIL_API_KEY")
        print("   请设置: export YYDSMAIL_API_KEY='AC-your_api_key_here'")
        print("   或在 config.json 中设置 yydsmail_api_key")
        return

    actual_workers = min(max_workers, total_accounts)
    print(f"\n{'#'*60}")
    print(f"  ChatGPT 批量自动注册 (YYDS Mail 临时邮箱版)")
    print(f"  注册数量: {total_accounts} | 并发数: {actual_workers}")
    print(f"  YYDS Mail: {YYDSMAIL_API_BASE}")
    print(f"  OAuth: {'开启' if ENABLE_OAUTH else '关闭'} | required: {'是' if OAUTH_REQUIRED else '否'}")
    if ENABLE_OAUTH:
        print(f"  OAuth Issuer: {OAUTH_ISSUER}")
        print(f"  OAuth Client: {OAUTH_CLIENT_ID}")
        print(f"  Token输出: {TOKEN_JSON_DIR}/, {AK_FILE}, {RK_FILE}")
    print(f"  输出文件: {output_file}")
    print(f"{'#'*60}\n")

    # 注册前清理 CPA 无效号
    do_cleanup = cpa_cleanup if cpa_cleanup is not None else CPA_CLEANUP_ENABLED
    if do_cleanup and UPLOAD_API_URL:
        _run_cpa_cleanup_before_register()

    success_count = 0
    fail_count = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        futures = {}
        for idx in range(1, total_accounts + 1):
            future = executor.submit(
                _register_one, idx, total_accounts, proxy, output_file
            )
            futures[future] = idx

        for future in as_completed(futures):
            idx = futures[future]
            try:
                ok, email, err = future.result()
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    print(f"  [账号 {idx}] 失败: {err}")
            except Exception as e:
                fail_count += 1
                with _print_lock:
                    print(f"[FAIL] 账号 {idx} 线程异常: {e}")

    elapsed = time.time() - start_time
    avg = elapsed / total_accounts if total_accounts else 0
    print(f"\n{'#'*60}")
    print(f"  注册完成! 耗时 {elapsed:.1f} 秒")
    print(f"  总数: {total_accounts} | 成功: {success_count} | 失败: {fail_count}")
    print(f"  平均速度: {avg:.1f} 秒/个")
    if success_count > 0:
        print(f"  结果文件: {output_file}")
    print(f"{'#'*60}")

    # 注册流程结束后，自动上传到 CPA 并清理
    if success_count > 0:
        _upload_all_tokens_to_cpa()


def main():
    print("=" * 60)
    print("  ChatGPT 批量自动注册工具 (YYDS Mail 临时邮箱版)")
    print("=" * 60)

    # 检查 YYDS Mail 配置
    if not YYDSMAIL_API_KEY:
        print("\n⚠️  警告: 未设置 YYDSMAIL_API_KEY")
        print("   请编辑 config.json 设置 yydsmail_api_key，或设置环境变量:")
        print("   Windows: set YYDSMAIL_API_KEY=AC-your_api_key_here")
        print("   Linux/Mac: export YYDSMAIL_API_KEY='AC-your_api_key_here'")
        print("\n   按 Enter 继续尝试运行 (可能会失败)...")
        input()

    # 交互式代理配置
    proxy = DEFAULT_PROXY
    if proxy:
        print(f"[Info] 检测到默认代理: {proxy}")
        use_default = input("使用此代理? (Y/n): ").strip().lower()
        if use_default == "n":
            proxy = input("输入代理地址 (留空=不使用代理): ").strip() or None
    else:
        env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
                 or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
        if env_proxy:
            print(f"[Info] 检测到环境变量代理: {env_proxy}")
            use_env = input("使用此代理? (Y/n): ").strip().lower()
            if use_env == "n":
                proxy = input("输入代理地址 (留空=不使用代理): ").strip() or None
            else:
                proxy = env_proxy
        else:
            proxy = input("输入代理地址 (如 http://127.0.0.1:7890，留空=不使用代理): ").strip() or None

    if proxy:
        print(f"[Info] 使用代理: {proxy}")
    else:
        print("[Info] 不使用代理")

    # 注册前是否清理 CPA 无效号
    cpa_cleanup = True
    if UPLOAD_API_URL:
        cleanup_input = input("\n注册前清理 CPA 无效号? (Y/n): ").strip().lower()
        cpa_cleanup = cleanup_input != "n"
    else:
        cpa_cleanup = False

    # 输入注册数量
    count_input = input(f"\n注册账号数量 (默认 {DEFAULT_TOTAL_ACCOUNTS}): ").strip()
    total_accounts = int(count_input) if count_input.isdigit() and int(count_input) > 0 else DEFAULT_TOTAL_ACCOUNTS

    workers_input = input("并发数 (默认 3): ").strip()
    max_workers = int(workers_input) if workers_input.isdigit() and int(workers_input) > 0 else 3

    run_batch(total_accounts=total_accounts, output_file=DEFAULT_OUTPUT_FILE,
              max_workers=max_workers, proxy=proxy, cpa_cleanup=cpa_cleanup)


if __name__ == "__main__":
    main()
