import base64
import json
import logging
import os
import threading
import tempfile
import time
import unittest
from unittest.mock import patch

import auto_pool_maintainer as apm


class DummyResponse:
    def __init__(self, status_code: int, *, text: str = "", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload if payload is not None else {}
        self.headers = {}
        self.url = "https://auth.openai.com/email-verification"

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def build_test_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).rstrip(b"=").decode("ascii")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{header}.{body}.signature"


class FlowHelperTests(unittest.TestCase):
    def test_request_with_local_retry_writes_flow_trace_log_with_redaction(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = os.path.join(tmp_dir, "flow-trace.jsonl")
            recorder = apm.FlowTraceRecorder(trace_path, reveal_sensitive=False, body_limit=512)

            class FakeSession:
                def __init__(self):
                    self.cookies = []

                def post(self, url, **kwargs):
                    response = DummyResponse(429, text='{"error":"rate_limit"}')
                    response.url = url
                    response.headers = {
                        "content-type": "application/json",
                        "set-cookie": "session=secret-cookie",
                    }
                    return response

            response, reason = apm.request_with_local_retry(
                FakeSession(),  # type: ignore[arg-type]
                "post",
                "https://auth.openai.com/api/accounts/authorize/continue",
                retry_attempts=1,
                error_prefix="authorize_continue_request",
                flow_trace=recorder,
                headers={
                    "Authorization": "Bearer super-secret-token",
                    "Cookie": "session=plain-cookie",
                    "x-test": "ok",
                },
                json={"password": "PlainPassword123", "username": "trace@example.com"},
                timeout=30,
                verify=False,
            )

            self.assertEqual(reason, "")
            self.assertIsNotNone(response)

            with open(trace_path, "r", encoding="utf-8") as trace_file:
                events = [json.loads(line) for line in trace_file if line.strip()]

            event_names = [event["event"] for event in events]
            self.assertIn("http_attempt", event_names)
            self.assertIn("http_response", event_names)

            attempt_event = next(event for event in events if event["event"] == "http_attempt")
            response_event = next(event for event in events if event["event"] == "http_response")

            self.assertEqual(attempt_event["request"]["url"], "https://auth.openai.com/api/accounts/authorize/continue")
            self.assertEqual(response_event["response"]["status_code"], 429)
            serialized = json.dumps(events, ensure_ascii=False)
            self.assertNotIn("PlainPassword123", serialized)
            self.assertNotIn("super-secret-token", serialized)
            self.assertNotIn("plain-cookie", serialized)

    def test_build_chatgpt_session_token_result_uses_callback_code(self):
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if url == "https://chatgpt.com/api/auth/callback/openai?code=oauth-code":
                    return DummyResponse(200)
                if url == "https://chatgpt.com/api/auth/session":
                    return DummyResponse(200, payload={"accessToken": access_token, "user": {"email": "jwt@example.com"}})
                raise AssertionError(f"unexpected url: {url}")

        session = FakeSession()

        result = apm.build_chatgpt_session_token_result(
            session=session,  # type: ignore[arg-type]
            auth_code="oauth-code",
            chatgpt_base="https://chatgpt.com",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["access_token"], access_token)
        self.assertEqual(result["email"], "jwt@example.com")
        self.assertEqual(result["account_id"], "acct_123")
        self.assertEqual(result["exp"], 1760000000)
        self.assertEqual(
            [call[0] for call in session.calls],
            [
                "https://chatgpt.com/api/auth/callback/openai?code=oauth-code",
                "https://chatgpt.com/api/auth/session",
            ],
        )

    def test_build_chatgpt_session_token_result_preserves_callback_query_params(self):
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if (
                    url
                    == "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ):
                    return DummyResponse(200)
                if url == "https://chatgpt.com/api/auth/session":
                    return DummyResponse(200, payload={"accessToken": access_token, "user": {"email": "jwt@example.com"}})
                raise AssertionError(f"unexpected url: {url}")

        session = FakeSession()

        result = apm.build_chatgpt_session_token_result(
            session=session,  # type: ignore[arg-type]
            auth_code="oauth-code",
            callback_params={
                "code": "oauth-code",
                "scope": "openid email profile offline_access",
                "state": "oauth-state",
            },
            chatgpt_base="https://chatgpt.com",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["access_token"], access_token)
        self.assertEqual(
            [call[0] for call in session.calls],
            [
                "https://chatgpt.com/api/auth/callback/openai?code=oauth-code&scope=openid+email+profile+offline_access&state=oauth-state",
                "https://chatgpt.com/api/auth/session",
            ],
        )

    def test_build_chatgpt_session_token_result_finds_nested_jwt(self):
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if url == "https://chatgpt.com/api/auth/session":
                    return DummyResponse(
                        200,
                        payload={
                            "user": {"email": "jwt@example.com"},
                            "session": {"tokens": [{"kind": "bearer", "value": access_token}]},
                        },
                    )
                raise AssertionError(f"unexpected url: {url}")

        session = FakeSession()

        result = apm.build_chatgpt_session_token_result(
            session=session,  # type: ignore[arg-type]
            auth_code="",
            chatgpt_base="https://chatgpt.com",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["access_token"], access_token)
        self.assertEqual(result["email"], "jwt@example.com")

    def test_is_transient_flow_error(self):
        self.assertTrue(apm.is_transient_flow_error("oauth_step_http_503"))
        self.assertTrue(apm.is_transient_flow_error("authorize_exception:timed out"))
        self.assertFalse(apm.is_transient_flow_error("email_otp_validate_http_400"))

    def test_parse_otp_validate_order(self):
        self.assertEqual(apm.parse_otp_validate_order("normal,sentinel"), ("normal", "sentinel"))
        self.assertEqual(apm.parse_otp_validate_order("sentinel,normal"), ("sentinel", "normal"))
        self.assertEqual(apm.parse_otp_validate_order("invalid"), ("normal", "sentinel"))

    def test_requires_phone_verification(self):
        payload = {
            "page": {"type": "phone_verification"},
            "continue_url": "/add-phone",
        }
        self.assertTrue(apm.requires_phone_verification(payload, ""))
        self.assertFalse(apm.requires_phone_verification({"page": {"type": "email_otp_verification"}}, ""))

    def test_resolve_loop_interval_seconds(self):
        self.assertEqual(apm.resolve_loop_interval_seconds({}, None), 60.0)
        self.assertEqual(apm.resolve_loop_interval_seconds({"maintainer": {"loop_interval_seconds": 12}}, None), 12.0)
        self.assertEqual(apm.resolve_loop_interval_seconds({"maintainer": {"loop_interval_seconds": 1}}, None), 5.0)
        self.assertEqual(apm.resolve_loop_interval_seconds({}, 8.5), 8.5)

    def test_parse_loop_next_check_in_seconds_from_log_line(self):
        line = "2026-03-27 21:33:42 | INFO | 循环模式休眠 60.0s 后再次检查号池"
        with patch("api_server.time.time", return_value=apm.dt.datetime(2026, 3, 27, 21, 34, 0).timestamp()):
            import api_server as aps

            remain = aps.parse_loop_next_check_in_seconds([line])
        self.assertEqual(remain, 42)

    def test_api_server_run_state_read_write_and_clear(self):
        import api_server as aps

        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_state = aps.Path(tmp_dir) / "run_state.json"
            with patch.object(aps, "RUN_STATE_FILE", fake_state):
                aps.save_run_state(12345, "loop")
                state = aps.load_run_state()
                self.assertEqual(state.get("pid"), 12345)
                self.assertEqual(state.get("mode"), "loop")
                aps.clear_run_state()
                self.assertFalse(fake_state.exists())

    def test_api_server_is_pid_running_current_process(self):
        import api_server as aps

        self.assertTrue(aps.is_pid_running(os.getpid()))
        self.assertFalse(aps.is_pid_running(99999999))

    def test_analyze_usage_status_marks_quota_and_threshold(self):
        body = {
            "rate_limit": {
                "allowed": True,
                "limit_reached": False,
                "primary_window": {"used_percent": 85},
                "secondary_window": {"used_percent": 99},
            }
        }
        usage = apm.analyze_usage_status(status_code=200, body_obj=body, body_text="", used_percent_threshold=80)
        self.assertEqual(usage["used_percent"], 99.0)
        self.assertTrue(usage["over_threshold"])
        self.assertTrue(usage["is_quota"])
        self.assertFalse(usage["is_healthy"])

    def test_analyze_usage_status_marks_healthy(self):
        body = {
            "rate_limit": {
                "allowed": True,
                "limit_reached": False,
                "primary_window": {"used_percent": 35},
            }
        }
        usage = apm.analyze_usage_status(status_code=200, body_obj=body, body_text="", used_percent_threshold=80)
        self.assertEqual(usage["used_percent"], 35.0)
        self.assertFalse(usage["over_threshold"])
        self.assertFalse(usage["is_quota"])
        self.assertTrue(usage["is_healthy"])

    def test_decide_clean_action(self):
        self.assertEqual(apm.decide_clean_action(status_code=401, disabled=False, is_quota=False, over_threshold=False), "delete")
        self.assertEqual(apm.decide_clean_action(status_code=200, disabled=False, is_quota=True, over_threshold=False), "disable")
        self.assertEqual(apm.decide_clean_action(status_code=200, disabled=True, is_quota=False, over_threshold=False), "enable")
        self.assertEqual(apm.decide_clean_action(status_code=None, disabled=False, is_quota=False, over_threshold=False), "keep")

    def test_get_candidates_count_excludes_disabled_items(self):
        files = [
            {"type": "codex", "disabled": False},
            {"type": "codex", "disabled": True},
            {"type": "codex", "disabled": "false"},
            {"type": "codex", "status": "disabled"},
            {"type": "claude", "disabled": False},
        ]
        total, candidates = apm.get_candidates_count_from_files(files, "codex")
        self.assertEqual(total, 5)
        self.assertEqual(candidates, 2)

    def test_select_probe_candidates_returns_all_when_sample_size_disabled(self):
        candidates = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        selected = apm.select_probe_candidates(candidates, sample_size=0, rng=apm.random.Random(1))
        self.assertEqual([item["name"] for item in selected], ["a", "b", "c"])

    def test_select_probe_candidates_returns_random_subset(self):
        candidates = [{"name": "a"}, {"name": "b"}, {"name": "c"}, {"name": "d"}, {"name": "e"}]
        selected = apm.select_probe_candidates(candidates, sample_size=2, rng=apm.random.Random(7))
        self.assertEqual([item["name"] for item in selected], ["c", "b"])

    def test_run_clean_401_passes_sample_size_to_async_cleanup(self):
        conf = {
            "clean": {
                "base_url": "https://example.test",
                "token": "pw",
                "sample_size": 3,
            }
        }
        captured = {}

        async def fake_run_clean_401_async(**kwargs):
            captured.update(kwargs)
            return {"action_total": 0}

        with patch.object(apm, "aiohttp", object()), patch.object(apm, "run_clean_401_async", fake_run_clean_401_async):
            result = apm.run_clean_401(conf, logging.getLogger("test-clean-sample"))

        self.assertEqual(captured["sample_size"], 3)
        self.assertEqual(result["action_total"], 0)

    def test_mail_provider_session_reuses_same_thread_and_isolates_cross_thread(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-mail-session"),
            api_base="https://example.test",
            api_key="k",
            domain="x.test",
        )
        main_session_first = provider._session()
        main_session_second = provider._session()
        self.assertIs(main_session_first, main_session_second)

        holder = {}

        def worker() -> None:
            holder["thread_session_first"] = provider._session()
            holder["thread_session_second"] = provider._session()

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=3)
        self.assertIn("thread_session_first", holder)
        self.assertIs(holder["thread_session_first"], holder["thread_session_second"])
        self.assertIsNot(main_session_first, holder["thread_session_first"])

    def test_self_hosted_mail_domain_normalization_removes_leading_dot(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-domain"),
            api_base="https://example.test",
            api_key="k",
            domain=".qzz.io",
        )
        mailbox = provider.create_mailbox()
        self.assertIsNotNone(mailbox)
        self.assertEqual(provider.domain, "qzz.io")
        self.assertNotIn("@.", mailbox.email if mailbox else "")

    def test_yyds_mail_domain_normalization_removes_leading_dot(self):
        provider = apm.YYDSMailProvider(
            proxy="",
            logger=logging.getLogger("test-yyds-domain"),
            api_base="https://example.test",
            api_key="k",
            domain=".qzz.io",
        )
        self.assertEqual(provider.domain, "qzz.io")

    def test_self_hosted_provider_accepts_code_without_openai_keywords(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-code"),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )
        provider._fetch_latest_email = lambda _email: {  # type: ignore[method-assign]
            "subject": "您的登录验证码",
            "text": "验证码：123456，请在页面输入",
        }
        codes = provider.poll_verification_codes(
            apm.Mailbox(email="u@qzz.io"),
            seen_ids=set(),
        )
        self.assertEqual(codes, ["123456"])

    def test_self_hosted_provider_logs_non_200_fetch_response(self):
        logger_name = "test-self-hosted-fetch-warning"
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger(logger_name),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )

        class FakeResponse:
            status_code = 401
            text = "无效的邮箱地址凭据"

            def json(self):
                return {}

        class FakeSession:
            @staticmethod
            def get(*args, **kwargs):
                return FakeResponse()

        provider._thread_local.session = FakeSession()
        with self.assertLogs(logger_name, level="WARNING") as captured:
            mail_obj = provider._fetch_latest_email("u@qzz.io")

        self.assertIsNone(mail_obj)
        self.assertTrue(any("401" in line and "无效的邮箱地址凭据" in line for line in captured.output))

    def test_yyds_provider_accepts_code_without_openai_keywords(self):
        provider = apm.YYDSMailProvider(
            proxy="",
            logger=logging.getLogger("test-yyds-code"),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )
        provider._fetch_messages = lambda _token: [{"id": "m-1"}]  # type: ignore[method-assign]
        provider._fetch_message_detail = lambda _token, _mid: {  # type: ignore[method-assign]
            "subject": "邮箱验证码",
            "text": "本次验证码 654321，5 分钟内有效",
        }
        codes = provider.poll_verification_codes(
            apm.Mailbox(email="u@qzz.io", token="tkn"),
            seen_ids=set(),
        )
        self.assertEqual(codes, ["654321"])

    def test_yyds_provider_accepts_code_from_inline_message_without_detail(self):
        provider = apm.YYDSMailProvider(
            proxy="",
            logger=logging.getLogger("test-yyds-inline-code"),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )
        provider._fetch_messages = lambda _token: [  # type: ignore[method-assign]
            {"id": "m-1", "subject": "邮箱验证码", "intro": "本次验证码 112233，5 分钟内有效"}
        ]
        provider._fetch_message_detail = lambda _token, _mid: None  # type: ignore[method-assign]
        codes = provider.poll_verification_codes(
            apm.Mailbox(email="u@qzz.io", token="tkn"),
            seen_ids=set(),
        )
        self.assertEqual(codes, ["112233"])

    def test_yyds_provider_normalizes_prefixed_message_id_for_detail_fetch(self):
        provider = apm.YYDSMailProvider(
            proxy="",
            logger=logging.getLogger("test-yyds-message-id"),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )
        provider._fetch_messages = lambda _token: [{"id": "/messages/m-1"}]  # type: ignore[method-assign]
        detail_call = {}

        def fake_fetch_detail(_token, message_id):
            detail_call["message_id"] = message_id
            return {
                "subject": "邮箱验证码",
                "text": "本次验证码 445566，5 分钟内有效",
            }

        provider._fetch_message_detail = fake_fetch_detail  # type: ignore[method-assign]
        codes = provider.poll_verification_codes(
            apm.Mailbox(email="u@qzz.io", token="tkn"),
            seen_ids=set(),
        )
        self.assertEqual(codes, ["445566"])
        self.assertEqual(detail_call.get("message_id"), "m-1")

    def test_yyds_provider_fetch_messages_reads_nested_messages_array(self):
        provider = apm.YYDSMailProvider(
            proxy="",
            logger=logging.getLogger("test-yyds-nested-messages"),
            api_base="https://example.test",
            api_key="k",
            domain="qzz.io",
        )

        class FakeResponse:
            status_code = 200
            content = b"1"

            @staticmethod
            def json():
                return {
                    "success": True,
                    "data": {
                        "messages": [
                            {"id": "m-1", "subject": "邮箱验证码", "createdAt": "2026-03-28T16:00:00Z"}
                        ]
                    },
                }

        class FakeSession:
            @staticmethod
            def get(*args, **kwargs):
                return FakeResponse()

        provider._thread_local.session = FakeSession()
        messages = provider._fetch_messages("tkn")
        self.assertEqual(messages, [{"id": "m-1", "subject": "邮箱验证码", "createdAt": "2026-03-28T16:00:00Z"}])

    def test_self_hosted_provider_prefers_domains_over_domain(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-domains-priority"),
            api_base="https://example.test",
            api_key="k",
            domain="fallback.test",
            domains=["a.test", "b.test"],
            failure_threshold=2,
            failure_cooldown_seconds=30.0,
        )

        self.assertEqual(provider.domains, ["a.test", "b.test"])
        mailbox = provider.create_mailbox()
        self.assertIsNotNone(mailbox)
        self.assertTrue((mailbox.email if mailbox else "").endswith("@a.test"))
        self.assertEqual(mailbox.domain if mailbox else "", "a.test")

    def test_self_hosted_provider_rotates_domains_in_order(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-rotate"),
            api_base="https://example.test",
            api_key="k",
            domain="fallback.test",
            domains=["a.test", "b.test", "c.test"],
            failure_threshold=2,
            failure_cooldown_seconds=30.0,
        )

        first = provider.create_mailbox()
        second = provider.create_mailbox()
        third = provider.create_mailbox()

        self.assertEqual([first.domain, second.domain, third.domain], ["a.test", "b.test", "c.test"])

    def test_self_hosted_provider_skips_domain_in_cooldown(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-cooldown"),
            api_base="https://example.test",
            api_key="k",
            domain="fallback.test",
            domains=["a.test", "b.test"],
            failure_threshold=2,
            failure_cooldown_seconds=60.0,
        )

        provider.note_domain_failure("a.test", stage="create_mailbox")
        provider.note_domain_failure("a.test", stage="create_mailbox")

        mailbox = provider.create_mailbox()
        self.assertIsNotNone(mailbox)
        self.assertEqual(mailbox.domain if mailbox else "", "b.test")

    def test_self_hosted_provider_reuses_domain_after_cooldown_expires(self):
        provider = apm.SelfHostedMailApiProvider(
            proxy="",
            logger=logging.getLogger("test-self-hosted-cooldown-expire"),
            api_base="https://example.test",
            api_key="k",
            domain="fallback.test",
            domains=["a.test", "b.test"],
            failure_threshold=1,
            failure_cooldown_seconds=5.0,
        )

        provider.note_domain_failure("a.test", stage="create_mailbox")
        provider.domain_cooldown_until["a.test"] = time.time() - 1

        mailbox = provider.create_mailbox()
        self.assertIsNotNone(mailbox)
        self.assertEqual(mailbox.domain if mailbox else "", "a.test")

    def test_cfmail_provider_create_mailbox_uses_next_available_domain(self):
        provider = apm.CfmailProvider(
            proxy="",
            logger=logging.getLogger("test-cfmail-provider"),
            api_base="https://mail.example.com",
            api_key="pw",
            domain="",
            domains=["a.test", "b.test"],
            failure_threshold=2,
            failure_cooldown_seconds=60.0,
        )

        provider._create_address_for_domain = lambda domain: apm.Mailbox(  # type: ignore[method-assign]
            email=f"oc123@{domain}",
            token="jwt",
            domain=domain,
            failure_target=domain,
        )

        first = provider.create_mailbox()
        second = provider.create_mailbox()

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual((first.domain, second.domain), ("a.test", "b.test"))

    def test_cfmail_provider_extracts_code_from_raw_and_metadata(self):
        provider = apm.CfmailProvider(
            proxy="",
            logger=logging.getLogger("test-cfmail-code"),
            api_base="https://mail.example.com",
            api_key="pw",
            domain="",
            domains=["a.test"],
            failure_threshold=2,
            failure_cooldown_seconds=60.0,
        )
        provider._fetch_cfmail_messages = lambda _mailbox: [  # type: ignore[method-assign]
            {
                "id": "m-1",
                "address": "oc123@a.test",
                "raw": "Subject: Your ChatGPT code is 123456",
                "metadata": {"provider": "openai"},
            }
        ]

        codes = provider.poll_verification_codes(
            apm.Mailbox(
                email="oc123@a.test",
                token="jwt",
                domain="a.test",
                failure_target="a.test",
            ),
            seen_ids=set(),
        )
        self.assertEqual(codes, ["123456"])

    def test_build_mail_provider_supports_cfmail(self):
        provider = apm.build_mail_provider(
            {
                "mail": {"provider": "cfmail"},
                "cfmail": {
                    "api_base": "https://mail.example.com",
                    "api_key": "pw",
                    "domains": ["a.test", "b.test"],
                },
            },
            proxy="",
            logger=logging.getLogger("test-build-cfmail"),
        )
        self.assertIsInstance(provider, apm.CfmailProvider)
        self.assertEqual(provider.domains, ["a.test", "b.test"])

    def test_api_server_merge_cfmail_api_key_preserves_masked_entries(self):
        import api_server as aps

        current = {
            "cfmail": {
                "api_base": "https://mail.example.com",
                "api_key": "secret-1",
                "domains": ["a.test"],
            }
        }
        incoming = {
            "cfmail": {
                "api_base": "https://mail.example.com",
                "api_key": aps.MASKED_VALUE,
                "domains": ["a.test"],
            }
        }

        merged = aps.merge_config_with_sensitive_fields(current, incoming)
        self.assertEqual(merged["cfmail"]["api_key"], "secret-1")

class ProtocolRegistrarTests(unittest.TestCase):
    def test_protocol_registrar_defaults_to_chatgpt_web_entry_mode(self):
        logger = logging.getLogger("test-registration-default-entry-mode")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={})

        self.assertEqual(registrar.entry_mode, "chatgpt_web")
        self.assertEqual(registrar._entry_mode_candidates(), ["chatgpt_web", "direct_auth"])

    def test_capture_registration_tokens_uses_consent_url_redirect_code(self):
        logger = logging.getLogger("test-registration-consent-code")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={"flow": {"step_retry_attempts": 1}})
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.cookies = []
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    response = DummyResponse(302)
                    response.headers = {
                        "Location": (
                            "http://localhost:1455/auth/callback"
                            "?code=oauth-consent-code"
                            "&scope=openid+email+profile+offline_access"
                            "&state=oauth-state"
                        )
                    }
                    response.url = url
                    return response
                if (
                    url
                    == "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-consent-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ):
                    response = DummyResponse(200)
                    response.url = url
                    return response
                if url == "https://chatgpt.com/api/auth/session":
                    response = DummyResponse(200, payload={"accessToken": access_token, "user": {"email": "jwt@example.com"}})
                    response.url = url
                    return response
                raise AssertionError(f"unexpected url: {url}")

        registrar.session = FakeSession()  # type: ignore[assignment]

        registrar._capture_registration_tokens(  # type: ignore[attr-defined]
            {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"}
        )

        self.assertEqual(registrar.registration_auth_code, "oauth-consent-code")
        self.assertIsNotNone(registrar.registration_tokens)
        self.assertEqual(registrar.registration_tokens["access_token"], access_token)
        self.assertEqual(registrar.registration_tokens["email"], "jwt@example.com")

    def test_capture_registration_tokens_falls_back_to_default_consent_when_add_phone_has_no_code(self):
        logger = logging.getLogger("test-registration-add-phone-fallback")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={"flow": {"step_retry_attempts": 1}})
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.cookies = []
                self.calls = []
                self.callback_completed = False

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if url == "https://auth.openai.com/add-phone":
                    response = DummyResponse(200, payload={"continue_url": "https://auth.openai.com/add-phone"})
                    response.url = url
                    return response
                if url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                    response = DummyResponse(302)
                    response.headers = {
                        "Location": (
                            "http://localhost:1455/auth/callback"
                            "?code=oauth-consent-code"
                            "&scope=openid+email+profile+offline_access"
                            "&state=oauth-state"
                        )
                    }
                    response.url = url
                    return response
                if (
                    url
                    == "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-consent-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ):
                    self.callback_completed = True
                    response = DummyResponse(200)
                    response.url = url
                    return response
                if url == "https://chatgpt.com/api/auth/session":
                    payload = {"accessToken": access_token, "user": {"email": "jwt@example.com"}} if self.callback_completed else {}
                    response = DummyResponse(200, payload=payload)
                    response.url = url
                    return response
                raise AssertionError(f"unexpected url: {url}")

        registrar.session = FakeSession()  # type: ignore[assignment]

        registrar._capture_registration_tokens(  # type: ignore[attr-defined]
            {"continue_url": "https://auth.openai.com/add-phone"}
        )

        self.assertEqual(registrar.registration_auth_code, "oauth-consent-code")
        self.assertIsNotNone(registrar.registration_tokens)
        self.assertEqual(registrar.registration_tokens["access_token"], access_token)
        self.assertIn(
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            [call[0] for call in registrar.session.calls],
        )

    def test_capture_registration_tokens_uses_nested_create_account_code_without_following_consent(self):
        logger = logging.getLogger("test-registration-nested-create-account-code")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={"flow": {"step_retry_attempts": 1}})
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )

        class FakeSession:
            def __init__(self):
                self.cookies = []
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if (
                    url
                    == "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-create-account-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ):
                    response = DummyResponse(200)
                    response.url = url
                    return response
                if url == "https://chatgpt.com/api/auth/session":
                    response = DummyResponse(200, payload={"accessToken": access_token, "user": {"email": "jwt@example.com"}})
                    response.url = url
                    return response
                raise AssertionError(f"unexpected url: {url}")

        registrar.session = FakeSession()  # type: ignore[assignment]

        registrar._capture_registration_tokens(  # type: ignore[attr-defined]
            {
                "continue_url": "https://auth.openai.com/add-phone",
                "page": {"type": "add_phone"},
                "data": {
                    "oauth_callback": {
                        "code": "oauth-create-account-code",
                        "scope": "openid email profile offline_access",
                        "state": "oauth-state",
                    }
                },
            }
        )

        self.assertEqual(registrar.registration_auth_code, "oauth-create-account-code")
        self.assertIsNotNone(registrar.registration_tokens)
        self.assertEqual(registrar.registration_tokens["access_token"], access_token)
        self.assertEqual(
            [call[0] for call in registrar.session.calls],
            [
                (
                    "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-create-account-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ),
                "https://chatgpt.com/api/auth/session",
            ],
        )

    def test_capture_registration_tokens_uses_session_cookie_callback_without_following_consent(self):
        logger = logging.getLogger("test-registration-cookie-callback-code")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={"flow": {"step_retry_attempts": 1}})
        access_token = build_test_jwt(
            {
                "email": "jwt@example.com",
                "exp": 1760000000,
                "https://api.openai.com/auth": {"chatgpt_account_id": "acct_123"},
            }
        )
        cookie_payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "continue_url": (
                        "http://localhost:1455/auth/callback"
                        "?code=oauth-cookie-code"
                        "&scope=openid+email+profile+offline_access"
                        "&state=oauth-state"
                    )
                }
            ).encode("utf-8")
        ).rstrip(b"=").decode("ascii")

        class DummyCookie:
            def __init__(self, name, value):
                self.name = name
                self.value = value
                self.domain = ".auth.openai.com"
                self.path = "/"

        class FakeSession:
            def __init__(self):
                self.cookies = [DummyCookie("oai-client-auth-session-info", f"{cookie_payload}.sig")]
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if (
                    url
                    == "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-cookie-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ):
                    response = DummyResponse(200)
                    response.url = url
                    return response
                if url == "https://chatgpt.com/api/auth/session":
                    response = DummyResponse(200, payload={"accessToken": access_token, "user": {"email": "jwt@example.com"}})
                    response.url = url
                    return response
                raise AssertionError(f"unexpected url: {url}")

        registrar.session = FakeSession()  # type: ignore[assignment]

        registrar._capture_registration_tokens(  # type: ignore[attr-defined]
            {
                "continue_url": "https://auth.openai.com/add-phone",
                "page": {"type": "add_phone"},
            }
        )

        self.assertEqual(registrar.registration_auth_code, "oauth-cookie-code")
        self.assertIsNotNone(registrar.registration_tokens)
        self.assertEqual(registrar.registration_tokens["access_token"], access_token)
        self.assertEqual(
            [call[0] for call in registrar.session.calls],
            [
                (
                    "https://chatgpt.com/api/auth/callback/openai"
                    "?code=oauth-cookie-code&scope=openid+email+profile+offline_access&state=oauth-state"
                ),
                "https://chatgpt.com/api/auth/session",
            ],
        )

    def test_step4_validate_otp_sentinel_fallback(self):
        logger = logging.getLogger("test-step4")
        conf = {
            "flow": {
                "step_retry_attempts": 1,
                "register_otp_validate_order": "normal,sentinel",
            }
        }
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf=conf)
        registrar.sentinel_gen.generate_token = lambda *_args, **_kwargs: "token-sentinel"

        captured_headers = []

        def fake_post(_url, **kwargs):
            captured_headers.append(kwargs.get("headers") or {})
            if len(captured_headers) == 1:
                return DummyResponse(400)
            return DummyResponse(200)

        registrar.session.post = fake_post

        ok = registrar.step4_validate_otp("123456")

        self.assertTrue(ok)
        self.assertEqual(len(captured_headers), 2)
        self.assertNotIn("openai-sentinel-token", captured_headers[0])
        self.assertEqual(captured_headers[1].get("openai-sentinel-token"), "token-sentinel")

    def test_register_passes_mail_poll_interval_to_provider(self):
        logger = logging.getLogger("test-register-mail-poll-interval")
        registrar = apm.ProtocolRegistrar(proxy="", logger=logger, conf={"flow": {"step_retry_attempts": 1}})

        registrar.step0_init_oauth_session = lambda *_args, **_kwargs: True
        registrar.step2_register_user = lambda *_args, **_kwargs: True
        registrar.step3_send_otp = lambda *_args, **_kwargs: True
        registrar.step4_validate_otp = lambda *_args, **_kwargs: True
        registrar.step5_create_account = lambda *_args, **_kwargs: True

        class FakeMailProvider:
            provider_name = "fake"

            def __init__(self):
                self.called_kwargs = {}

            def wait_for_verification_code(self, _mailbox, **kwargs):
                self.called_kwargs = kwargs
                return "123456"

        provider = FakeMailProvider()

        with patch("auto_pool_maintainer.time.sleep", lambda *_args, **_kwargs: None):
            ok = registrar.register(
                email="test@example.com",
                password="pw",
                client_id="cid",
                redirect_uri="http://localhost/cb",
                mailbox=apm.Mailbox(email="test@example.com"),
                mail_provider=provider,  # type: ignore[arg-type]
                otp_timeout_seconds=88,
                otp_poll_interval_seconds=1.25,
            )

        self.assertTrue(ok)
        self.assertEqual(provider.called_kwargs.get("timeout"), 88)
        self.assertEqual(provider.called_kwargs.get("poll_interval_seconds"), 1.25)


class RegisterOneFlowTests(unittest.TestCase):
    class _FakeMailProvider:
        provider_name = "fake"

        @staticmethod
        def create_mailbox():
            return apm.Mailbox(email="fake@example.com")

    class _FakeRuntime:
        def __init__(self, oauth_token=None):
            self.stop_event = threading.Event()
            self.target_tokens = 1
            self._token_count = 0
            self.mail_provider = RegisterOneFlowTests._FakeMailProvider()
            self.mail_provider_name = "fake"
            self.logger = logging.getLogger("test-register-one")
            self.proxy = ""
            self.conf = {}
            self.oauth_client_id = "cid"
            self.oauth_redirect_uri = "http://localhost/cb"
            self.mail_otp_timeout_seconds = 60
            self.mail_poll_interval_seconds = 1.0
            self.oauth_outer_retry_attempts = 3
            self.last_oauth_failure_detail = ""
            self.oauth_token = oauth_token
            self.oauth_called = False
            self.saved_tokens = None
            self.saved_account = None
            self.success_key = None

        def get_token_success_count(self):
            return self._token_count

        def wait_for_provider_availability(self, worker_id=0):
            return None

        def oauth_login_with_retry(self, mailbox, password):
            self.oauth_called = True
            return self.oauth_token

        def claim_token_slot(self):
            self._token_count += 1
            return True, self._token_count

        def release_token_slot(self):
            self._token_count = max(0, self._token_count - 1)

        def save_tokens(self, email, tokens):
            self.saved_tokens = tokens
            return True

        def save_account(self, email, password):
            self.saved_account = (email, password)

        def note_attempt_success(self, success_key="register_oauth_success"):
            self.success_key = success_key

        def note_attempt_failure(self, stage, email="", detail=""):
            raise AssertionError(f"unexpected failure: stage={stage} email={email} detail={detail}")

    class _FakeRegistrar:
        def __init__(self, proxy, logger, conf):
            self.last_failure_detail = ""
            self.last_failure_stage = ""

        def register(self, **kwargs):
            return True

        def exchange_codex_tokens(self, client_id, redirect_uri):
            raise AssertionError("register_one 不应再调用 exchange_codex_tokens")

    def test_register_one_calls_oauth_path(self):
        fake_runtime = self._FakeRuntime(oauth_token={"access_token": "oauth-token"})

        class Registrar(self._FakeRegistrar):
            pass

        with patch("auto_pool_maintainer.ProtocolRegistrar", Registrar), patch(
            "auto_pool_maintainer.generate_random_password", lambda: "Pw123456!"
        ):
            _, success, _, _ = apm.register_one(fake_runtime, worker_id=1)

        self.assertTrue(success)
        self.assertTrue(fake_runtime.oauth_called)
        self.assertEqual(fake_runtime.saved_tokens, {"access_token": "oauth-token"})
        self.assertEqual(fake_runtime.success_key, "register_oauth_success")

    def test_register_one_prefers_registration_session_tokens(self):
        class RuntimeWithoutOauth(self._FakeRuntime):
            def oauth_login_with_retry(self, mailbox, password):
                raise AssertionError("已有注册阶段 token 时不应再跑 OAuth 登录")

        runtime = RuntimeWithoutOauth(oauth_token=None)

        class Registrar(self._FakeRegistrar):
            def __init__(self, proxy, logger, conf):
                super().__init__(proxy, logger, conf)
                self.registration_tokens = {"access_token": "session-token", "email": "fake@example.com"}

        with patch("auto_pool_maintainer.ProtocolRegistrar", Registrar), patch(
            "auto_pool_maintainer.generate_random_password", lambda: "Pw123456!"
        ):
            _, success, _, _ = apm.register_one(runtime, worker_id=1)

        self.assertTrue(success)
        self.assertEqual(runtime.saved_tokens, {"access_token": "session-token", "email": "fake@example.com"})
        self.assertEqual(runtime.success_key, "register_oauth_success")

    def test_register_one_returns_fail_when_oauth_failed(self):
        class RuntimeWithFailure(self._FakeRuntime):
            failure_events = []

            def note_attempt_failure(self, stage, email="", detail=""):
                self.failure_events.append((stage, email, detail))

        runtime = RuntimeWithFailure(oauth_token=None)

        class Registrar(self._FakeRegistrar):
            pass

        with patch("auto_pool_maintainer.ProtocolRegistrar", Registrar), patch(
            "auto_pool_maintainer.generate_random_password", lambda: "Pw123456!"
        ):
            _, success, _, _ = apm.register_one(runtime, worker_id=1)

        self.assertFalse(success)
        self.assertTrue(runtime.oauth_called)
        self.assertTrue(runtime.failure_events)
        self.assertEqual(runtime.failure_events[-1][0], "oauth")

    def test_register_one_create_mailbox_failure_marks_selected_domain(self):
        class FakeMailProvider:
            provider_name = "fake"

            def __init__(self):
                self.last_selected_domain = "a.test"
                self.failure_calls = []

            def wait_for_availability(self, worker_id=0):
                return None

            def create_mailbox(self):
                return None

            def note_domain_failure(self, domain, *, stage, detail=""):
                self.failure_calls.append((domain, stage, detail))

            def note_domain_success(self, domain):
                return None

        class FakeRuntime(self._FakeRuntime):
            def __init__(self):
                super().__init__()
                self.mail_provider = FakeMailProvider()
                self.mail_provider_name = "fake"
                self.failure_events = []

            def note_attempt_failure(self, stage, email="", detail=""):
                self.failure_events.append((stage, email, detail))

        runtime = FakeRuntime()
        email, success, _, _ = apm.register_one(runtime)

        self.assertIsNone(email)
        self.assertFalse(success)
        self.assertEqual(runtime.mail_provider.failure_calls, [("a.test", "create_mailbox", "provider=fake")])

    def test_register_one_register_mail_timeout_marks_mailbox_domain(self):
        class FakeMailProvider(self._FakeMailProvider):
            provider_name = "fake"

            def __init__(self):
                self.failure_calls = []

            def wait_for_availability(self, worker_id=0):
                return None

            @staticmethod
            def create_mailbox():
                return apm.Mailbox(email="fake@example.com", domain="a.test")

            def note_domain_failure(self, domain, *, stage, detail=""):
                self.failure_calls.append((domain, stage, detail))

            def note_domain_success(self, domain):
                return None

        class FakeRuntime(self._FakeRuntime):
            def __init__(self):
                super().__init__()
                self.mail_provider = FakeMailProvider()
                self.mail_provider_name = "fake"
                self.failure_events = []

            def note_attempt_failure(self, stage, email="", detail=""):
                self.failure_events.append((stage, email, detail))

        class FakeRegistrar(self._FakeRegistrar):
            def register(self, **kwargs):
                self.last_failure_stage = "register_mail_otp_timeout"
                self.last_failure_detail = "provider=fake"
                return False

        runtime = FakeRuntime()
        with patch("auto_pool_maintainer.ProtocolRegistrar", FakeRegistrar), patch(
            "auto_pool_maintainer.generate_random_password", lambda: "Pw123456!"
        ):
            email, success, _, _ = apm.register_one(runtime, worker_id=1)

        self.assertEqual(email, "fake@example.com")
        self.assertFalse(success)
        self.assertEqual(runtime.mail_provider.failure_calls, [("a.test", "register", "provider=fake")])


if __name__ == "__main__":
    unittest.main()
