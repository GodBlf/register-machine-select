import logging
import os
import threading
import tempfile
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


class FlowHelperTests(unittest.TestCase):
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

class ProtocolRegistrarTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
