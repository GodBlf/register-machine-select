import type { LogLine, StatItem } from "./runtime";

export type SingleAccountTimingResponse = {
  latest_reg_seconds: number | null;
  latest_oauth_seconds: number | null;
  latest_total_seconds: number | null;
  recent_avg_reg_seconds: number | null;
  recent_avg_oauth_seconds: number | null;
  recent_avg_total_seconds: number | null;
  recent_slow_count: number;
  sample_size: number;
  window_size: number;
};

export type BackendConfig = {
  cfmail: {
    api_base: string;
    api_key: string;
    domain: string;
    domains: string[];
  };
  clean: {
    base_url: string;
    token: string;
    target_type: string;
    workers: number;
    sample_size: number;
    delete_workers: number;
    timeout: number;
    retries: number;
    user_agent?: string;
    used_percent_threshold: number;
  };
  mail: {
    provider: string;
    api_base: string;
    api_key: string;
    domain: string;
    domains: string[];
    otp_timeout_seconds: number;
    poll_interval_seconds: number;
  };
  duckmail: {
    api_base: string;
    bearer: string;
    domain: string;
    domains: string[];
  };
  tempmail_lol: {
    api_base: string;
  };
  yyds_mail: {
    api_base: string;
    api_key: string;
    domain: string;
    domains: string[];
  };
  maintainer: {
    min_candidates: number;
    loop_interval_seconds: number;
  };
  run: {
    workers: number;
    proxy: string;
    failure_threshold_for_cooldown: number;
    failure_cooldown_seconds: number;
    loop_jitter_min_seconds: number;
    loop_jitter_max_seconds: number;
  };
  flow: {
    step_retry_attempts: number;
    step_retry_delay_base: number;
    step_retry_delay_cap: number;
    outer_retry_attempts: number;
    oauth_local_retry_attempts: number;
    transient_markers: string;
    register_otp_validate_order: string;
    oauth_otp_validate_order: string;
    oauth_password_phone_action: string;
    oauth_otp_phone_action: string;
  };
  registration: {
    entry_mode: string;
    entry_mode_fallback: boolean;
    chatgpt_base: string;
    register_create_account_phone_action: string;
    phone_verification_markers: string;
  };
  oauth: {
    issuer: string;
    client_id: string;
    redirect_uri: string;
    retry_attempts: number;
    retry_backoff_base: number;
    retry_backoff_max: number;
    otp_timeout_seconds: number;
    otp_poll_interval_seconds: number;
  };
  output: {
    accounts_file: string;
    csv_file: string;
    ak_file: string;
    rk_file: string;
    save_local: boolean;
  };
};

export type RuntimeStatusResponse = {
  running: boolean;
  run_mode?: string;
  loop_running?: boolean;
  loop_next_check_in_seconds?: number | null;
  phase: string;
  message: string;
  available_candidates: number | null;
  available_candidates_error?: string;
  completed: number;
  total: number;
  percent: number;
  stats: StatItem[];
  single_account_timing?: SingleAccountTimingResponse;
  logs: LogLine[];
  last_log_path?: string;
};

export type StartRuntimeResponse = {
  ok: boolean;
  started: boolean;
  pid?: number;
  mode?: string;
  message: string;
};

export type StopRuntimeResponse = {
  ok: boolean;
  stopped: boolean;
  message: string;
};

export type AuthState = {
  token: string;
};
