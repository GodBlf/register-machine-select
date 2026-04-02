import type { BackendConfig } from "../types/api";
import type { ConfigSection } from "../types/runtime";

export const defaultBackendConfig: BackendConfig = {
  cfmail: {
    api_base: "https://mail.example.com",
    api_key: "",
    domain: "",
    domains: [],
  },
  clean: {
    base_url: "CPA地址",
    token: "CPA登录密码",
    target_type: "codex",
    workers: 20,
    sample_size: 0,
    delete_workers: 20,
    timeout: 10,
    retries: 1,
    user_agent: "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
    used_percent_threshold: 95,
  },
  mail: {
    provider: "tempmail_lol",
    api_base: "https://your-worker.workers.dev",
    api_key: "your-mail-api-key",
    domain: "mail.example.com",
    domains: [],
    otp_timeout_seconds: 120,
    poll_interval_seconds: 3,
  },
  duckmail: {
    api_base: "https://api.duckmail.sbs",
    bearer: "",
    domain: "duckmail.sbs",
    domains: [],
  },
  tempmail_lol: {
    api_base: "https://api.tempmail.lol/v2",
  },
  yyds_mail: {
    api_base: "https://maliapi.215.im/v1",
    api_key: "",
    domain: "",
    domains: [],
  },
  maintainer: {
    min_candidates: 50,
    loop_interval_seconds: 60,
  },
  run: {
    workers: 8,
    proxy: "",
    failure_threshold_for_cooldown: 5,
    failure_cooldown_seconds: 45,
    loop_jitter_min_seconds: 2,
    loop_jitter_max_seconds: 6,
  },
  flow: {
    step_retry_attempts: 2,
    step_retry_delay_base: 0.2,
    step_retry_delay_cap: 0.8,
    outer_retry_attempts: 3,
    oauth_local_retry_attempts: 3,
    transient_markers:
      "sentinel_,oauth_authorization_code_not_found,headers_failed,timeout,timed out,server disconnected,unexpected_eof_while_reading,transport,remoteprotocolerror,connection reset,temporarily unavailable,network,eof occurred,http_429,http_500,http_502,http_503,http_504",
    register_otp_validate_order: "normal,sentinel",
    oauth_otp_validate_order: "normal,sentinel",
    oauth_password_phone_action: "warn_and_continue",
    oauth_otp_phone_action: "warn_and_continue",
  },
  registration: {
    entry_mode: "chatgpt_web",
    entry_mode_fallback: true,
    chatgpt_base: "https://chatgpt.com",
    register_create_account_phone_action: "warn_and_continue",
    phone_verification_markers: "add_phone,/add-phone,phone_verification,phone-verification,phone/verify",
  },
  oauth: {
    issuer: "https://auth.openai.com",
    client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
    redirect_uri: "http://localhost:1455/auth/callback",
    retry_attempts: 3,
    retry_backoff_base: 2,
    retry_backoff_max: 15,
    otp_timeout_seconds: 120,
    otp_poll_interval_seconds: 2,
  },
  output: {
    accounts_file: "accounts.txt",
    csv_file: "registered_accounts.csv",
    ak_file: "ak.txt",
    rk_file: "rk.txt",
    save_local: false,
  },
};

function toNumber(value: unknown, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toString(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function toBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function toStringArray(value: unknown, fallback: string[] = []): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const normalized = value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
  return normalized.length ? normalized : fallback;
}

function linesToArray(value: unknown): string[] {
  return String(value ?? "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function arrayToLines(values: string[]): string {
  return values.join("\n");
}

export function normalizeBackendConfig(raw: Partial<BackendConfig> | Record<string, unknown>): BackendConfig {
  const source = raw ?? {};
  const cfmail = (source.cfmail ?? {}) as Partial<BackendConfig["cfmail"]>;
  const clean = (source.clean ?? {}) as Partial<BackendConfig["clean"]>;
  const mail = (source.mail ?? {}) as Partial<BackendConfig["mail"]>;
  const duckmail = (source.duckmail ?? {}) as Partial<BackendConfig["duckmail"]>;
  const tempmailLol = (source.tempmail_lol ?? {}) as Partial<BackendConfig["tempmail_lol"]>;
  const yydsMail = (source.yyds_mail ?? {}) as Partial<BackendConfig["yyds_mail"]>;
  const maintainer = (source.maintainer ?? {}) as Partial<BackendConfig["maintainer"]>;
  const run = (source.run ?? {}) as Partial<BackendConfig["run"]>;
  const flow = (source.flow ?? {}) as Partial<BackendConfig["flow"]>;
  const registration = (source.registration ?? {}) as Partial<BackendConfig["registration"]>;
  const oauth = (source.oauth ?? {}) as Partial<BackendConfig["oauth"]>;
  const output = (source.output ?? {}) as Partial<BackendConfig["output"]>;

  return {
    cfmail: {
      api_base: toString(cfmail.api_base, defaultBackendConfig.cfmail.api_base),
      api_key: toString(cfmail.api_key, defaultBackendConfig.cfmail.api_key),
      domain: toString(cfmail.domain, defaultBackendConfig.cfmail.domain),
      domains: toStringArray(cfmail.domains, defaultBackendConfig.cfmail.domains),
    },
    clean: {
      base_url: toString(clean.base_url, defaultBackendConfig.clean.base_url),
      token: toString(clean.token, defaultBackendConfig.clean.token),
      target_type: toString(clean.target_type, defaultBackendConfig.clean.target_type),
      workers: toNumber(clean.workers, defaultBackendConfig.clean.workers),
      sample_size: toNumber(clean.sample_size, defaultBackendConfig.clean.sample_size),
      delete_workers: toNumber(clean.delete_workers, defaultBackendConfig.clean.delete_workers),
      timeout: toNumber(clean.timeout, defaultBackendConfig.clean.timeout),
      retries: toNumber(clean.retries, defaultBackendConfig.clean.retries),
      user_agent: toString(clean.user_agent, defaultBackendConfig.clean.user_agent ?? ""),
      used_percent_threshold: toNumber(clean.used_percent_threshold, defaultBackendConfig.clean.used_percent_threshold),
    },
    mail: {
      provider: toString(mail.provider, defaultBackendConfig.mail.provider),
      api_base: toString(mail.api_base, defaultBackendConfig.mail.api_base),
      api_key: toString(mail.api_key, defaultBackendConfig.mail.api_key),
      domain: toString(mail.domain, defaultBackendConfig.mail.domain),
      domains: toStringArray(mail.domains, defaultBackendConfig.mail.domains),
      otp_timeout_seconds: toNumber(mail.otp_timeout_seconds, defaultBackendConfig.mail.otp_timeout_seconds),
      poll_interval_seconds: toNumber(mail.poll_interval_seconds, defaultBackendConfig.mail.poll_interval_seconds),
    },
    duckmail: {
      api_base: toString(duckmail.api_base, defaultBackendConfig.duckmail.api_base),
      bearer: toString(duckmail.bearer, defaultBackendConfig.duckmail.bearer),
      domain: toString(duckmail.domain, defaultBackendConfig.duckmail.domain),
      domains: toStringArray(duckmail.domains, defaultBackendConfig.duckmail.domains),
    },
    tempmail_lol: {
      api_base: toString(tempmailLol.api_base, defaultBackendConfig.tempmail_lol.api_base),
    },
    yyds_mail: {
      api_base: toString(yydsMail.api_base, defaultBackendConfig.yyds_mail.api_base),
      api_key: toString(yydsMail.api_key, defaultBackendConfig.yyds_mail.api_key),
      domain: toString(yydsMail.domain, defaultBackendConfig.yyds_mail.domain),
      domains: toStringArray(yydsMail.domains, defaultBackendConfig.yyds_mail.domains),
    },
    maintainer: {
      min_candidates: toNumber(maintainer.min_candidates, defaultBackendConfig.maintainer.min_candidates),
      loop_interval_seconds: toNumber(
        maintainer.loop_interval_seconds,
        defaultBackendConfig.maintainer.loop_interval_seconds,
      ),
    },
    run: {
      workers: toNumber(run.workers, defaultBackendConfig.run.workers),
      proxy: toString(run.proxy, defaultBackendConfig.run.proxy),
      failure_threshold_for_cooldown: toNumber(
        run.failure_threshold_for_cooldown,
        defaultBackendConfig.run.failure_threshold_for_cooldown,
      ),
      failure_cooldown_seconds: toNumber(run.failure_cooldown_seconds, defaultBackendConfig.run.failure_cooldown_seconds),
      loop_jitter_min_seconds: toNumber(run.loop_jitter_min_seconds, defaultBackendConfig.run.loop_jitter_min_seconds),
      loop_jitter_max_seconds: toNumber(run.loop_jitter_max_seconds, defaultBackendConfig.run.loop_jitter_max_seconds),
    },
    flow: {
      step_retry_attempts: toNumber(flow.step_retry_attempts, defaultBackendConfig.flow.step_retry_attempts),
      step_retry_delay_base: toNumber(flow.step_retry_delay_base, defaultBackendConfig.flow.step_retry_delay_base),
      step_retry_delay_cap: toNumber(flow.step_retry_delay_cap, defaultBackendConfig.flow.step_retry_delay_cap),
      outer_retry_attempts: toNumber(flow.outer_retry_attempts, defaultBackendConfig.flow.outer_retry_attempts),
      oauth_local_retry_attempts: toNumber(
        flow.oauth_local_retry_attempts,
        defaultBackendConfig.flow.oauth_local_retry_attempts,
      ),
      transient_markers: toString(flow.transient_markers, defaultBackendConfig.flow.transient_markers),
      register_otp_validate_order: toString(
        flow.register_otp_validate_order,
        defaultBackendConfig.flow.register_otp_validate_order,
      ),
      oauth_otp_validate_order: toString(flow.oauth_otp_validate_order, defaultBackendConfig.flow.oauth_otp_validate_order),
      oauth_password_phone_action: toString(
        flow.oauth_password_phone_action,
        defaultBackendConfig.flow.oauth_password_phone_action,
      ),
      oauth_otp_phone_action: toString(flow.oauth_otp_phone_action, defaultBackendConfig.flow.oauth_otp_phone_action),
    },
    registration: {
      entry_mode: toString(registration.entry_mode, defaultBackendConfig.registration.entry_mode),
      entry_mode_fallback: toBoolean(registration.entry_mode_fallback, defaultBackendConfig.registration.entry_mode_fallback),
      chatgpt_base: toString(registration.chatgpt_base, defaultBackendConfig.registration.chatgpt_base),
      register_create_account_phone_action: toString(
        registration.register_create_account_phone_action,
        defaultBackendConfig.registration.register_create_account_phone_action,
      ),
      phone_verification_markers: toString(
        registration.phone_verification_markers,
        defaultBackendConfig.registration.phone_verification_markers,
      ),
    },
    oauth: {
      issuer: toString(oauth.issuer, defaultBackendConfig.oauth.issuer),
      client_id: toString(oauth.client_id, defaultBackendConfig.oauth.client_id),
      redirect_uri: toString(oauth.redirect_uri, defaultBackendConfig.oauth.redirect_uri),
      retry_attempts: toNumber(oauth.retry_attempts, defaultBackendConfig.oauth.retry_attempts),
      retry_backoff_base: toNumber(oauth.retry_backoff_base, defaultBackendConfig.oauth.retry_backoff_base),
      retry_backoff_max: toNumber(oauth.retry_backoff_max, defaultBackendConfig.oauth.retry_backoff_max),
      otp_timeout_seconds: toNumber(oauth.otp_timeout_seconds, defaultBackendConfig.oauth.otp_timeout_seconds),
      otp_poll_interval_seconds: toNumber(
        oauth.otp_poll_interval_seconds,
        defaultBackendConfig.oauth.otp_poll_interval_seconds,
      ),
    },
    output: {
      accounts_file: toString(output.accounts_file, defaultBackendConfig.output.accounts_file),
      csv_file: toString(output.csv_file, defaultBackendConfig.output.csv_file),
      ak_file: toString(output.ak_file, defaultBackendConfig.output.ak_file),
      rk_file: toString(output.rk_file, defaultBackendConfig.output.rk_file),
      save_local: toBoolean(output.save_local, defaultBackendConfig.output.save_local),
    },
  };
}

export function configToSections(config: BackendConfig): ConfigSection[] {
  return [
    {
      key: "priority",
      label: "核心配置",
      fields: [
        { key: "base_url", label: "CPA 接口地址", type: "text", value: config.clean.base_url },
        { key: "token", label: "CPA 访问令牌", type: "password", value: config.clean.token, sensitive: true },
        {
          key: "min_candidates",
          label: "最小候选账号数",
          type: "number",
          value: config.maintainer.min_candidates,
          hint: "表示账号池希望长期保有的最低可用账号数。清理完成后若当前候选账号低于该值，系统会自动补号。",
        },
        {
          key: "loop_interval_seconds",
          label: "循环补号间隔(秒)",
          type: "number",
          value: config.maintainer.loop_interval_seconds,
          hint: "点击“循环补号”按钮后，每轮检查完会休眠该秒数再重新检测。",
        },
        {
          key: "proxy",
          label: "代理地址",
          type: "text",
          value: config.run.proxy,
          hint: "示例: http://127.0.0.1:7890 或 socks5://127.0.0.1:1080",
        },
      ],
    },
    {
      key: "clean",
      label: "清理配置",
      columns: 2,
      fields: [
        { key: "target_type", label: "目标账号类型", type: "text", value: config.clean.target_type },
        { key: "timeout", label: "请求超时", type: "number", value: config.clean.timeout },
        { key: "workers", label: "探测并发", type: "number", value: config.clean.workers },
        {
          key: "sample_size",
          label: "抽样数量",
          type: "number",
          value: config.clean.sample_size,
          hint: "0 表示全量探测；大于 0 时，每轮仅随机抽取这部分账号做可用性探测。",
        },
        { key: "delete_workers", label: "删除并发", type: "number", value: config.clean.delete_workers },
        { key: "retries", label: "重试次数", type: "number", value: config.clean.retries },
        {
          key: "used_percent_threshold",
          label: "用量阈值",
          type: "number",
          value: config.clean.used_percent_threshold,
          hint: "用于识别高消耗账号。若账号的 used_percent 大于等于该值，会在清理阶段优先禁用（不直接删除）。",
        },
      ],
    },
    {
      key: "mail",
      label: "邮箱配置",
      columns: 2,
      fields: [
        {
          key: "provider",
          label: "邮箱提供方",
          type: "select",
          value: config.mail.provider,
          options: [
            { label: "cfmail", value: "cfmail" },
            { label: "self_hosted_mail_api", value: "self_hosted_mail_api" },
            { label: "duckmail", value: "duckmail" },
            { label: "tempmail_lol", value: "tempmail_lol" },
            { label: "yyds_mail", value: "yyds_mail" },
          ],
        },
        { key: "otp_timeout_seconds", label: "验证码超时", type: "number", value: config.mail.otp_timeout_seconds },
        { key: "poll_interval_seconds", label: "轮询间隔", type: "number", value: config.mail.poll_interval_seconds },
      ],
    },
    {
      key: "cfmail",
      label: "CF Mail 配置",
      columns: 2,
      fields: [
        { key: "api_base", label: "接口地址", type: "text", value: config.cfmail.api_base },
        { key: "api_key", label: "接口密钥", type: "password", value: config.cfmail.api_key, sensitive: true },
        { key: "domain", label: "邮箱域名", type: "text", value: config.cfmail.domain },
        {
          key: "domains",
          label: "邮箱域名列表",
          type: "textarea",
          value: arrayToLines(config.cfmail.domains),
          hint: "每行一个域名；填写后优先于单个 domain。",
        },
      ],
    },
    {
      key: "self_hosted_mail_api",
      label: "自建 Mail API 配置",
      columns: 2,
      fields: [
        { key: "api_base", label: "邮件 API 地址", type: "text", value: config.mail.api_base },
        { key: "domain", label: "邮箱域名", type: "text", value: config.mail.domain },
        {
          key: "domains",
          label: "邮箱域名列表",
          type: "textarea",
          value: arrayToLines(config.mail.domains),
          hint: "每行一个域名；填写后优先于单个 domain。",
        },
        { key: "api_key", label: "邮件 API 密钥", type: "password", value: config.mail.api_key, sensitive: true },
      ],
    },
    {
      key: "duckmail",
      label: "DuckMail 配置",
      columns: 2,
      fields: [
        { key: "api_base", label: "接口地址", type: "text", value: config.duckmail.api_base },
        { key: "domain", label: "邮箱域名", type: "text", value: config.duckmail.domain },
        {
          key: "domains",
          label: "邮箱域名列表",
          type: "textarea",
          value: arrayToLines(config.duckmail.domains),
          hint: "每行一个域名；填写后优先于单个 domain。",
        },
        { key: "bearer", label: "访问凭证", type: "password", value: config.duckmail.bearer, sensitive: true },
      ],
    },
    {
      key: "tempmail_lol",
      label: "TempMail.lol 配置",
      fields: [{ key: "api_base", label: "接口地址", type: "text", value: config.tempmail_lol.api_base }],
    },
    {
      key: "yyds_mail",
      label: "YYDS Mail 配置",
      columns: 2,
      fields: [
        { key: "api_base", label: "接口地址", type: "text", value: config.yyds_mail.api_base },
        { key: "domain", label: "邮箱域名", type: "text", value: config.yyds_mail.domain },
        {
          key: "domains",
          label: "邮箱域名列表",
          type: "textarea",
          value: arrayToLines(config.yyds_mail.domains),
          hint: "每行一个域名；填写后优先于单个 domain。",
        },
        { key: "api_key", label: "访问密钥", type: "password", value: config.yyds_mail.api_key, sensitive: true },
      ],
    },
    {
      key: "run",
      label: "运行参数",
      columns: 2,
      fields: [
        { key: "workers", label: "补号并发数", type: "number", value: config.run.workers },
        {
          key: "failure_threshold_for_cooldown",
          label: "连续失败阈值",
          type: "number",
          value: config.run.failure_threshold_for_cooldown,
        },
        {
          key: "failure_cooldown_seconds",
          label: "冷却时长",
          type: "number",
          value: config.run.failure_cooldown_seconds,
        },
        { key: "loop_jitter_min_seconds", label: "最小抖动秒数", type: "number", value: config.run.loop_jitter_min_seconds },
        { key: "loop_jitter_max_seconds", label: "最大抖动秒数", type: "number", value: config.run.loop_jitter_max_seconds },
      ],
    },
    {
      key: "registration",
      label: "注册流程策略",
      columns: 2,
      fields: [
        {
          key: "entry_mode",
          label: "注册入口模式",
          type: "select",
          value: config.registration.entry_mode,
          options: [
            { label: "chatgpt_web", value: "chatgpt_web" },
            { label: "direct_auth", value: "direct_auth" },
          ],
        },
        { key: "entry_mode_fallback", label: "入口失败自动回退", type: "checkbox", value: config.registration.entry_mode_fallback },
        { key: "chatgpt_base", label: "ChatGPT 入口域名", type: "text", value: config.registration.chatgpt_base },
        {
          key: "register_create_account_phone_action",
          label: "注册命中手机验证",
          type: "select",
          value: config.registration.register_create_account_phone_action,
          options: [
            { label: "warn_and_continue", value: "warn_and_continue" },
            { label: "fail_fast", value: "fail_fast" },
          ],
        },
        {
          key: "phone_verification_markers",
          label: "手机验证识别关键词",
          type: "text",
          value: config.registration.phone_verification_markers,
        },
      ],
    },
    {
      key: "flow",
      label: "流程重试策略",
      columns: 2,
      fields: [
        { key: "step_retry_attempts", label: "注册步骤局部重试", type: "number", value: config.flow.step_retry_attempts },
        { key: "step_retry_delay_base", label: "步骤重试基数", type: "number", value: config.flow.step_retry_delay_base },
        { key: "step_retry_delay_cap", label: "步骤重试上限", type: "number", value: config.flow.step_retry_delay_cap },
        { key: "outer_retry_attempts", label: "OAuth 外层重试", type: "number", value: config.flow.outer_retry_attempts },
        {
          key: "oauth_local_retry_attempts",
          label: "OAuth 局部重试",
          type: "number",
          value: config.flow.oauth_local_retry_attempts,
        },
        { key: "register_otp_validate_order", label: "注册 OTP 校验顺序", type: "text", value: config.flow.register_otp_validate_order },
        { key: "oauth_otp_validate_order", label: "OAuth OTP 校验顺序", type: "text", value: config.flow.oauth_otp_validate_order },
        {
          key: "oauth_password_phone_action",
          label: "OAuth 密码阶段手机验证",
          type: "select",
          value: config.flow.oauth_password_phone_action,
          options: [
            { label: "warn_and_continue", value: "warn_and_continue" },
            { label: "fail_fast", value: "fail_fast" },
          ],
        },
        {
          key: "oauth_otp_phone_action",
          label: "OAuth OTP阶段手机验证",
          type: "select",
          value: config.flow.oauth_otp_phone_action,
          options: [
            { label: "warn_and_continue", value: "warn_and_continue" },
            { label: "fail_fast", value: "fail_fast" },
          ],
        },
        { key: "transient_markers", label: "瞬时错误关键词", type: "text", value: config.flow.transient_markers },
      ],
    },
    {
      key: "oauth",
      label: "OAuth 配置",
      columns: 2,
      fields: [
        { key: "issuer", label: "认证服务地址", type: "text", value: config.oauth.issuer },
        { key: "client_id", label: "客户端 ID", type: "text", value: config.oauth.client_id },
        { key: "redirect_uri", label: "回调地址", type: "text", value: config.oauth.redirect_uri },
        { key: "retry_attempts", label: "重试次数", type: "number", value: config.oauth.retry_attempts },
        { key: "retry_backoff_base", label: "退避基数", type: "number", value: config.oauth.retry_backoff_base },
        { key: "retry_backoff_max", label: "最大退避", type: "number", value: config.oauth.retry_backoff_max },
        { key: "otp_timeout_seconds", label: "登录验证码超时", type: "number", value: config.oauth.otp_timeout_seconds },
        { key: "otp_poll_interval_seconds", label: "登录轮询间隔", type: "number", value: config.oauth.otp_poll_interval_seconds },
      ],
    },
    {
      key: "output",
      label: "输出配置",
      columns: 2,
      fields: [
        { key: "accounts_file", label: "账号文件", type: "text", value: config.output.accounts_file },
        { key: "csv_file", label: "CSV 文件", type: "text", value: config.output.csv_file },
        { key: "ak_file", label: "Access Token 文件", type: "text", value: config.output.ak_file },
        { key: "rk_file", label: "Refresh Token 文件", type: "text", value: config.output.rk_file },
        { key: "save_local", label: "本地保存", type: "checkbox", value: config.output.save_local },
      ],
    },
  ];
}

export function sectionsToConfig(sections: ConfigSection[]): BackendConfig {
  const config = structuredClone(defaultBackendConfig);

  for (const section of sections) {
    const targetKey = section.key === "self_hosted_mail_api" ? "mail" : section.key;
    if (section.key === "priority") {
      for (const field of section.fields) {
        if (field.key === "base_url" || field.key === "token") {
          (config.clean as Record<string, string | number | boolean>)[field.key] = field.value;
        } else if (field.key === "min_candidates") {
          config.maintainer.min_candidates = Number(field.value);
        } else if (field.key === "loop_interval_seconds") {
          config.maintainer.loop_interval_seconds = Number(field.value);
        } else if (field.key === "proxy") {
          config.run.proxy = String(field.value);
        }
      }
      continue;
    }
    const target = config[targetKey as keyof BackendConfig] as Record<string, string | number | boolean | string[]>;
    if (!target) {
      continue;
    }
    for (const field of section.fields) {
      if (field.key === "domains") {
        target[field.key] = linesToArray(field.value);
        continue;
      }
      target[field.key] = field.value;
    }
  }

  return normalizeBackendConfig(config);
}
