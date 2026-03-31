# gpt-auto

一个用于**账号池维护（清理 + 补号）**的本地工具，包含：

- Python 后端（`api_server.py` + `auto_pool_maintainer.py`）
- Preact 前端控制台（`frontend/`）
- 一键启动脚本（`dev_services.sh`）

---

## 新手快速上手（最短路径）

> 目标：第一次就能正确拉起项目并进入前端面板。

### 1) 安装依赖

在项目根目录执行：

```bash
# 1. Python 依赖
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 2. 前端依赖
cd frontend
pnpm install
cd ..
```

### 2) 准备配置文件

```bash
cp config.example.json config.json
```

然后至少修改以下关键项（不改会跑不起来）：

- `clean.base_url`：你的 CLIProxyAPI 地址（例如 `http://127.0.0.1:8317`）
- `clean.token`：CLIProxyAPI 管理 token
- `mail.provider` + 对应 provider 的配置（`mail.api_base/api_key/domain/domains` 或 `cfmail.api_base/api_key/domains` 等）

### 3) 启动项目

```bash
./dev_services.sh fg
```

启动成功后：

- 前端地址：`http://127.0.0.1:8173`
- 后端 API：`http://127.0.0.1:8318`

首次启动后端会生成 `admin_token.txt`，把里面的 token 复制到前端登录框（`X-Admin-Token`）。

---

## 关键配置说明（只讲重要的）

配置文件：`config.json`

### `clean`（账号探测/清理）

- `base_url` / `token`：CLIProxyAPI 连接信息（必填）
- `target_type`：目标账号类型（通常为 `codex`）
- `sample_size`：随机抽样探测数量，`0` 表示全量探测
- `used_percent_threshold`：超阈值判定

### `maintainer`（补号目标）

- `min_candidates`：目标可用号数量（低于它就补号）
- `loop_interval_seconds`：循环模式下每轮检查间隔

### `run`（补号执行参数）

- `workers`：补号并发
- `failure_threshold_for_cooldown` / `failure_cooldown_seconds`：连续失败冷却策略
  - 对支持多域名的邮箱 provider，这两个参数作用于“单个域名”的熔断与恢复

### `mail`（邮箱提供方）

- `provider`：`cfmail / self_hosted_mail_api / duckmail / tempmail_lol / yyds_mail`
- 不同 provider 需要填写对应 section 的鉴权字段
- `otp_timeout_seconds` / `poll_interval_seconds`：验证码等待与轮询间隔
- 支持多域名的 provider：`self_hosted_mail_api / duckmail / yyds_mail`
- `domains`：可选数组，配置多个域名时按顺序轮询；如果填写，优先级高于单个 `domain`
- `tempmail_lol` 当前不支持自定义多域名切换

### `cfmail`（CF 自建邮箱）

- `api_base`：CF Mail Worker 接口地址
- `api_key`：CF Mail 管理密钥，请求时会发到 `x-admin-auth`
- `domains`：域名列表，按顺序轮询；填写后优先于单个 `domain`
- `cfmail` 是独立 provider，不复用 `self_hosted_mail_api`
- 节点熔断直接复用 `run.failure_threshold_for_cooldown / run.failure_cooldown_seconds`

---

## 常用命令

```bash
# 前台启动（推荐调试）
./dev_services.sh fg

# 后台启动
./dev_services.sh bg

# 查看状态
./dev_services.sh status

# 停止后台服务
./dev_services.sh stop
```

单次执行维护任务（不走前端）：

```bash
./.venv/bin/python auto_pool_maintainer.py --config config.json --log-dir logs
```

---

## 日志与产物

- 维护日志：`logs/pool_maintainer_*.log`
- 服务托管日志：`logs/dev-services/`
- 本地 token/账号输出（当 `output.save_local=true` 时）：
  - `output_fixed/`
  - `output_tokens/`

---

## 排错建议（高频）

1. 前端打开但接口 401：通常是 `X-Admin-Token` 错误，重新读取 `admin_token.txt`
2. 补号不触发：先看日志里的 `清理后统计: candidates=... 阈值=...`
3. 启动失败：先看 `logs/dev-services/backend.log` / `frontend.log`
4. OAuth 偶发慢：优先看日志中的 `oauth_mail_otp_timeout` 是否增多（邮箱链路波动）

---

## 安全提示

- `config.json`、`admin_token.txt` 可能包含敏感信息，不要公开上传。
- 对外发布代码时，建议仅保留 `config.example.json`。
