# Codex Auth Cleaner (Go)

一个基于 Go 的 Codex 认证文件扫描服务，用于批量检查指定目录中的 auth JSON 文件，识别：

- `401 Unauthorized`
- `quota exceeded / usage_limit_reached`
- `unlimited / no-limit` 账号
- 解析错误、缺失 token、网络错误

项目提供 Web 界面和 HTTP API，支持：

- 递归扫描 `auth_dir`
- 可选在检查前使用 `refresh_token` 刷新 access token
- 自动隔离超限账号到 `exceeded_dir`
- 回扫 `exceeded_dir`，恢复已恢复正常的账号
- 自动删除或手动删除 `401` 文件
- SSE 实时推送扫描进度

## 功能说明

### `exceeded_dir` 是做什么的

`exceeded_dir` 是“超限隔离目录”，不是删除目录。

扫描时如果某个 auth 文件被识别为 `quota_exceeded=true`，并且没有启用 `no_quarantine`，程序会把它从 `auth_dir` 移到 `exceeded_dir`。这样可以把“额度暂时用完但凭据还有效”的账号先隔离出去，避免继续参与主目录的使用或扫描。

之后程序会再扫一遍 `exceeded_dir`：

- 如果文件仍然超限，继续留在 `exceeded_dir`
- 如果文件已经恢复正常，且返回 `2xx` 且不再超限，就移回 `auth_dir`

`401` 文件不进入 `exceeded_dir`。它们属于已失效凭据，开启 `delete_401` 后会直接删除。

## 技术栈

- `gin`：HTTP 服务与 API
- `viper`：读取 `config.yaml`
- `resty`：HTTP 请求客户端
- `fx`：依赖注入与应用启动
- `embed`：将前端静态资源打包进二进制

## 项目结构

```text
clean-script-go/
├─ cmd/server/main.go           # 服务入口
├─ config.yaml                  # 默认配置
├─ internal/app                 # Fx 应用装配
├─ internal/config              # 配置加载与请求参数合并
├─ internal/codex               # Codex 请求、refresh token、响应判定
├─ internal/fileops             # 文件扫描、JSON 读取、移动与删除
├─ internal/httpapi             # Gin 路由、SSE、静态资源服务
├─ internal/manager             # 扫描状态与订阅管理
├─ internal/model               # DTO / 领域模型
├─ internal/scanner             # 扫描主流程
└─ web                          # 前端页面与静态资源
```

## 运行要求

- Go `1.26+`

本项目的 `go.mod` 在 `clean-script-go` 目录下，不在仓库根目录。所有 Go 命令都应在 `clean-script-go` 下执行，或者使用 `go -C`。

## 快速开始

### 1. 进入项目目录

```powershell
cd D:\tmp_test\test32523423\clean-script-go
```

### 2. 安装依赖

```powershell
go mod tidy
```

### 3. 启动服务

```powershell
go run ./cmd/server
```

默认监听：

```text
http://0.0.0.0:8000
```

浏览器访问：

```text
http://127.0.0.1:8000
```

### 4. 构建二进制

在 `clean-script-go` 目录内执行：

```powershell
go build -o main.exe ./cmd/server
```

或者从外层目录执行：

```powershell
go build -C D:\tmp_test\test32523423\clean-script-go -o main.exe ./cmd/server
```

不要把输出文件名写成 `main.go`，那是源码扩展名，不适合作为构建产物名。

## 配置文件

默认配置文件为 [config.yaml](D:/tmp_test/test32523423/clean-script-go/config.yaml)：

```yaml
app:
  host: 0.0.0.0
  port: 8000
  read_timeout_seconds: 30
  write_timeout_seconds: 30

scan:
  auth_dir: ./auth
  exceeded_dir: ""
  model: gpt-5.4
  workers: 100
  timeout_seconds: 20
  refresh_before_check: false
  no_quarantine: false
  delete_401: false

http_client:
  codex_base_url: https://chatgpt.com/backend-api/codex
  quota_path: /responses
  refresh_url: https://auth.openai.com/oauth/token
  retry_attempts: 3
  retry_backoff_seconds: 0.6
  client_id: app_EMoamEEZ73f0CkXaXp7hrann
  version: 0.98.0
  user_agent: codex_cli_rs/0.98.0 (go-port)

web:
  allow_origins:
    - "*"
```

### 关键配置解释

- `scan.auth_dir`
  扫描目录。程序会递归查找其中所有 `*.json` 文件。

- `scan.exceeded_dir`
  超限隔离目录。如果为空，程序会自动推导为 `auth_dir` 的同级目录 `exceeded`。

- `scan.model`
  用于探测请求的模型名。

- `scan.workers`
  并发扫描 worker 数量。

- `scan.timeout_seconds`
  单个 refresh 或 probe 请求的超时时间。

- `scan.refresh_before_check`
  是否在检测前使用 `refresh_token` 刷新 access token。

- `scan.no_quarantine`
  是否禁用超限账号隔离与回扫恢复。

- `scan.delete_401`
  扫描完成后是否自动删除首轮扫描出的 `401` 文件。

- `http_client.retry_attempts`
  网络错误时的总重试次数。

- `http_client.retry_backoff_seconds`
  重试退避基础时间，按指数退避递增。

## 扫描流程

1. 递归扫描 `auth_dir` 下所有 `*.json`
2. 判断文件是否像 Codex auth 文件
3. 提取 `provider / email / access_token / refresh_token / account_id / base_url`
4. 可选先刷新 token
5. 发送 probe 请求到 `base_url + quota_path`
6. 判定结果是否为：
   - `401`
   - `quota_exceeded`
   - `no_limit_unlimited`
   - 普通成功
   - 解析/网络错误
7. 如果启用隔离：
   - 把超限文件移到 `exceeded_dir`
   - 再平扫 `exceeded_dir`
   - 对已恢复正常的文件移回 `auth_dir`
8. 如果启用 `delete_401`：
   - 删除首轮扫描得到的 `401` 文件

## HTTP API

### `GET /`

返回 Web 页面。

### `GET /api/config`

返回前端可见的默认扫描配置。

示例响应：

```json
{
  "auth_dir": "./auth",
  "exceeded_dir": "...\u005cexceeded",
  "workers": 100,
  "timeout_seconds": 20,
  "model": "gpt-5.4",
  "refresh_before_check": false,
  "no_quarantine": false,
  "delete_401": false
}
```

### `POST /api/scan`

启动一次后台扫描。

示例请求：

```json
{
  "auth_dir": "./auth",
  "exceeded_dir": "./exceeded",
  "model": "gpt-5.4",
  "workers": 100,
  "timeout_seconds": 20,
  "refresh_before_check": false,
  "no_quarantine": false,
  "delete_401": false
}
```

成功响应：

```json
{
  "ok": true,
  "status": "started"
}
```

如果已经有扫描任务在运行，会返回 `409 Conflict`。

### `GET /api/scan/stream`

SSE 实时推送扫描进度和最终结果。

事件类型：

- `progress`
- `final`
- `error`

`progress` 示例：

```json
{
  "type": "progress",
  "stage": "scan",
  "current": 12,
  "total": 50,
  "filename": "codex-user-12.json"
}
```

`final` 顶层字段：

- `results`
- `exceeded_dir_results`
- `quarantine`
- `deletion`

### `POST /api/delete-401`

手动删除一批文件。删除会校验路径，拒绝删除 `auth_dir` / `exceeded_dir` 外部的文件。

示例请求：

```json
{
  "files": [
    "D:\\auth\\a.json",
    "D:\\auth\\b.json"
  ]
}
```

### `GET /api/status`

返回当前扫描状态：

```json
{
  "running": false,
  "has_result": true
}
```

## Web 界面

页面支持：

- 修改本次扫描参数
- 查看实时进度条
- 查看统计卡片
- 按 `全部 / 401 / 超限 / Unlimited / 错误` 过滤结果
- 查看隔离摘要与删除摘要
- 一键删除当前结果中的 `401` 文件

前端参数只覆盖当前请求，不会回写 `config.yaml`。

## 测试与校验

执行所有测试：

```powershell
go test ./...
```

检查是否可以完整编译：

```powershell
go build ./...
```

当前已覆盖的测试点包括：

- quota exceeded 判定
- unlimited 判定
- 配置合并与 `exceeded_dir` 推导
- auth 字段提取
- 删除操作的目录边界保护

## 注意事项

- 只有“像 Codex auth”的 JSON 文件才会继续被扫描。
- 如果 JSON 解析失败，会在结果中返回 `parse error`。
- 如果缺少 `access_token`，会返回 `missing access token`。
- 如果开启 `refresh_before_check` 但 refresh 失败，该文件会返回 refresh 错误。
- 自动删除 `401` 时只删除首轮扫描识别到的 `401` 文件。
- 手动删除接口也会做路径归一化与白名单校验，避免越界删除。

## 相关源码入口

- 配置加载：[internal/config/config.go](D:/tmp_test/test32523423/clean-script-go/internal/config/config.go)
- 扫描流程：[internal/scanner/service.go](D:/tmp_test/test32523423/clean-script-go/internal/scanner/service.go)
- HTTP API：[internal/httpapi/server.go](D:/tmp_test/test32523423/clean-script-go/internal/httpapi/server.go)
- 文件操作：[internal/fileops/fileops.go](D:/tmp_test/test32523423/clean-script-go/internal/fileops/fileops.go)
