# Frontend Scaffold

轻量前端脚手架，技术选型：

- `Vite`
- `Preact`
- `TypeScript`
- 手写 `CSS`

## 启动

```bash
cd /home/zhang/workspace/script/auto_pool_maintainer_duckMail
python3 api_server.py
```

另一个终端：

```bash
cd frontend
npm install
npm run dev
```

生产构建：

```bash
cd frontend
npm run build
```

## 一键管理三端

项目根目录提供了统一脚本：

```bash
./dev_services.sh fg
```

前台托管三个服务，按 `Ctrl+C` 会一起关闭。

```bash
./dev_services.sh bg
./dev_services.sh status
./dev_services.sh stop
```

后台启动、查看状态、停止服务都可以直接用上面三条命令。
后台日志和 PID 会写到 `logs/dev-services/`。

## 结构

- `src/app.tsx`: 页面入口
- `src/components/`: 配置面板、监控台、日志终端、账号表格
- `src/mock/data.ts`: 当前假数据
- `src/services/`: 后续接后端 API / SSE 的位置
- `src/types/`: 前端状态类型定义
- `src/styles/`: 设计变量和页面样式

## 当前状态

- 已将现有静态 UI 迁为前端组件结构
- `config` 已接到真实后端接口：`GET/POST /api/config`
- `runtime status` 已接到真实后端接口：`GET /api/runtime/status`
- 账号表格仍使用本地假数据
