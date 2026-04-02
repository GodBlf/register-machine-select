import { configToSections, defaultBackendConfig } from "../lib/config-schema";
import type { MonitorState } from "../types/runtime";

export const initialConfigSections = configToSections(defaultBackendConfig);

export const initialMonitorState: MonitorState = {
  running: false,
  runMode: "",
  loopRunning: false,
  loopNextCheckInSeconds: null,
  phase: "idle",
  message: "等待任务启动",
  availableCandidates: null,
  availableCandidatesError: "",
  completed: 2,
  total: 20,
  percent: 10,
  stats: [
    { label: "成功", value: 2, icon: "☑", tone: "success" },
    { label: "失败", value: 0, icon: "✕", tone: "danger" },
    { label: "剩余", value: 18, icon: "⏳", tone: "pending" },
  ],
  singleAccountTiming: {
    latestRegSeconds: 15.4,
    latestOauthSeconds: 56.8,
    latestTotalSeconds: 72.2,
    recentAvgRegSeconds: 16.1,
    recentAvgOauthSeconds: 54.3,
    recentAvgTotalSeconds: 70.4,
    recentSlowCount: 1,
    sampleSize: 20,
    windowSize: 20,
  },
  logs: [
    { id: "1", prefix: "[00:28:38] [任务3]", timestamp: "[00:28:38]", message: "提交密码状态: 200", tone: "info" },
    { id: "2", prefix: "[00:28:38] [任务3]", timestamp: "[00:28:38]", message: "9. 发送验证码...", tone: "info" },
    { id: "3", prefix: "[00:28:39] [任务3]", timestamp: "[00:28:39]", message: "验证码发送状态: 200", tone: "info" },
    { id: "4", prefix: "[00:28:39] [任务3]", timestamp: "[00:28:39]", message: "10. 等待验证码...", tone: "info" },
    {
      id: "5",
      prefix: "[00:28:39] [任务3]",
      timestamp: "[00:28:39]",
      message: "正在等待邮箱 dictman3eb8a4@whf.hush2u.com 的验证码...",
      tone: "info",
    },
    { id: "6", prefix: "[00:28:39] [任务3]", timestamp: "[00:28:39]", message: "成功获取验证码: 963817", tone: "success" },
    { id: "7", prefix: "[00:28:40] [任务3]", timestamp: "[00:28:40]", message: "生成用户信息: Charlotte，生日: 1996-01-27", tone: "info" },
    { id: "8", prefix: "[00:28:41] [任务3]", timestamp: "[00:28:41]", message: "Sentinel token 获取成功", tone: "success" },
    { id: "9", prefix: "[00:28:44] [任务3]", timestamp: "[00:28:44]", message: "OAuth 登录链路进入 consent 阶段", tone: "success" },
  ],
};
