import { TerminalLog } from "./terminal-log";
import type { MonitorState } from "../types/runtime";

type MonitorPanelProps = {
  monitor: MonitorState;
  onClearLogs: () => void;
};

export function MonitorPanel(props: MonitorPanelProps) {
  const { monitor, onClearLogs } = props;
  const successCount = monitor.stats.find((item) => item.tone === "success")?.value ?? 0;
  const failedCount = monitor.stats.find((item) => item.tone === "danger")?.value ?? 0;
  const pendingFromStats = monitor.stats.find((item) => item.tone === "pending")?.value ?? 0;
  const pendingCount = Math.max(0, Math.max(pendingFromStats, monitor.total - successCount));
  const timing = monitor.singleAccountTiming;
  const displaySeconds = (value: number | null): string => (typeof value === "number" ? `${value.toFixed(1)}s` : "--");
  const loopRemain = monitor.loopNextCheckInSeconds;
  const runtimeModeText = monitor.loopRunning ? "循环补号" : monitor.running ? "单次维护" : "未运行";
  const loopRemainText = typeof loopRemain === "number" ? `${Math.max(0, loopRemain)}s` : "--";

  return (
    <section class="card monitor-card">
      <div class="card-head">
        <div class="card-title">
          <span class="title-icon">💻</span>
          <span>监控台</span>
        </div>
        <button class="link-button" type="button" onClick={onClearLogs}>
          清空
        </button>
      </div>

      <div class="monitor-body">
        <div class={`runtime-banner ${monitor.running ? "active" : ""}`}>
          <span class="runtime-dot" />
          <span>{monitor.message}</span>
        </div>

        <div class="runtime-mode-banner">
          <span class="runtime-mode-label">运行模式</span>
          <span class="runtime-mode-value">{runtimeModeText}</span>
          {monitor.loopRunning ? (
            <span class="runtime-mode-next">下次检查: {loopRemainText}</span>
          ) : null}
        </div>

        <div class="inventory-banner">
          <span class="inventory-label">CPA 可用账号</span>
          <span class="inventory-value">
            {monitor.availableCandidates === null ? "--" : monitor.availableCandidates}
          </span>
        </div>

        <div class="progress-head">
          <div class="progress-title">补号进度</div>
          <div class="progress-meta">
            <span>
              已补 {successCount} / 目标 {monitor.total}
            </span>
            <span>{monitor.percent}%</span>
          </div>
        </div>

        <div class="progress-track">
          <div class="progress-value" style={{ width: `${monitor.percent}%` }} />
        </div>

        <div class="stat-strip">
          <div class="mini-stat success">
            <span class="mini-stat-label">补号成功</span>
            <span class="mini-stat-value">{successCount}</span>
          </div>
          <div class="mini-stat danger">
            <span class="mini-stat-label">补号失败</span>
            <span class="mini-stat-value">{failedCount}</span>
          </div>
          <div class="mini-stat pending">
            <span class="mini-stat-label">待补数量</span>
            <span class="mini-stat-value">{pendingCount}</span>
          </div>
        </div>

        <div class="timing-strip">
          <div class="timing-item">
            <span class="timing-label">最近单号总耗时</span>
            <span class="timing-value">{displaySeconds(timing.latestTotalSeconds)}</span>
          </div>
          <div class="timing-item">
            <span class="timing-label">最近单号注册/OAuth</span>
            <span class="timing-value">
              {displaySeconds(timing.latestRegSeconds)} / {displaySeconds(timing.latestOauthSeconds)}
            </span>
          </div>
          <div class="timing-item">
            <span class="timing-label">近{timing.windowSize}条均值(总)</span>
            <span class="timing-value">{displaySeconds(timing.recentAvgTotalSeconds)}</span>
          </div>
          <div class="timing-item">
            <span class="timing-label">慢号(≥100s)</span>
            <span class="timing-value">
              {timing.recentSlowCount} / {timing.sampleSize}
            </span>
          </div>
        </div>

        <TerminalLog lines={monitor.logs} />
      </div>
    </section>
  );
}
