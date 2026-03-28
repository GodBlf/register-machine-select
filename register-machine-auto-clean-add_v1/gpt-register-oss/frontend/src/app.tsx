import { useEffect, useState } from "preact/hooks";
import { ConfigPanel } from "./components/config-panel";
import { LoginGate } from "./components/login-gate";
import { MonitorPanel } from "./components/monitor-panel";
import { initialConfigSections, initialMonitorState } from "./mock/data";
import {
  clearAuthToken,
  fetchConfig,
  fetchMonitorState,
  getStoredAuth,
  isAuthError,
  saveConfig,
  startRuntime,
  startRuntimeLoop,
  stopRuntime,
  storeAuthToken,
  verifyAuthToken,
} from "./services/api";
import type { ConfigSection, MonitorState } from "./types/runtime";

export function App() {
  const [sections, setSections] = useState<ConfigSection[]>(initialConfigSections);
  const [monitor, setMonitor] = useState<MonitorState>(initialMonitorState);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string>("");
  const [authenticated, setAuthenticated] = useState<boolean>(Boolean(getStoredAuth().token));
  const [authError, setAuthError] = useState("");
  const [hasStoredToken, setHasStoredToken] = useState<boolean>(Boolean(getStoredAuth().token));

  const refreshMonitor = async () => {
    const nextMonitor = await fetchMonitorState();
    setMonitor(nextMonitor);
  };

  useEffect(() => {
    let active = true;

    fetchConfig()
      .then((nextSections) => {
        if (active) {
          setSections(nextSections);
          setAuthenticated(true);
        }
      })
      .catch((error) => {
        if (active) {
          if (isAuthError(error)) {
            clearAuthToken();
            setHasStoredToken(false);
            setAuthError("登录已失效，请重新输入管理令牌");
          }
          setAuthenticated(false);
        }
      });

    refreshMonitor()
      .then(() => {
        if (active) {
          setNotice("");
        }
      })
      .catch((error) => {
        if (active && isAuthError(error)) {
          clearAuthToken();
          setHasStoredToken(false);
          setAuthenticated(false);
          setAuthError("登录已失效，请重新输入管理令牌");
        }
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!authenticated) {
      return;
    }

    let active = true;

    const timer = window.setInterval(() => {
      refreshMonitor()
        .then(() => {
          if (active) {
            setNotice((current) => current);
          }
        })
        .catch((error) => {
          if (active && isAuthError(error)) {
            clearAuthToken();
            setHasStoredToken(false);
            setAuthenticated(false);
            setAuthError("登录已失效，请重新输入管理令牌");
          }
        });
    }, 5000);

    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [authenticated]);

  const handleLogin = async (token: string) => {
    setBusy(true);
    setAuthError("");
    try {
      await verifyAuthToken(token);
      storeAuthToken(token);
      setAuthenticated(true);
      setHasStoredToken(true);
      setNotice("登录成功");
      const [nextSections, nextMonitor] = await Promise.all([fetchConfig(), fetchMonitorState()]);
      setSections(nextSections);
      setMonitor(nextMonitor);
    } catch (error) {
      console.error("登录失败", error);
      clearAuthToken();
      setAuthenticated(false);
      setHasStoredToken(false);
      setAuthError("管理令牌无效或服务暂不可用");
    } finally {
      setBusy(false);
    }
  };

  const handleLogout = () => {
    clearAuthToken();
    setAuthenticated(false);
    setHasStoredToken(false);
    setNotice("已退出登录");
    setAuthError("");
  };

  const updateFieldValue = (sectionKey: string, fieldKey: string, nextValue: string | number | boolean) => {
    setSections((current) =>
      current.map((section) => {
        if (section.key !== sectionKey) {
          return section;
        }
        return {
          ...section,
          fields: section.fields.map((field) =>
            field.key === fieldKey ? { ...field, value: nextValue } : field,
          ),
        };
      }),
    );
  };

  const handleClearLogs = () => {
    setMonitor((current) => ({
      ...current,
      logs: [
        {
          id: "cleared",
          prefix: "[系统] [00:00:00]",
          timestamp: "[00:00:00]",
          message: "日志已清空，等待任务输出...",
          tone: "muted",
        },
      ],
    }));
  };

  const handleSaveConfig = async () => {
    setBusy(true);
    try {
      const savedSections = await saveConfig(sections);
      setSections(savedSections);
      setNotice("配置已保存");
    } catch (error) {
      console.error("保存配置失败", error);
      if (isAuthError(error)) {
        clearAuthToken();
        setHasStoredToken(false);
        setAuthenticated(false);
        setAuthError("登录已失效，请重新输入管理令牌");
      } else {
        setNotice("保存配置失败");
      }
    } finally {
      setBusy(false);
    }
  };

  const handleStartRuntime = async () => {
    setBusy(true);
    try {
      const savedSections = await saveConfig(sections);
      setSections(savedSections);
      const result = await startRuntime();
      setNotice(`配置已保存，${result.message}`);
      await refreshMonitor();
    } catch (error) {
      console.error("保存配置或启动维护任务失败", error);
      if (isAuthError(error)) {
        clearAuthToken();
        setHasStoredToken(false);
        setAuthenticated(false);
        setAuthError("登录已失效，请重新输入管理令牌");
      } else {
        setNotice("保存配置或启动维护任务失败");
      }
    } finally {
      setBusy(false);
    }
  };

  const handleStopRuntime = async () => {
    setBusy(true);
    try {
      const result = await stopRuntime();
      setNotice(result.message);
      await refreshMonitor();
    } catch (error) {
      console.error("停止维护任务失败", error);
      if (isAuthError(error)) {
        clearAuthToken();
        setHasStoredToken(false);
        setAuthenticated(false);
        setAuthError("登录已失效，请重新输入管理令牌");
      } else {
        setNotice("停止维护任务失败");
      }
    } finally {
      setBusy(false);
    }
  };

  const handleStartRuntimeLoop = async () => {
    setBusy(true);
    try {
      const savedSections = await saveConfig(sections);
      setSections(savedSections);
      const result = await startRuntimeLoop();
      setNotice(`配置已保存，${result.message}`);
      await refreshMonitor();
    } catch (error) {
      console.error("保存配置或启动循环补号任务失败", error);
      if (isAuthError(error)) {
        clearAuthToken();
        setHasStoredToken(false);
        setAuthenticated(false);
        setAuthError("登录已失效，请重新输入管理令牌");
      } else {
        setNotice("保存配置或启动循环补号任务失败");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="page-shell">
      {!authenticated ? <LoginGate busy={busy} error={authError} onSubmit={handleLogin} /> : null}
      {authenticated ? (
        <>
      {notice ? <div class="page-notice">{notice}</div> : null}
      <div class="page-grid">
        <ConfigPanel
          sections={sections}
          onValueChange={updateFieldValue}
          onSave={handleSaveConfig}
          onStart={handleStartRuntime}
          onStartLoop={handleStartRuntimeLoop}
          onStop={handleStopRuntime}
          onLogout={handleLogout}
          busy={busy}
          running={monitor.running}
          loopRunning={Boolean(monitor.loopRunning)}
          hasStoredToken={hasStoredToken}
        />
        <div class="main-stack">
          <MonitorPanel monitor={monitor} onClearLogs={handleClearLogs} />
        </div>
      </div>
        </>
      ) : null}
    </div>
  );
}
