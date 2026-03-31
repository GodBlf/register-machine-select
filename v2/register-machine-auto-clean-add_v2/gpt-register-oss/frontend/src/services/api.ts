import { configToSections, normalizeBackendConfig, sectionsToConfig } from "../lib/config-schema";
import type {
  AuthState,
  BackendConfig,
  RuntimeStatusResponse,
  StartRuntimeResponse,
  StopRuntimeResponse,
} from "../types/api";
import type { ConfigSection, MonitorState } from "../types/runtime";

const AUTH_STORAGE_KEY = "apm_admin_token";

export function getStoredAuth(): AuthState {
  return {
    token: window.sessionStorage.getItem(AUTH_STORAGE_KEY) ?? "",
  };
}

export function storeAuthToken(token: string): void {
  window.sessionStorage.setItem(AUTH_STORAGE_KEY, token);
}

export function clearAuthToken(): void {
  window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
}

export class ApiRequestError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
  }
}

export function isAuthError(error: unknown): boolean {
  return error instanceof ApiRequestError && (error.status === 401 || error.status === 403);
}

async function getJson<T>(path: string, init?: RequestInit, token?: string): Promise<T> {
  const adminToken = token ?? getStoredAuth().token;
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(adminToken ? { "X-Admin-Token": adminToken } : {}),
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw new ApiRequestError(`${init?.method ?? "GET"} ${path} failed: ${response.status}`, response.status);
  }

  return (await response.json()) as T;
}

export async function verifyAuthToken(token: string): Promise<void> {
  await getJson<{ ok: boolean; time: string }>("/api/health", undefined, token);
  await getJson<Partial<BackendConfig>>("/api/config", undefined, token);
}

export async function fetchConfig(): Promise<ConfigSection[]> {
  const config = await getJson<Partial<BackendConfig>>("/api/config");
  return configToSections(normalizeBackendConfig(config));
}

export async function saveConfig(sections: ConfigSection[]): Promise<ConfigSection[]> {
  const saved = await getJson<BackendConfig>("/api/config", {
    method: "POST",
    body: JSON.stringify(sectionsToConfig(sections)),
  });
  return configToSections(normalizeBackendConfig(saved));
}

export async function fetchMonitorState(): Promise<MonitorState> {
  const status = await getJson<RuntimeStatusResponse>("/api/runtime/status");
  const timing = status.single_account_timing;
  return {
    running: status.running,
    runMode: status.run_mode ?? "",
    loopRunning: status.loop_running ?? false,
    loopNextCheckInSeconds: status.loop_next_check_in_seconds ?? null,
    phase: status.phase,
    message: status.message,
    availableCandidates: status.available_candidates,
    availableCandidatesError: status.available_candidates_error,
    completed: status.completed,
    total: status.total,
    percent: status.percent,
    stats: status.stats,
    singleAccountTiming: {
      latestRegSeconds: timing?.latest_reg_seconds ?? null,
      latestOauthSeconds: timing?.latest_oauth_seconds ?? null,
      latestTotalSeconds: timing?.latest_total_seconds ?? null,
      recentAvgRegSeconds: timing?.recent_avg_reg_seconds ?? null,
      recentAvgOauthSeconds: timing?.recent_avg_oauth_seconds ?? null,
      recentAvgTotalSeconds: timing?.recent_avg_total_seconds ?? null,
      recentSlowCount: timing?.recent_slow_count ?? 0,
      sampleSize: timing?.sample_size ?? 0,
      windowSize: timing?.window_size ?? 20,
    },
    logs: status.logs,
  };
}

export async function startRuntime(): Promise<StartRuntimeResponse> {
  return getJson<StartRuntimeResponse>("/api/runtime/start", {
    method: "POST",
    body: "{}",
  });
}

export async function startRuntimeLoop(): Promise<StartRuntimeResponse> {
  return getJson<StartRuntimeResponse>("/api/runtime/start-loop", {
    method: "POST",
    body: "{}",
  });
}

export async function stopRuntime(): Promise<StopRuntimeResponse> {
  return getJson<StopRuntimeResponse>("/api/runtime/stop", {
    method: "POST",
    body: "{}",
  });
}
