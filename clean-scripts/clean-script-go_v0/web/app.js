const state = {
  results: [],
  filter: "all",
  scanning: false,
  deletion: null,
  quarantine: null,
  eventSource: null,
};

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await loadConfig();
});

function bindEvents() {
  document.getElementById("scan-button").addEventListener("click", startScan);
  document.getElementById("delete-button").addEventListener("click", deleteCurrent401);
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      document.querySelectorAll("[data-filter]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      renderResults();
    });
  });
}

async function loadConfig() {
  const response = await fetch("/api/config");
  const config = await response.json();
  setField("auth_dir", config.auth_dir);
  setField("exceeded_dir", config.exceeded_dir);
  setField("model", config.model);
  setField("workers", config.workers);
  setField("timeout_seconds", config.timeout_seconds);
  setChecked("refresh_before_check", config.refresh_before_check);
  setChecked("no_quarantine", config.no_quarantine);
  setChecked("delete_401", config.delete_401);
}

async function startScan() {
  if (state.scanning) {
    return;
  }

  state.scanning = true;
  state.results = [];
  state.deletion = null;
  state.quarantine = null;
  updateStats();
  renderResults();
  renderSummaries();
  setError("");
  setRunState("扫描中", true);
  setProgress("准备扫描", 0, 0);

  const payload = {
    auth_dir: getField("auth_dir"),
    exceeded_dir: getField("exceeded_dir"),
    model: getField("model"),
    workers: Number(getField("workers")),
    timeout_seconds: Number(getField("timeout_seconds")),
    refresh_before_check: getChecked("refresh_before_check"),
    no_quarantine: getChecked("no_quarantine"),
    delete_401: getChecked("delete_401"),
  };

  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    setError(body.detail || body.error || response.statusText);
    setRunState("启动失败", false);
    state.scanning = false;
    return;
  }

  subscribeEvents();
}

function subscribeEvents() {
  if (state.eventSource) {
    state.eventSource.close();
  }

  const source = new EventSource("/api/scan/stream");
  state.eventSource = source;

  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === "progress") {
      const stageLabel = data.stage === "recovery" ? "回扫 exceeded" : "扫描 auth";
      setProgress(`${stageLabel}: ${data.filename || "处理中"}`, data.current, data.total);
      return;
    }
    if (data.type === "error") {
      state.scanning = false;
      setRunState("任务失败", false);
      setError(data.message || "未知错误");
      source.close();
      return;
    }
    if (data.type === "final") {
      state.scanning = false;
      state.results = Array.isArray(data.results) ? data.results : [];
      state.deletion = data.deletion || null;
      state.quarantine = data.quarantine || null;
      setRunState("已完成", false);
      setProgress("扫描完成", state.results.length, state.results.length);
      setError("");
      document.getElementById("last-scan").textContent = `最近扫描: ${new Date().toLocaleString()}`;
      updateStats();
      renderResults();
      renderSummaries();
      source.close();
    }
  };

  source.onerror = () => {
    if (!state.scanning) {
      return;
    }
    state.scanning = false;
    setRunState("连接断开", false);
    setError("SSE 连接断开");
    source.close();
  };
}

function updateStats() {
  const stats = {
    total: state.results.length,
    unauthorized: state.results.filter((item) => item.unauthorized_401).length,
    exceeded: state.results.filter((item) => item.quota_exceeded && !item.unauthorized_401).length,
    unlimited: state.results.filter((item) => item.no_limit_unlimited).length,
    errors: state.results.filter((item) => item.error && !item.unauthorized_401 && !item.quota_exceeded).length,
  };

  setText("stat-total", stats.total);
  setText("stat-401", stats.unauthorized);
  setText("stat-exceeded", stats.exceeded);
  setText("stat-unlimited", stats.unlimited);
  setText("stat-errors", stats.errors);

  const deleteButton = document.getElementById("delete-button");
  deleteButton.disabled = stats.unauthorized === 0 || state.scanning;
}

function renderSummaries() {
  const quarantineText = state.quarantine
    ? state.quarantine.enabled
      ? `移入 exceeded: ${state.quarantine.moved_to_exceeded.length}，恢复回 auth: ${state.quarantine.moved_from_exceeded.length}，失败: ${(state.quarantine.moved_to_exceeded_errors || []).length + (state.quarantine.moved_from_exceeded_errors || []).length}`
      : "本次扫描已禁用超限隔离"
    : "尚无数据";

  const deletionText = state.deletion
    ? state.deletion.requested
      ? `目标 ${state.deletion.target_count}，已删 ${state.deletion.deleted_count}，失败 ${(state.deletion.errors || []).length}`
      : "本次扫描未启用自动删除"
    : "尚无数据";

  document.getElementById("quarantine-summary").textContent = quarantineText;
  document.getElementById("delete-summary").textContent = deletionText;
}

function renderResults() {
  const body = document.getElementById("results-body");
  const rows = filteredResults();
  if (rows.length === 0) {
    body.innerHTML = `<tr><td colspan="6" class="empty">暂无结果</td></tr>`;
    return;
  }

  body.innerHTML = rows
    .map((item) => {
      const status = statusMeta(item);
      const resetAt = item.quota_resets_at ? new Date(item.quota_resets_at * 1000).toLocaleString() : "—";
      const detail = item.error || item.response_preview || "";
      return `
        <tr>
          <td><span class="status-badge ${status.className}">${status.label}</span></td>
          <td class="mono">${escapeHtml(item.file || "")}</td>
          <td>${escapeHtml(item.email || "—")}</td>
          <td class="mono">${escapeHtml(item.account_id || "—")}</td>
          <td>${escapeHtml(resetAt)}</td>
          <td>${escapeHtml(detail)}</td>
        </tr>
      `;
    })
    .join("");
}

function filteredResults() {
  switch (state.filter) {
    case "401":
      return state.results.filter((item) => item.unauthorized_401);
    case "exceeded":
      return state.results.filter((item) => item.quota_exceeded && !item.unauthorized_401);
    case "unlimited":
      return state.results.filter((item) => item.no_limit_unlimited);
    case "errors":
      return state.results.filter((item) => item.error && !item.unauthorized_401 && !item.quota_exceeded);
    default:
      return state.results;
  }
}

function statusMeta(item) {
  if (item.unauthorized_401) {
    return { label: "401", className: "red" };
  }
  if (item.quota_exceeded) {
    return { label: "LIM", className: "gold" };
  }
  if (item.error) {
    return { label: "ERR", className: "slate" };
  }
  if (item.no_limit_unlimited) {
    return { label: "INF", className: "green" };
  }
  return { label: String(item.status_code || "?"), className: "slate" };
}

async function deleteCurrent401() {
  const files = state.results.filter((item) => item.unauthorized_401).map((item) => item.file);
  if (files.length === 0) {
    return;
  }

  const response = await fetch("/api/delete-401", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ files }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setError(payload.detail || payload.error || "删除失败");
    return;
  }

  state.results = state.results.filter((item) => !item.unauthorized_401);
  state.deletion = {
    requested: true,
    target_count: files.length,
    confirmed: true,
    deleted_count: payload.deleted_count || 0,
    deleted_files: payload.deleted_files || [],
    errors: payload.errors || [],
  };
  updateStats();
  renderResults();
  renderSummaries();
}

function setRunState(text, scanning) {
  state.scanning = scanning;
  document.getElementById("run-state").textContent = text;
  document.getElementById("scan-button").disabled = scanning;
  document.getElementById("delete-button").disabled = scanning || state.results.filter((item) => item.unauthorized_401).length === 0;
}

function setProgress(label, current, total) {
  document.getElementById("progress-label").textContent = label;
  document.getElementById("progress-count").textContent = `${current} / ${total}`;
  const width = total > 0 ? Math.round((current / total) * 100) : 0;
  document.getElementById("progress-fill").style.width = `${width}%`;
}

function setError(message) {
  const el = document.getElementById("error-banner");
  if (!message) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = message;
  el.classList.remove("hidden");
}

function setField(id, value) {
  document.getElementById(id).value = value ?? "";
}

function getField(id) {
  return document.getElementById(id).value.trim();
}

function setChecked(id, value) {
  document.getElementById(id).checked = Boolean(value);
}

function getChecked(id) {
  return document.getElementById(id).checked;
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
