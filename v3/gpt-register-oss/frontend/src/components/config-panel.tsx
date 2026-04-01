import { useEffect, useState } from "preact/hooks";
import type { ConfigField, ConfigSection } from "../types/runtime";

type ConfigPanelProps = {
  sections: ConfigSection[];
  onValueChange: (sectionKey: string, fieldKey: string, nextValue: string | number | boolean) => void;
  onSave: () => void;
  onStart: () => void;
  onStartLoop: () => void;
  onStop: () => void;
  onLogout: () => void;
  busy?: boolean;
  running?: boolean;
  loopRunning?: boolean;
  hasStoredToken?: boolean;
};

type ConfigCategory = "common" | "mail" | "advanced";

function FieldControl(props: {
  sectionKey: string;
  field: ConfigField;
  onValueChange: ConfigPanelProps["onValueChange"];
}) {
  const { sectionKey, field, onValueChange } = props;

  if (field.type === "select") {
    return (
      <select
        value={String(field.value)}
        onInput={(event) =>
          onValueChange(sectionKey, field.key, (event.currentTarget as HTMLSelectElement).value)
        }
      >
        {(field.options ?? []).map((option) => (
          <option value={option.value} key={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    );
  }

  if (field.type === "checkbox") {
    return (
      <label class="check-row">
        <input
          type="checkbox"
          checked={Boolean(field.value)}
          onInput={(event) =>
            onValueChange(sectionKey, field.key, (event.currentTarget as HTMLInputElement).checked)
          }
        />
        <span>
          {field.label} <span class="field-key">{field.key}</span>
        </span>
      </label>
    );
  }

  if (field.type === "textarea") {
    return (
      <textarea
        value={String(field.value)}
        onInput={(event) =>
          onValueChange(sectionKey, field.key, (event.currentTarget as HTMLTextAreaElement).value)
        }
      />
    );
  }

  return (
    <input
      type={field.type}
      value={String(field.value)}
      placeholder={field.sensitive && String(field.value) === "__MASKED__" ? "已保存，留空或保持不变将沿用原值" : ""}
      onInput={(event) => {
        const target = event.currentTarget as HTMLInputElement;
        const nextValue = field.type === "number" ? Number(target.value) : target.value;
        onValueChange(sectionKey, field.key, nextValue);
      }}
    />
  );
}

export function ConfigPanel(props: ConfigPanelProps) {
  const {
    sections,
    onValueChange,
    onSave,
    onStart,
    onStartLoop,
    onStop,
    onLogout,
    busy = false,
    running = false,
    loopRunning = false,
    hasStoredToken = false,
  } = props;
  const [activeCategory, setActiveCategory] = useState<ConfigCategory>("common");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    priority: true,
    clean: false,
    mail: true,
    cfmail: false,
    self_hosted_mail_api: false,
    duckmail: false,
    tempmail_lol: false,
    yyds_mail: false,
    run: false,
    registration: false,
    flow: false,
    oauth: false,
    output: false,
  });

  const sectionCategoryMap: Record<string, ConfigCategory> = {
    priority: "common",
    clean: "common",
    mail: "mail",
    cfmail: "mail",
    self_hosted_mail_api: "mail",
    duckmail: "mail",
    tempmail_lol: "mail",
    yyds_mail: "mail",
    run: "advanced",
    registration: "advanced",
    flow: "advanced",
    oauth: "advanced",
    output: "advanced",
  };

  const categoryLabelMap: Record<ConfigCategory, string> = {
    common: "常用",
    mail: "邮箱",
    advanced: "高级",
  };

  const selectedProvider =
    sections.find((section) => section.key === "mail")?.fields.find((field) => field.key === "provider")?.value ??
    "self_hosted_mail_api";

  const providerLabelMap: Record<string, string> = {
    cfmail: "CF Mail",
    self_hosted_mail_api: "自建 Mail API",
    duckmail: "DuckMail",
    tempmail_lol: "TempMail.lol",
    yyds_mail: "YYDS Mail",
  };

  const visibleSections = sections.filter((section) => {
    if (sectionCategoryMap[section.key] !== activeCategory) {
      return false;
    }
    if (section.key === "self_hosted_mail_api") {
      return selectedProvider === "self_hosted_mail_api";
    }
    if (section.key === "cfmail") {
      return selectedProvider === "cfmail";
    }
    if (section.key === "duckmail") {
      return selectedProvider === "duckmail";
    }
    if (section.key === "tempmail_lol") {
      return selectedProvider === "tempmail_lol";
    }
    if (section.key === "yyds_mail") {
      return selectedProvider === "yyds_mail";
    }
    return true;
  });

  const summaryItems = [
    {
      label: "当前邮箱",
      value: providerLabelMap[String(selectedProvider)] ?? String(selectedProvider),
    },
    {
      label: "维护目标",
      value: String(
        sections.find((section) => section.key === "priority")?.fields.find((field) => field.key === "min_candidates")
          ?.value ??
          "",
      ),
    },
    {
      label: "补号并发",
      value: String(
        sections.find((section) => section.key === "run")?.fields.find((field) => field.key === "workers")?.value ?? "",
      ),
    },
  ];

  const toggleSection = (sectionKey: string) => {
    setExpandedSections((current) => ({
      ...current,
      [sectionKey]: !(current[sectionKey] ?? false),
    }));
  };

  useEffect(() => {
    if (
      selectedProvider === "cfmail" ||
      selectedProvider === "self_hosted_mail_api" ||
      selectedProvider === "duckmail" ||
      selectedProvider === "tempmail_lol" ||
      selectedProvider === "yyds_mail"
    ) {
      setExpandedSections((current) => ({
        ...current,
        [String(selectedProvider)]: true,
      }));
    }
  }, [selectedProvider]);

  useEffect(() => {
    if (activeCategory === "mail") {
      return;
    }

    if (
      selectedProvider === "cfmail" ||
      selectedProvider === "self_hosted_mail_api" ||
      selectedProvider === "duckmail" ||
      selectedProvider === "tempmail_lol" ||
      selectedProvider === "yyds_mail"
    ) {
      setExpandedSections((current) => ({
        ...current,
        [String(selectedProvider)]: true,
      }));
    }
  }, [activeCategory, selectedProvider]);

  return (
    <aside class="card settings-card">
      <div class="card-head">
        <div class="card-title">
          <span class="title-icon">📝</span>
          <span>维护配置</span>
        </div>
        {hasStoredToken ? (
          <button class="link-button" type="button" onClick={onLogout}>
            退出登录
          </button>
        ) : null}
      </div>

      <div class="settings-body">
        <div class="settings-summary">
          {summaryItems.map((item) => (
            <div class="summary-chip" key={item.label}>
              <span class="summary-label">{item.label}</span>
              <span class="summary-value">{item.value}</span>
            </div>
          ))}
        </div>

        <div class="settings-tabs">
          {(Object.keys(categoryLabelMap) as ConfigCategory[]).map((category) => (
            <button
              key={category}
              type="button"
              class={`settings-tab${activeCategory === category ? " active" : ""}`}
              onClick={() => setActiveCategory(category)}
            >
              {categoryLabelMap[category]}
            </button>
          ))}
        </div>

        {visibleSections.map((section) => {
          const isExpanded = expandedSections[section.key] ?? false;

          return (
            <section class={`config-group${isExpanded ? " expanded" : ""}`} key={section.key}>
              <button class="group-toggle" type="button" onClick={() => toggleSection(section.key)}>
                <span class="group-title">
                  {section.label}
                  <span class="group-key">{section.key}</span>
                </span>
                <span class={`group-caret${isExpanded ? " open" : ""}`}>⌄</span>
              </button>

              {isExpanded ? (
                <div class="group-content field-row single-col">
                  {section.fields.map((field) => (
                    <label class={`field${field.type === "checkbox" ? " checkbox-group compact" : ""}`} key={field.key}>
                      {field.type !== "checkbox" ? (
                        <span class="field-label">
                          {field.label}
                          <span class="field-key">{field.key}</span>
                        </span>
                      ) : null}
                      <FieldControl sectionKey={section.key} field={field} onValueChange={onValueChange} />
                      {field.hint ? <span class="field-hint">{field.hint}</span> : null}
                    </label>
                  ))}
                </div>
              ) : null}
            </section>
          );
        })}

        <div class="settings-actions">
          <button class="button primary" type="button" onClick={onStart} disabled={busy || running}>
            开始维护
          </button>
          <button class="button primary" type="button" onClick={onStartLoop} disabled={busy || running}>
            {loopRunning ? "循环补号运行中" : "循环补号"}
          </button>
          <button class="button warning" type="button" onClick={onStop} disabled={busy || !running}>
            停止维护
          </button>
          <button class="button secondary" type="button" onClick={onSave} disabled={busy}>
            保存配置
          </button>
        </div>
      </div>
    </aside>
  );
}
