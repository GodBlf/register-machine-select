import { useState } from "preact/hooks";

type LoginGateProps = {
  busy?: boolean;
  error?: string;
  onSubmit: (token: string) => Promise<void>;
};

export function LoginGate(props: LoginGateProps) {
  const { busy = false, error = "", onSubmit } = props;
  const [token, setToken] = useState("");

  const handleSubmit = async (event: Event) => {
    event.preventDefault();
    await onSubmit(token.trim());
  };

  return (
    <div class="login-shell">
      <form class="login-card" onSubmit={handleSubmit}>
        <div class="login-title">管理登录</div>
        <div class="login-subtitle">请输入管理令牌以访问控制台</div>
        <label class="field">
          <span class="field-label">Admin Token</span>
          <input
            type="password"
            value={token}
            onInput={(event) => setToken((event.currentTarget as HTMLInputElement).value)}
            placeholder="请输入 X-Admin-Token"
          />
        </label>
        {error ? <div class="login-error">{error}</div> : null}
        <button class="button primary login-button" type="submit" disabled={busy || !token.trim()}>
          {busy ? "验证中..." : "进入控制台"}
        </button>
      </form>
    </div>
  );
}
