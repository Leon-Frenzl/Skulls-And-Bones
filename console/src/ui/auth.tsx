"use client";

import {
  useState,
  type FormEvent,
  type ReactNode,
  type CSSProperties,
} from "react";

export interface AuthThemeProps {
  primaryColor?: string;
  backgroundColor?: string;
  cardBackground?: string;
  textColor?: string;
  borderColor?: string;
}

export interface AuthCardProps {
  title?: string;
  subtitle?: string;
  logoText?: string;
  theme?: AuthThemeProps;
  children: ReactNode;
  className?: string;
}

export function AuthCard({
  title = "SKULLS & BONES",
  subtitle = "Sovereign Authentication Gateway",
  logoText = "S&B AUTH",
  theme,
  children,
  className = "",
}: AuthCardProps) {
  const styleVars: CSSProperties & Record<string, string> = {
    "--sba-primary": theme?.primaryColor || "#00f0ff",
    "--sba-bg": theme?.backgroundColor || "#0b0b0d",
    "--sba-card": theme?.cardBackground || "#141418",
    "--sba-text": theme?.textColor || "#e6e6e6",
    "--sba-border": theme?.borderColor || "#26262e",
  };

  return (
    <div
      style={styleVars}
      className={`sba-card-container ${className}`}
    >
      <div className="sba-card">
        <div className="sba-header">
          {logoText && <div className="sba-logo">{logoText}</div>}
          <h1 className="sba-title">{title}</h1>
          {subtitle && <p className="sba-subtitle">{subtitle}</p>}
        </div>
        {children}
      </div>
      <style>{`
        .sba-card-container {
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100%;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          color: var(--sba-text);
        }
        .sba-card {
          background: var(--sba-card);
          border: 1px solid var(--sba-border);
          border-radius: 8px;
          width: 100%;
          max-width: 420px;
          padding: 2.25rem;
          box-shadow: 0 8px 32px rgba(0,0,0,0.6);
          position: relative;
          overflow: hidden;
        }
        .sba-card::before {
          content: "";
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 3px;
          background: var(--sba-primary);
        }
        .sba-header {
          text-align: center;
          margin-bottom: 2rem;
        }
        .sba-logo {
          display: inline-block;
          font-weight: 800;
          letter-spacing: 2px;
          color: var(--sba-primary);
          border: 1px solid var(--sba-primary);
          padding: 0.25rem 0.75rem;
          border-radius: 4px;
          margin-bottom: 1rem;
          font-size: 0.85rem;
        }
        .sba-title {
          font-size: 1.25rem;
          font-weight: 700;
          letter-spacing: 1px;
          margin-bottom: 0.25rem;
        }
        .sba-subtitle {
          font-size: 0.8rem;
          opacity: 0.6;
        }
        .sba-form-group {
          margin-bottom: 1.25rem;
        }
        .sba-label {
          display: block;
          font-size: 0.75rem;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 0.4rem;
          opacity: 0.8;
        }
        .sba-input {
          width: 100%;
          background: rgba(0,0,0,0.3);
          border: 1px solid var(--sba-border);
          color: var(--sba-text);
          font-family: inherit;
          padding: 0.75rem 0.9rem;
          border-radius: 4px;
          font-size: 0.9rem;
          transition: border 0.2s;
        }
        .sba-input:focus {
          outline: none;
          border-color: var(--sba-primary);
        }
        .sba-btn {
          width: 100%;
          background: var(--sba-primary);
          color: #000;
          font-family: inherit;
          font-weight: 700;
          letter-spacing: 1px;
          text-transform: uppercase;
          padding: 0.85rem;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          margin-top: 0.5rem;
          transition: opacity 0.2s;
        }
        .sba-btn:hover { opacity: 0.9; }
        .sba-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .sba-alert {
          margin-top: 1rem;
          padding: 0.75rem;
          border-radius: 4px;
          font-size: 0.8rem;
        }
        .sba-alert--error {
          background: rgba(255, 51, 102, 0.15);
          border: 1px solid #ff3366;
          color: #ff3366;
        }
        .sba-alert--success {
          background: rgba(0, 255, 136, 0.15);
          border: 1px solid #00ff88;
          color: #00ff88;
        }
      `}</style>
    </div>
  );
}

export interface LoginFormProps {
  onLogin: (credentials: { username: string; password: string }) => Promise<void>;
  loading?: boolean;
  error?: string | null;
  submitLabel?: string;
}

export function LoginForm({
  onLogin,
  loading = false,
  error = null,
  submitLabel = "Authentifizieren",
}: LoginFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await onLogin({ username, password });
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="sba-form-group">
        <label className="sba-label">Benutzername / Identität</label>
        <input
          className="sba-input"
          type="text"
          required
          placeholder="z. B. leonf"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={loading}
          autoComplete="username"
        />
      </div>
      <div className="sba-form-group">
        <label className="sba-label">Passwort</label>
        <input
          className="sba-input"
          type="password"
          required
          placeholder="••••••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
          autoComplete="current-password"
        />
      </div>
      <button className="sba-btn" type="submit" disabled={loading}>
        {loading ? "Wird verifiziert..." : submitLabel}
      </button>
      {error && <div className="sba-alert sba-alert--error">{error}</div>}
    </form>
  );
}

export interface TotpFormProps {
  onVerify: (code: string) => Promise<void>;
  loading?: boolean;
  error?: string | null;
}

export function TotpChallengeForm({
  onVerify,
  loading = false,
  error = null,
}: TotpFormProps) {
  const [code, setCode] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (code.length === 6) {
      await onVerify(code);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="sba-form-group">
        <label className="sba-label">6-Stelliger TOTP-Code</label>
        <input
          className="sba-input"
          style={{ letterSpacing: "6px", fontSize: "1.25rem", textAlign: "center" }}
          type="text"
          maxLength={6}
          pattern="[0-9]{6}"
          required
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          disabled={loading}
          autoComplete="one-time-code"
        />
      </div>
      <button className="sba-btn" type="submit" disabled={loading || code.length !== 6}>
        {loading ? "Prüfe Code..." : "Code Bestätigen"}
      </button>
      {error && <div className="sba-alert sba-alert--error">{error}</div>}
    </form>
  );
}

export interface SessionItem {
  sessionId: string;
  device: string;
  ipAddress?: string;
  lastActive: string;
  isCurrent?: boolean;
}

export interface SessionManagerProps {
  sessions: SessionItem[];
  onRevokeSession: (sessionId: string) => Promise<void>;
  onRevokeAllOtherSessions?: () => Promise<void>;
}

export function SessionManager({
  sessions,
  onRevokeSession,
  onRevokeAllOtherSessions,
}: SessionManagerProps) {
  return (
    <div className="sba-sessions-list">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h3 style={{ fontSize: "0.9rem", textTransform: "uppercase", letterSpacing: "1px" }}>Aktive Sitzungen</h3>
        {onRevokeAllOtherSessions && (
          <button
            onClick={() => onRevokeAllOtherSessions()}
            style={{
              background: "transparent",
              border: "1px solid #ff3366",
              color: "#ff3366",
              padding: "0.3rem 0.6rem",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "0.75rem",
              fontFamily: "inherit"
            }}
          >
            Alle anderen abmelden
          </button>
        )}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {sessions.map((s) => (
          <div
            key={s.sessionId}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "0.75rem",
              background: "rgba(0,0,0,0.2)",
              border: "1px solid var(--sba-border, #26262e)",
              borderRadius: "4px",
            }}
          >
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                {s.device}
                {s.isCurrent && (
                  <span style={{ background: "rgba(0,255,136,0.2)", color: "#00ff88", padding: "0.15rem 0.4rem", borderRadius: "3px", fontSize: "0.7rem" }}>
                    Aktuell
                  </span>
                )}
              </div>
              <div style={{ fontSize: "0.75rem", opacity: 0.6, marginTop: "0.2rem" }}>
                {s.ipAddress ? `${s.ipAddress} · ` : ""}Zuletzt aktiv: {s.lastActive}
              </div>
            </div>

            {!s.isCurrent && (
              <button
                onClick={() => onRevokeSession(s.sessionId)}
                style={{
                  background: "transparent",
                  border: "1px solid #ff3366",
                  color: "#ff3366",
                  padding: "0.25rem 0.5rem",
                  borderRadius: "3px",
                  cursor: "pointer",
                  fontSize: "0.7rem",
                  fontFamily: "inherit"
                }}
              >
                Widerrufen
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

