import React, { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button, TextField } from "../ui";
import { NoticeBanner } from "../ui/NoticeBanner";
import { formatHttpError, formatNetworkError, type ConsoleNotice } from "../ui/errors";

interface LoginViewProps {
  onSuccess: (accessToken: string, refreshToken: string) => Promise<void>;
}

export function LoginView({ onSuccess }: LoginViewProps) {
  const [loginMode, setLoginMode] = useState<"password" | "code">("password");
  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [loginCode, setLoginCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<ConsoleNotice | null>(null);

  const pushErr = (data: Omit<ConsoleNotice, "id" | "scope">) => {
    setNotice({ ...data, id: `login-${Date.now()}`, scope: "login" });
  };

  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotice(null);
    setBusy(true);
    try {
      const res = await fetch("/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser, password: loginPass }),
      });
      if (res.ok) {
        const data = await res.json();
        setLoginPass("");
        await onSuccess(data.access_token, data.refresh_token || "");
      } else {
        const body = await res.text().catch(() => "");
        pushErr(formatHttpError("Anmeldung", res.status, body));
      }
    } catch (err) {
      pushErr(formatNetworkError("Anmeldung", err));
    } finally {
      setBusy(false);
    }
  };

  const handleCodeLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotice(null);
    setBusy(true);
    try {
      const res = await fetch("/v1/auth/exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: loginCode }),
      });
      if (res.ok) {
        const data = await res.json();
        setLoginCode("");
        await onSuccess(data.access_token, data.refresh_token || "");
      } else {
        const body = await res.text().catch(() => "");
        pushErr(formatHttpError("Einmal-Code einlösen", res.status, body));
      }
    } catch (err) {
      pushErr(formatNetworkError("Einmal-Code einlösen", err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-header">
          <ShieldCheck size={32} color="#52c7bd" aria-hidden="true" />
          <div>
            <div style={{ fontWeight: 700, fontSize: 18 }}>Skulls &amp; Bones</div>
            <div style={{ fontSize: 12, color: "var(--accent)" }}>Sovereign Control Console</div>
          </div>
        </div>

        <div className="login-tabs" role="tablist" aria-label="Anmeldemethode">
          <Button
            variant={loginMode === "password" ? "primary" : "secondary"}
            onClick={() => {
              setLoginMode("password");
              setNotice(null);
            }}
          >
            Passwort-Login
          </Button>
          <Button
            variant={loginMode === "code" ? "primary" : "secondary"}
            onClick={() => {
              setLoginMode("code");
              setNotice(null);
            }}
          >
            Einmal-Code
          </Button>
        </div>

        {notice && (
          <NoticeBanner notice={notice} compact onDismiss={() => setNotice(null)} />
        )}

        {loginMode === "password" ? (
          <form onSubmit={(e) => void handlePasswordLogin(e)} style={{ display: "grid", gap: 12, marginTop: 12 }}>
            <TextField
              label="Domänen-Benutzer"
              placeholder="leon.admin"
              autoComplete="username"
              value={loginUser}
              onChange={(e) => setLoginUser(e.target.value)}
              required
            />
            <TextField
              label="Passwort"
              type="password"
              placeholder="••••••••••••"
              autoComplete="current-password"
              value={loginPass}
              onChange={(e) => setLoginPass(e.target.value)}
              required
            />
            <Button variant="primary" type="submit" busy={busy} style={{ width: "100%", justifyContent: "center" }}>
              Anmelden
            </Button>
          </form>
        ) : (
          <form onSubmit={(e) => void handleCodeLogin(e)} style={{ display: "grid", gap: 12, marginTop: 12 }}>
            <TextField
              label="Einmal-Anmeldecode"
              placeholder="sbo_..."
              autoComplete="one-time-code"
              value={loginCode}
              onChange={(e) => setLoginCode(e.target.value)}
              required
            />
            <Button variant="primary" type="submit" busy={busy} style={{ width: "100%", justifyContent: "center" }}>
              Code einlösen
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}
