import React, { useEffect, useState } from "react";
import {
  Activity,
  Download,
  FileText,
  Globe,
  KeyRound,
  Laptop,
  Lock,
  RefreshCw,
  ShieldCheck,
  Terminal,
  Trash2,
  UserCheck,
  UserX,
  Users,
} from "lucide-react";

type TabId = "overview" | "me" | "vault" | "users" | "machines" | "policies" | "dns" | "ca" | "audit" | "explorer";

interface VaultEntryMeta {
  key: string;
  label: string;
  updated_at: string;
  updated_by: string;
  version: number;
}

interface CompanyApp {
  id: string;
  name: string;
  url: string;
  description: string;
  allowed_groups: string[];
}

interface AuditEvent {
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
}

interface DomainUser {
  username: string;
  display_name: string;
  email: string;
  groups: string[];
  enabled: boolean;
}

interface HealthInfo {
  status: string;
  service: string;
  api_version: string;
  dc_upstream: string;
}

interface MachineRecord {
  machine_id: string;
  fqdn: string;
  os: string;
  mesh_ip: string;
  joined_by: string;
  revoked: boolean;
}

interface PolicyDocument {
  id: string;
  name: string;
  description: string;
  version: number;
  target_os: string[];
  rules: unknown[];
  updated_at: string;
  updated_by: string;
}

export default function App() {
  const [tab, setTab] = useState<TabId>("overview");
  const [token, setToken] = useState<string>(() => localStorage.getItem("sb_token") || "");
  const [refreshToken, setRefreshToken] = useState<string>(() => localStorage.getItem("sb_refresh_token") || "");
  const [loginUser, setLoginUser] = useState<string>("leon.admin");
  const [loginPass, setLoginPass] = useState<string>("");
  const [loginMode, setLoginMode] = useState<"password" | "code">("password");
  const [authError, setAuthError] = useState<string>("");
  const [meNewPass, setMeNewPass] = useState<string>("");
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [machines, setMachines] = useState<MachineRecord[]>([]);
  const [users, setUsers] = useState<DomainUser[]>([]);
  const [newUsername, setNewUsername] = useState<string>("");
  const [newEmail, setNewEmail] = useState<string>("");
  const [newGroups, setNewGroups] = useState<string>("engineering");
  const [policies, setPolicies] = useState<PolicyDocument[]>([]);
  const [dnsRecords, setDnsRecords] = useState<Record<string, unknown> | null>(null);
  const [caStatus, setCaStatus] = useState<Record<string, unknown> | null>(null);
  const [routes, setRoutes] = useState<unknown[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [enrollPkg, setEnrollPkg] = useState<Record<string, unknown> | null>(null);
  const [meUser, setMeUser] = useState<(DomainUser & { ssh_public_key?: string }) | null>(null);
  const [meMachines, setMeMachines] = useState<MachineRecord[]>([]);
  const [meSshPubkey, setMeSshPubkey] = useState<string>("");
  const [meSshCert, setMeSshCert] = useState<string>("");
  const [vaultPass, setVaultPass] = useState<string>("");
  const [vaultEntries, setVaultEntries] = useState<VaultEntryMeta[]>([]);
  const [vaultKey, setVaultKey] = useState<string>("");
  const [vaultLabel, setVaultLabel] = useState<string>("");
  const [vaultSecret, setVaultSecret] = useState<string>("");
  const [revealedSecret, setRevealedSecret] = useState<string>("");
  const [teamGroup, setTeamGroup] = useState<string>("engineering");
  const [teamEntries, setTeamEntries] = useState<VaultEntryMeta[]>([]);
  const [apps, setApps] = useState<CompanyApp[]>([]);
  const [elevRuleId, setElevRuleId] = useState<string>("jit-domain-admin");
  const [elevReason, setElevReason] = useState<string>("");
  const [elevOut, setElevOut] = useState<string>("");
  const [loginCode, setLoginCode] = useState<string>("");
  const [ipamData, setIpamData] = useState<Record<string, unknown> | null>(null);
  const [dnsNewDomain, setDnsNewDomain] = useState<string>("");
  const [dnsNewIp, setDnsNewIp] = useState<string>("");
  const [gpoId, setGpoId] = useState<string>("baseline-ssh");
  const [gpoName, setGpoName] = useState<string>("SSH Hardening");
  const [gpoSsh, setGpoSsh] = useState<boolean>(true);
  const [gpoOut, setGpoOut] = useState<string>("");
  const [appId, setAppId] = useState<string>("");
  const [appName, setAppName] = useState<string>("");
  const [appUrl, setAppUrl] = useState<string>("");
  const [appGroups, setAppGroups] = useState<string>("all");
  const [fleetHealth, setFleetHealth] = useState<{
    heartbeats: Array<{
      machine_id: string;
      gpo_revision: number;
      laps_rotated_at?: string | null;
      service_status?: string | null;
      last_seen_at: string;
    }>;
    laps_rotate_pending: number;
    package_count: number;
  } | null>(null);
  const [pkgId, setPkgId] = useState<string>("");
  const [pkgName, setPkgName] = useState<string>("");
  const [pkgApt, setPkgApt] = useState<string>("");
  const [pkgRollout, setPkgRollout] = useState<number>(100);
  const [statusMsg, setStatusMsg] = useState<string>("");

  // API Explorer state
  const [apiMethod, setApiMethod] = useState<string>("GET");
  const [apiPath, setApiPath] = useState<string>("/v1/openapi.json");
  const [apiBody, setApiBody] = useState<string>("{}");
  const [apiOutput, setApiOutput] = useState<string>("");

  // Enrollment state
  const [enrollDomain, setEnrollDomain] = useState<string>("skulls-and-bones.sb");
  const [enrollResult, setEnrollResult] = useState<string>("");

  const authHeaders = (): Record<string, string> =>
    token.trim() ? { Authorization: `Bearer ${token.trim()}` } : {};

  const saveSession = (access: string, refresh?: string) => {
    setToken(access);
    localStorage.setItem("sb_token", access);
    if (refresh !== undefined) {
      setRefreshToken(refresh);
      localStorage.setItem("sb_refresh_token", refresh);
    }
  };

  const saveToken = (val: string) => {
    saveSession(val, val ? refreshToken : "");
  };

  const tryRefreshSession = async (): Promise<string | null> => {
    if (!refreshToken) return null;
    const res = await fetch("/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.access_token) {
      saveSession(data.access_token, data.refresh_token || refreshToken);
      return data.access_token;
    }
    return null;
  };

  const refreshAll = async (overrideToken?: string) => {
    const activeToken = (overrideToken ?? token).trim();
    if (!activeToken) return;
    setStatusMsg("");
    try {
      let headers: Record<string, string> = { Authorization: `Bearer ${activeToken}` };
      let meRes = await fetch("/v1/me", { headers });
      if (meRes.status === 401 && refreshToken) {
        const refreshed = await tryRefreshSession();
        if (refreshed) {
          headers = { Authorization: `Bearer ${refreshed}` };
          meRes = await fetch("/v1/me", { headers });
        }
      }
      if (meRes.status === 401 || meRes.status === 403) {
        saveSession("", "");
        setAuthError("Sitzung abgelaufen — bitte erneut anmelden.");
        return;
      }

      const [h, p, d, c, r, ipm, mRes, uRes, aRes, vRes, tvRes, appRes, fhRes] = await Promise.all([
        fetch("/v1/health").then((x) => x.json()),
        fetch("/v1/policies", { headers }).then((x) => x.json()).catch(() => ({ policies: [] })),
        fetch("/v1/dns/records", { headers }).then((x) => x.json()).catch(() => null),
        fetch("/v1/ca/status", { headers }).then((x) => x.json()).catch(() => null),
        fetch("/v1/proxy/routes", { headers }).then((x) => x.json()).catch(() => ({ routes: [] })),
        fetch("/v1/ipam/subnets", { headers }).then((x) => x.json()).catch(() => null),
        fetch("/v1/machines", { headers }),
        fetch("/v1/users", { headers }),
        fetch("/v1/audit/events?limit=50", { headers }),
        fetch("/v1/me/vault", { headers }),
        fetch(`/v1/vault/team?group=${encodeURIComponent(teamGroup)}`, { headers }),
        fetch("/v1/apps", { headers }),
        fetch("/v1/fleet/health", { headers }),
      ]);
      setHealth(h);
      setPolicies(Array.isArray(p?.policies) ? p.policies : []);
      setDnsRecords(d);
      setCaStatus(c);
      setRoutes(Array.isArray(r?.routes) ? r.routes : []);
      setIpamData(ipm);

      if (meRes.ok) {
        const meJson = await meRes.json();
        setMeUser(meJson.user ?? null);
        setMeMachines(Array.isArray(meJson.machines) ? meJson.machines : []);
        if (meJson.user?.ssh_public_key) {
          setMeSshPubkey(meJson.user.ssh_public_key);
        }
      }
      if (mRes.ok) {
        const mJson = await mRes.json();
        setMachines(Array.isArray(mJson.machines) ? mJson.machines : []);
      }
      if (uRes.ok) {
        const uJson = await uRes.json();
        setUsers(Array.isArray(uJson.users) ? uJson.users : []);
      }
      if (aRes.ok) {
        const aJson = await aRes.json();
        setAuditEvents(Array.isArray(aJson.events) ? aJson.events : []);
        setAuditValid(typeof aJson.chain_valid === "boolean" ? aJson.chain_valid : null);
      }
      if (vRes.ok) {
        const vJson = await vRes.json();
        setVaultEntries(Array.isArray(vJson.entries) ? vJson.entries : []);
      }
      if (tvRes.ok) {
        const tvJson = await tvRes.json();
        setTeamEntries(Array.isArray(tvJson.entries) ? tvJson.entries : []);
      }
      if (appRes.ok) {
        const appJson = await appRes.json();
        setApps(Array.isArray(appJson.apps) ? appJson.apps : []);
      }
      if (fhRes.ok) {
        setFleetHealth(await fhRes.json());
      }
    } catch (err) {
      setStatusMsg(`API-Verbindung fehlgeschlagen: ${String(err)}`);
    }
  };

  useEffect(() => {
    if (token.trim()) {
      void refreshAll();
    }
  }, []);

  const runExplorer = async () => {
    setApiOutput("Loading...");
    try {
      const init: RequestInit = {
        method: apiMethod,
        headers: {
          "Content-Type": "application/json",
          ...authHeaders(),
        },
      };
      if (apiMethod === "POST" || apiMethod === "PUT") {
        init.body = apiBody;
      }
      const res = await fetch(apiPath, init);
      const text = await res.text();
      try {
        setApiOutput(`HTTP ${res.status}\n` + JSON.stringify(JSON.parse(text), null, 2));
      } catch {
        setApiOutput(`HTTP ${res.status}\n${text}`);
      }
    } catch (err) {
      setApiOutput(`Error: ${String(err)}`);
    }
  };

  const createEnrollment = async () => {
    setEnrollResult("");
    setEnrollPkg(null);
    const res = await fetch("/v1/enrollments", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ domain: enrollDomain }),
    });
    const data = await res.json();
    if (data.enrollment_package) {
      setEnrollPkg(data.enrollment_package);
    }
    setEnrollResult(JSON.stringify(data, null, 2));
  };

  const downloadEnrollFile = () => {
    if (!enrollPkg) return;
    const blob = new Blob([JSON.stringify(enrollPkg, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${enrollDomain}.sb-enroll`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const offboardUser = async (username: string) => {
    const res = await fetch(`/v1/users/${encodeURIComponent(username)}/offboard`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (res.ok) {
      await refreshAll();
    } else {
      setStatusMsg(`Offboarding fehlgeschlagen (${res.status}): ${await res.text()}`);
    }
  };

  const deletePolicy = async (id: string) => {
    const res = await fetch(`/v1/policies/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (res.ok) {
      await refreshAll();
    } else {
      const err = await res.text();
      setStatusMsg(`Löschen fehlgeschlagen (${res.status}): ${err}`);
    }
  };

  if (!token.trim()) {
    return (
      <div className="login-shell">
        <div className="login-card">
          <div className="login-header">
            <ShieldCheck size={32} color="#52c7bd" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 18 }}>Skulls &amp; Bones</div>
              <div style={{ fontSize: 12, color: "var(--accent)" }}>Sovereign Control Console</div>
            </div>
          </div>

          <div className="login-tabs">
            <button
              className={`btn ${loginMode === "password" ? "btn-primary" : ""}`}
              onClick={() => { setLoginMode("password"); setAuthError(""); }}
            >
              Passwort-Login
            </button>
            <button
              className={`btn ${loginMode === "code" ? "btn-primary" : ""}`}
              onClick={() => { setLoginMode("code"); setAuthError(""); }}
            >
              Einmal-Code
            </button>
          </div>

          {authError && <div className="login-error">{authError}</div>}

          {loginMode === "password" ? (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setAuthError("");
                const res = await fetch("/v1/auth/login", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ username: loginUser, password: loginPass }),
                });
                if (res.ok) {
                  const data = await res.json();
                  saveSession(data.access_token, data.refresh_token || "");
                  setLoginPass("");
                  await refreshAll(data.access_token);
                } else {
                  setAuthError(`Anmeldung fehlgeschlagen (${res.status})`);
                }
              }}
            >
              <div className="login-field">
                <label>Domänen-Benutzer</label>
                <input
                  className="input"
                  placeholder="leon.admin"
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  required
                />
              </div>
              <div className="login-field">
                <label>Passwort</label>
                <input
                  className="input"
                  type="password"
                  placeholder="••••••••••••"
                  value={loginPass}
                  onChange={(e) => setLoginPass(e.target.value)}
                  required
                />
              </div>
              <button className="btn btn-primary" type="submit" style={{ width: "100%", justifyContent: "center", padding: "10px 14px" }}>
                Anmelden
              </button>
            </form>
          ) : (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setAuthError("");
                const res = await fetch("/v1/auth/exchange", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ code: loginCode }),
                });
                if (res.ok) {
                  const data = await res.json();
                  if (data.access_token) {
                    saveSession(data.access_token, data.refresh_token || "");
                    setLoginCode("");
                    await refreshAll(data.access_token);
                  }
                } else {
                  setAuthError(`Ungültiger oder abgelaufener Code (${res.status})`);
                }
              }}
            >
              <div className="login-field">
                <label>Einmal-Code (sbc_...)</label>
                <input
                  className="input"
                  placeholder="sbc_..."
                  value={loginCode}
                  onChange={(e) => setLoginCode(e.target.value)}
                  required
                />
              </div>
              <button className="btn btn-primary" type="submit" style={{ width: "100%", justifyContent: "center", padding: "10px 14px" }}>
                Mit Code anmelden
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={24} color="#52c7bd" />
          <div>
            <div className="brand-title">Skulls &amp; Bones</div>
            <div className="brand-sub">Sovereign Control Console</div>
          </div>
        </div>

        <button className={`nav-btn ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>
          <Activity size={16} /> Übersicht
        </button>
        <button className={`nav-btn ${tab === "me" ? "active" : ""}`} onClick={() => setTab("me")}>
          <UserCheck size={16} /> Mein Konto
        </button>
        <button className={`nav-btn ${tab === "vault" ? "active" : ""}`} onClick={() => setTab("vault")}>
          <Lock size={16} /> Passwort-Tresor
        </button>
        <button className={`nav-btn ${tab === "users" ? "active" : ""}`} onClick={() => setTab("users")}>
          <Users size={16} /> Users &amp; Gruppen
        </button>
        <button className={`nav-btn ${tab === "machines" ? "active" : ""}`} onClick={() => setTab("machines")}>
          <Laptop size={16} /> Maschinen &amp; Join
        </button>
        <button className={`nav-btn ${tab === "policies" ? "active" : ""}`} onClick={() => setTab("policies")}>
          <ShieldCheck size={16} /> GPO Policies
        </button>
        <button className={`nav-btn ${tab === "dns" ? "active" : ""}`} onClick={() => setTab("dns")}>
          <Globe size={16} /> DNS Manager
        </button>
        <button className={`nav-btn ${tab === "ca" ? "active" : ""}`} onClick={() => setTab("ca")}>
          <KeyRound size={16} /> CA &amp; Proxy
        </button>
        <button className={`nav-btn ${tab === "audit" ? "active" : ""}`} onClick={() => setTab("audit")}>
          <FileText size={16} /> Audit Log
        </button>
        <button className={`nav-btn ${tab === "explorer" ? "active" : ""}`} onClick={() => setTab("explorer")}>
          <Terminal size={16} /> Graph API Explorer
        </button>
      </aside>

      <main className="main">
        <div className="topbar">
          <h1 style={{ margin: 0, fontSize: 22 }}>
            {tab === "overview" && "Infrastruktur-Übersicht"}
            {tab === "me" && "Mein Konto (Self-Service)"}
            {tab === "vault" && "Sovereign Passwort-Tresor (Argon2id + AES-256-GCM)"}
            {tab === "users" && "Domänen-Benutzer & Gruppen"}
            {tab === "machines" && "Domänen-Maschinen & Mobile Enrollment"}
            {tab === "policies" && "Signierte Cross-Platform GPOs"}
            {tab === "dns" && "Souveräner DNS-Manager"}
            {tab === "ca" && "Certificate Authority & Proxy"}
            {tab === "audit" && "Hash-Verkettetes Audit Log (NIS2 / DSGVO)"}
            {tab === "explorer" && "Open Graph API Explorer (/v1/*)"}
          </h1>

          <div className="token-box">
            {meUser && (
              <span className="badge badge-ok" style={{ padding: "6px 10px" }}>
                {meUser.username} ({meUser.groups.join(", ")})
              </span>
            )}
            <button className="btn" onClick={() => void refreshAll()}>
              <RefreshCw size={14} /> Refresh
            </button>
            <button className="btn btn-danger" onClick={() => { saveSession("", ""); setMeUser(null); }}>
              Abmelden
            </button>
          </div>
        </div>

        {statusMsg && (
          <div className="card" style={{ borderColor: "#ef5350", marginBottom: 16 }}>
            {statusMsg}
          </div>
        )}

        {tab === "overview" && (
          <>
            <div className="grid">
              <div className="card">
                <div className="card-title">Open Graph Gateway</div>
                <div className="card-value">
                  {health?.status === "ok" ? (
                    <span className="badge badge-ok">ONLINE ({health.api_version})</span>
                  ) : (
                    <span className="badge badge-err">OFFLINE</span>
                  )}
                </div>
              </div>
              <div className="card">
                <div className="card-title">GPO Policies</div>
                <div className="card-value">{policies.length}</div>
              </div>
              <div className="card">
                <div className="card-title">Proxy Routen</div>
                <div className="card-value">{routes.length}</div>
              </div>
              <div className="card">
                <div className="card-title">X.509 / SSH CA</div>
                <div className="card-value">
                  {caStatus?.x509_root_initialized ? (
                    <span className="badge badge-ok">INITIALISIERT</span>
                  ) : (
                    <span className="badge badge-warn">AUSSTEHEND</span>
                  )}
                </div>
              </div>
              <div className="card">
                <div className="card-title">Flotten-Heartbeats / LAPS Pending</div>
                <div className="card-value">
                  {fleetHealth ? `${fleetHealth.heartbeats.length} / ${fleetHealth.laps_rotate_pending}` : "–"}
                </div>
              </div>
            </div>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Firmen-App-Portal ({apps.length})</div>
              {apps.length > 0 ? (
                <div className="grid" style={{ marginBottom: 0 }}>
                  {apps.map((app) => (
                    <a
                      key={app.id}
                      href={app.url}
                      target="_blank"
                      rel="noreferrer"
                      className="card"
                      style={{ textDecoration: "none", color: "inherit", borderColor: "rgba(82,199,189,0.35)" }}
                    >
                      <div style={{ fontWeight: 700, color: "var(--accent)" }}>{app.name}</div>
                      <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>{app.description || app.url}</div>
                    </a>
                  ))}
                </div>
              ) : (
                <p style={{ color: "var(--muted)", margin: 0 }}>
                  Noch keine Firmen-Apps sichtbar.
                </p>
              )}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
                <input className="input" placeholder="app-id (z. B. grafana)" value={appId} onChange={(e) => setAppId(e.target.value)} />
                <input className="input" placeholder="Name" value={appName} onChange={(e) => setAppName(e.target.value)} />
                <input className="input" placeholder="https://..." value={appUrl} onChange={(e) => setAppUrl(e.target.value)} />
                <input className="input" placeholder="Gruppen (z. B. all)" value={appGroups} onChange={(e) => setAppGroups(e.target.value)} />
                <button
                  className="btn"
                  onClick={async () => {
                    const res = await fetch(`/v1/apps/${encodeURIComponent(appId)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({
                        id: appId,
                        name: appName,
                        url: appUrl,
                        description: "",
                        allowed_groups: appGroups.split(",").map((s) => s.trim()).filter(Boolean),
                      }),
                    });
                    if (res.ok) {
                      setAppId("");
                      setAppName("");
                      setAppUrl("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`App-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  App hinzufügen
                </button>
              </div>
            </div>
            <div className="card">
              <div className="card-title">Unified API Endpunkte</div>
              <p style={{ color: "var(--muted)", marginTop: 0 }}>
                Alle Module dieser Konsole nutzen dieselbe entwicklerfreundliche Open Graph API unter{" "}
                <code>/v1/*</code>. OpenAPI 3.1 Spezifikation:{" "}
                <a href="/v1/openapi.json" target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
                  /v1/openapi.json
                </a>
              </p>
            </div>
          </>
        )}

        {tab === "me" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Mein Domänen-Profil</div>
              {meUser ? (
                <div>
                  <p style={{ margin: "4px 0" }}>
                    <strong>{meUser.display_name}</strong> (<code>{meUser.username}</code>) — {meUser.email}
                  </p>
                  <p style={{ margin: "4px 0", color: "var(--muted)" }}>
                    Gruppen: {meUser.groups.join(", ") || "keine"}
                  </p>
                </div>
              ) : (
                <p style={{ color: "var(--muted)", margin: 0 }}>
                  Bitte oben dein <code>sb-auth</code> Token einfügen und Refresh klicken.
                </p>
              )}
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">OpenSSH Public Key &amp; 8h-Zertifikat</div>
              <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
                <input
                  className="input"
                  style={{ flex: 1, minWidth: 260 }}
                  placeholder="ssh-ed25519 AAAA..."
                  value={meSshPubkey}
                  onChange={(e) => setMeSshPubkey(e.target.value)}
                />
                <button
                  className="btn"
                  onClick={async () => {
                    const res = await fetch("/v1/me/ssh-key", {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ ssh_public_key: meSshPubkey }),
                    });
                    if (res.ok) {
                      await refreshAll();
                    } else {
                      setStatusMsg(`SSH-Key Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Key speichern
                </button>
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch("/v1/me/ssh-cert", {
                      method: "POST",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ ttl_seconds: 28800 }),
                    });
                    const text = await res.text();
                    setMeSshCert(text);
                  }}
                >
                  8h SSH-Zertifikat holen
                </button>
              </div>
              {meSshCert && <pre className="code-block">{meSshCert}</pre>}
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Browser-Passwort setzen / ändern (Argon2id)</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input
                  className="input"
                  type="password"
                  placeholder="Neues Passwort (min. 8 Zeichen)"
                  value={meNewPass}
                  onChange={(e) => setMeNewPass(e.target.value)}
                  style={{ width: 260 }}
                />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch("/v1/me/password", {
                      method: "POST",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ password: meNewPass }),
                    });
                    if (res.ok) {
                      setMeNewPass("");
                      setStatusMsg("Passwort erfolgreich aktualisiert!");
                    } else {
                      setStatusMsg(`Passwort-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Passwort speichern
                </button>
              </div>
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Just-in-Time Admin-Rechte (nur bei RBAC-Berechtigung)</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                <input className="input" placeholder="Rule ID (z. B. jit-domain-admin)" value={elevRuleId} onChange={(e) => setElevRuleId(e.target.value)} />
                <input className="input" style={{ flex: 1, minWidth: 220 }} placeholder="Begründung (min. 5 Zeichen)" value={elevReason} onChange={(e) => setElevReason(e.target.value)} />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch("/v1/me/elevate", {
                      method: "POST",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ rule_id: elevRuleId, reason: elevReason, ttl_seconds: 1800 }),
                    });
                    setElevOut(await res.text());
                  }}
                >
                  30 Min anfordern
                </button>
              </div>
              {elevOut && <pre className="code-block">{elevOut}</pre>}
            </div>

            <div className="card">
              <div className="card-title">Meine Geräte ({meMachines.length})</div>
              <table className="table">
                <thead>
                  <tr><th>FQDN</th><th>OS</th><th>Mesh IP</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {meMachines.map((m) => (
                    <tr key={m.machine_id}>
                      <td>{m.fqdn}</td>
                      <td>{m.os}</td>
                      <td>{m.mesh_ip}</td>
                      <td><span className={`badge ${m.revoked ? "badge-err" : "badge-ok"}`}>{m.revoked ? "REVOKED" : "ACTIVE"}</span></td>
                    </tr>
                  ))}
                  {meMachines.length === 0 && (
                    <tr><td colSpan={4} style={{ color: "var(--muted)" }}>Noch keine eigenen Geräte registriert.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "vault" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Tresor-Master-Passwort (nur im RAM)</div>
              <input
                className="input"
                type="password"
                placeholder="Master-Passwort zum Ver-/Entschlüsseln..."
                value={vaultPass}
                onChange={(e) => setVaultPass(e.target.value)}
                style={{ width: 320 }}
              />
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Neues Secret speichern (Persönlich oder Team)</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                <input className="input" placeholder="Key (z. B. github-pat)" value={vaultKey} onChange={(e) => setVaultKey(e.target.value)} />
                <input className="input" placeholder="Label / URL" value={vaultLabel} onChange={(e) => setVaultLabel(e.target.value)} />
                <input className="input" type="password" placeholder="Secret / Passwort" value={vaultSecret} onChange={(e) => setVaultSecret(e.target.value)} />
                <button
                  className="btn"
                  onClick={() => {
                    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
                    const arr = new Uint32Array(24);
                    crypto.getRandomValues(arr);
                    setVaultSecret(Array.from(arr, (n) => chars[n % chars.length]).join(""));
                  }}
                >
                  Passwort generieren
                </button>
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch(`/v1/me/vault/${encodeURIComponent(vaultKey)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ label: vaultLabel, secret: vaultSecret, passphrase: vaultPass }),
                    });
                    if (res.ok) {
                      setVaultKey("");
                      setVaultSecret("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`Tresor-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Persönlich speichern
                </button>
                <button
                  className="btn"
                  onClick={async () => {
                    const res = await fetch(`/v1/vault/team/${encodeURIComponent(teamGroup)}/${encodeURIComponent(vaultKey)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ label: vaultLabel, secret: vaultSecret, passphrase: vaultPass }),
                    });
                    if (res.ok) {
                      setVaultKey("");
                      setVaultSecret("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`Team-Tresor-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Im Team ({teamGroup}) speichern
                </button>
              </div>
              {revealedSecret && <pre className="code-block">{revealedSecret}</pre>}
            </div>

            <div className="grid">
              <div className="card">
                <div className="card-title">Mein persönlicher Tresor ({vaultEntries.length})</div>
                <table className="table">
                  <thead><tr><th>Key</th><th>Label</th><th>Aktion</th></tr></thead>
                  <tbody>
                    {vaultEntries.map((e) => (
                      <tr key={e.key}>
                        <td><code>{e.key}</code></td>
                        <td>{e.label}</td>
                        <td>
                          <button
                            className="btn"
                            onClick={async () => {
                              const r = await fetch(`/v1/me/vault/${encodeURIComponent(e.key)}/reveal`, {
                                method: "POST",
                                headers: { "Content-Type": "application/json", ...authHeaders() },
                                body: JSON.stringify({ passphrase: vaultPass }),
                              });
                              setRevealedSecret(await r.text());
                            }}
                          >
                            Entschlüsseln
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="card">
                <div className="card-title">
                  Team-Tresor{" "}
                  <input className="input" value={teamGroup} onChange={(e) => setTeamGroup(e.target.value)} style={{ width: 130, padding: "4px 8px" }} />
                </div>
                <table className="table">
                  <thead><tr><th>Key</th><th>Label</th><th>Aktion</th></tr></thead>
                  <tbody>
                    {teamEntries.map((e) => (
                      <tr key={e.key}>
                        <td><code>{e.key}</code></td>
                        <td>{e.label}</td>
                        <td>
                          <button
                            className="btn"
                            onClick={async () => {
                              const r = await fetch(`/v1/vault/team/${encodeURIComponent(teamGroup)}/${encodeURIComponent(e.key)}/reveal`, {
                                method: "POST",
                                headers: { "Content-Type": "application/json", ...authHeaders() },
                                body: JSON.stringify({ passphrase: vaultPass }),
                              });
                              setRevealedSecret(await r.text());
                            }}
                          >
                            Entschlüsseln
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {tab === "users" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Benutzer anlegen / aktualisieren</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input
                  className="input"
                  placeholder="username (z. B. anna.admin)"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                />
                <input
                  className="input"
                  placeholder="email (z. B. anna@corp.eu)"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                />
                <input
                  className="input"
                  placeholder="groups (kommagetrennt)"
                  value={newGroups}
                  onChange={(e) => setNewGroups(e.target.value)}
                />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch(`/v1/users/${encodeURIComponent(newUsername)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({
                        username: newUsername,
                        display_name: newUsername,
                        email: newEmail,
                        groups: newGroups.split(",").map((s) => s.trim()).filter(Boolean),
                        enabled: true,
                        created_at: "",
                        updated_at: "",
                      }),
                    });
                    if (res.ok) {
                      setNewUsername("");
                      setNewEmail("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Speichern
                </button>
              </div>
            </div>

            <div className="card">
              <div className="card-title">Benutzer ({users.length})</div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>E-Mail</th>
                    <th>Gruppen</th>
                    <th>Status</th>
                    <th>Aktion</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.username}>
                      <td><code>{u.username}</code></td>
                      <td>{u.email}</td>
                      <td>{u.groups.join(", ")}</td>
                      <td>
                        <span className={`badge ${u.enabled ? "badge-ok" : "badge-err"}`}>
                          {u.enabled ? "ACTIVE" : "DISABLED"}
                        </span>
                      </td>
                      <td>
                        {u.enabled && (
                          <button className="btn btn-danger" onClick={() => void offboardUser(u.username)}>
                            <UserX size={14} /> Offboard
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ color: "var(--muted)" }}>
                        Keine Benutzer geladen (Bearer Token mit <code>directory:read</code> oder <code>domain:admin</code> erforderlich).
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "machines" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Mobile / Remote Work Enrollment</div>
              <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                <input
                  className="input"
                  value={enrollDomain}
                  onChange={(e) => setEnrollDomain(e.target.value)}
                  placeholder="corp.eu"
                />
                <button className="btn btn-primary" onClick={() => void createEnrollment()}>
                  Enrollment-Paket erzeugen
                </button>
                {enrollPkg && (
                  <button className="btn" onClick={downloadEnrollFile}>
                    <Download size={14} /> .sb-enroll herunterladen
                  </button>
                )}
              </div>
              {enrollResult && <pre className="code-block">{enrollResult}</pre>}
            </div>

            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">Linux Software-Rollout (Canary %)</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input className="input" placeholder="Paket-ID (z. B. dev-tools)" value={pkgId} onChange={(e) => setPkgId(e.target.value)} />
                <input className="input" placeholder="Name" value={pkgName} onChange={(e) => setPkgName(e.target.value)} />
                <input className="input" placeholder="apt-Pakete (git,htop)" value={pkgApt} onChange={(e) => setPkgApt(e.target.value)} />
                <input className="input" type="number" min={1} max={100} value={pkgRollout} onChange={(e) => setPkgRollout(Number(e.target.value))} style={{ width: 90 }} />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch(`/v1/packages/${encodeURIComponent(pkgId)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({
                        id: pkgId,
                        name: pkgName,
                        apt_packages: pkgApt.split(",").map((s) => s.trim()).filter(Boolean),
                        flatpak_apps: [],
                        target_groups: [],
                        rollout_percent: pkgRollout,
                        version: 1,
                        updated_at: "",
                      }),
                    });
                    if (res.ok) {
                      setPkgId("");
                      setPkgName("");
                      setPkgApt("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`Paket-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  Rollout speichern
                </button>
              </div>
            </div>

            <div className="card">
              <div className="card-title">Registrierte Maschinen ({machines.length})</div>
              <table className="table">
                <thead>
                  <tr>
                    <th>FQDN</th>
                    <th>OS</th>
                    <th>Mesh IP</th>
                    <th>Joined By</th>
                    <th>GPO / LAPS-Sync</th>
                    <th>Status</th>
                    <th>LAPS</th>
                  </tr>
                </thead>
                <tbody>
                  {machines.map((m) => {
                    const hb = fleetHealth?.heartbeats.find((h) => h.machine_id === m.machine_id);
                    return (
                    <tr key={m.machine_id}>
                      <td>{m.fqdn}</td>
                      <td>{m.os}</td>
                      <td>{m.mesh_ip}</td>
                      <td>{m.joined_by}</td>
                      <td>
                        {hb ? (
                          <span style={{ fontSize: "0.82rem" }}>
                            Rev {hb.gpo_revision}
                            {hb.service_status ? ` · ${hb.service_status}` : ""}
                            {hb.laps_rotated_at ? ` · LAPS ${hb.laps_rotated_at.slice(0, 10)}` : ""}
                          </span>
                        ) : (
                          <span style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Kein Sync</span>
                        )}
                      </td>
                      <td>
                        <span className={`badge ${m.revoked ? "badge-err" : "badge-ok"}`}>
                          {m.revoked ? "REVOKED" : "ACTIVE"}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn"
                          onClick={async () => {
                            const pass = window.prompt("LAPS Master-Passphrase eingeben:") || "";
                            if (!pass) return;
                            const r = await fetch(`/v1/machines/${encodeURIComponent(m.machine_id)}/laps/reveal`, {
                              method: "POST",
                              headers: { "Content-Type": "application/json", ...authHeaders() },
                              body: JSON.stringify({ passphrase: pass }),
                            });
                            setStatusMsg(await r.text());
                          }}
                        >
                          Notfall-PW
                        </button>
                      </td>
                    </tr>
                    );
                  })}
                  {machines.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ color: "var(--muted)" }}>
                        Keine Maschinen geladen (Bearer Token mit <code>domain:read</code> oben eintragen &amp; Refresh).
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "policies" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">GPO-Editor (inkl. Dry-Run Vorschau)</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
                <input className="input" placeholder="Policy ID" value={gpoId} onChange={(e) => setGpoId(e.target.value)} />
                <input className="input" placeholder="Name" value={gpoName} onChange={(e) => setGpoName(e.target.value)} />
                <label style={{ fontSize: 13 }}>
                  <input type="checkbox" checked={gpoSsh} onChange={(e) => setGpoSsh(e.target.checked)} /> SSH Hardening
                </label>
                <button
                  className="btn"
                  onClick={async () => {
                    const res = await fetch(`/v1/policies/${encodeURIComponent(gpoId)}?dry_run=true`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({
                        id: gpoId,
                        name: gpoName,
                        description: "",
                        version: 1,
                        scope: { type: "domain" },
                        target_os: [],
                        rules: gpoSsh ? [{ kind: "ssh_hardening", password_auth: false, permit_root_login: false, trusted_user_ca_keys: true }] : [],
                        updated_at: "",
                        updated_by: "",
                      }),
                    });
                    setGpoOut(await res.text());
                  }}
                >
                  Dry-Run Vorschau
                </button>
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch(`/v1/policies/${encodeURIComponent(gpoId)}`, {
                      method: "PUT",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({
                        id: gpoId,
                        name: gpoName,
                        description: "",
                        version: 1,
                        scope: { type: "domain" },
                        target_os: [],
                        rules: gpoSsh ? [{ kind: "ssh_hardening", password_auth: false, permit_root_login: false, trusted_user_ca_keys: true }] : [],
                        updated_at: "",
                        updated_by: "",
                      }),
                    });
                    setGpoOut(await res.text());
                    if (res.ok) await refreshAll();
                  }}
                >
                  Speichern
                </button>
              </div>
              {gpoOut && <pre className="code-block">{gpoOut}</pre>}
            </div>

            <div className="card">
              <div className="card-title">GPO Policies ({policies.length})</div>
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Regeln</th>
                  <th>Aktion</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td><code>{p.id}</code></td>
                    <td>{p.name}</td>
                    <td>v{p.version}</td>
                    <td>{p.rules.length}</td>
                    <td>
                      <button className="btn btn-danger" onClick={() => void deletePolicy(p.id)}>
                        <Trash2 size={14} /> Löschen
                      </button>
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ color: "var(--muted)" }}>
                      Noch keine GPO-Policies vorhanden. Erstelle eine über den Graph API Explorer (<code>PUT /v1/policies/baseline-ssh</code>) oder <code>sb-node policy put</code>.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          </>
        )}

        {tab === "dns" && (
          <>
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title">DNS A-Record hinzufügen</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input className="input" placeholder="app.corp.eu" value={dnsNewDomain} onChange={(e) => setDnsNewDomain(e.target.value)} />
                <input className="input" placeholder="10.42.0.50" value={dnsNewIp} onChange={(e) => setDnsNewIp(e.target.value)} />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    const res = await fetch("/v1/dns/records", {
                      method: "POST",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ domain: dnsNewDomain, ip: dnsNewIp }),
                    });
                    if (res.ok) {
                      setDnsNewDomain("");
                      setDnsNewIp("");
                      await refreshAll();
                    } else {
                      setStatusMsg(`DNS-Fehler (${res.status}): ${await res.text()}`);
                    }
                  }}
                >
                  A-Record speichern
                </button>
              </div>
            </div>
            <div className="grid">
              <div className="card">
                <div className="card-title">Souveräne DNS-Zonen (A / AAAA / CNAME / TXT / SRV)</div>
                <pre className="code-block">{JSON.stringify(dnsRecords, null, 2)}</pre>
              </div>
              <div className="card">
                <div className="card-title">DHCP &amp; IPAM Subnets / Leases</div>
                <pre className="code-block">{JSON.stringify(ipamData, null, 2)}</pre>
              </div>
            </div>
          </>
        )}

        {tab === "ca" && (
          <div className="grid">
            <div className="card">
              <div className="card-title">CA Status</div>
              <pre className="code-block">{JSON.stringify(caStatus, null, 2)}</pre>
            </div>
            <div className="card">
              <div className="card-title">Reverse-Proxy Routen</div>
              <pre className="code-block">{JSON.stringify(routes, null, 2)}</pre>
            </div>
          </div>
        )}

        {tab === "audit" && (
          <div className="card">
            <div className="card-title">
              Audit Events ({auditEvents.length}){" "}
              {auditValid !== null && (
                <span className={`badge ${auditValid ? "badge-ok" : "badge-err"}`}>
                  {auditValid ? "HASH-KETTE INTACT" : "MANIPULATION ERKANNT"}
                </span>
              )}
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Zeitpunkt</th>
                  <th>Akteur</th>
                  <th>Aktion</th>
                  <th>Ziel</th>
                  <th>Ergebnis</th>
                </tr>
              </thead>
              <tbody>
                {auditEvents.map((ev) => (
                  <tr key={ev.seq}>
                    <td>{ev.seq}</td>
                    <td>{ev.timestamp}</td>
                    <td><code>{ev.actor}</code></td>
                    <td><code>{ev.action}</code></td>
                    <td>{ev.target}</td>
                    <td><span className="badge badge-ok">{ev.outcome}</span></td>
                  </tr>
                ))}
                {auditEvents.length === 0 && (
                  <tr>
                    <td colSpan={6} style={{ color: "var(--muted)" }}>
                      Keine Audit-Events geladen (Bearer Token mit <code>audit:read</code> oder <code>domain:admin</code> erforderlich).
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {tab === "explorer" && (
          <div className="card">
            <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
              <select className="select" value={apiMethod} onChange={(e) => setApiMethod(e.target.value)}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
              <input
                className="input"
                value={apiPath}
                onChange={(e) => setApiPath(e.target.value)}
                style={{ flex: 1, minWidth: 220 }}
              />
              <button className="btn btn-primary" onClick={() => void runExplorer()}>
                Request senden
              </button>
            </div>
            {(apiMethod === "POST" || apiMethod === "PUT") && (
              <textarea
                className="textarea"
                value={apiBody}
                onChange={(e) => setApiBody(e.target.value)}
                style={{ marginBottom: 12 }}
              />
            )}
            <pre className="code-block">{apiOutput || "// Antwort erscheint hier..."}</pre>
          </div>
        )}
      </main>
    </div>
  );
}
