import React, { useEffect, useState } from "react";
import {
  Activity,
  Download,
  FileText,
  Globe,
  KeyRound,
  Laptop,
  RefreshCw,
  ShieldCheck,
  Terminal,
  Trash2,
  UserCheck,
  UserX,
  Users,
} from "lucide-react";

type TabId = "overview" | "me" | "users" | "machines" | "policies" | "dns" | "ca" | "audit" | "explorer";

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
  const [statusMsg, setStatusMsg] = useState<string>("");

  // API Explorer state
  const [apiMethod, setApiMethod] = useState<string>("GET");
  const [apiPath, setApiPath] = useState<string>("/v1/openapi.json");
  const [apiBody, setApiBody] = useState<string>("{}");
  const [apiOutput, setApiOutput] = useState<string>("");

  // Enrollment state
  const [enrollDomain, setEnrollDomain] = useState<string>("corp.eu");
  const [enrollResult, setEnrollResult] = useState<string>("");

  const authHeaders = (): Record<string, string> =>
    token.trim() ? { Authorization: `Bearer ${token.trim()}` } : {};

  const saveToken = (val: string) => {
    setToken(val);
    localStorage.setItem("sb_token", val);
  };

  const refreshAll = async () => {
    setStatusMsg("");
    try {
      const [h, p, d, c, r] = await Promise.all([
        fetch("/v1/health").then((x) => x.json()),
        fetch("/v1/policies").then((x) => x.json()).catch(() => ({ policies: [] })),
        fetch("/v1/dns/records").then((x) => x.json()),
        fetch("/v1/ca/status").then((x) => x.json()),
        fetch("/v1/proxy/routes").then((x) => x.json()),
      ]);
      setHealth(h);
      setPolicies(Array.isArray(p.policies) ? p.policies : []);
      setDnsRecords(d);
      setCaStatus(c);
      setRoutes(Array.isArray(r.routes) ? r.routes : []);

      if (token.trim()) {
        const [mRes, uRes, aRes, meRes] = await Promise.all([
          fetch("/v1/machines", { headers: authHeaders() }),
          fetch("/v1/users", { headers: authHeaders() }),
          fetch("/v1/audit/events?limit=50", { headers: authHeaders() }),
          fetch("/v1/me", { headers: authHeaders() }),
        ]);
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
        if (meRes.ok) {
          const meJson = await meRes.json();
          setMeUser(meJson.user ?? null);
          setMeMachines(Array.isArray(meJson.machines) ? meJson.machines : []);
          if (meJson.user?.ssh_public_key) {
            setMeSshPubkey(meJson.user.ssh_public_key);
          }
        }
      }
    } catch (err) {
      setStatusMsg(`API-Verbindung fehlgeschlagen: ${String(err)}`);
    }
  };

  useEffect(() => {
    void refreshAll();
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
            {tab === "users" && "Domänen-Benutzer & Gruppen"}
            {tab === "machines" && "Domänen-Maschinen & Mobile Enrollment"}
            {tab === "policies" && "Signierte Cross-Platform GPOs"}
            {tab === "dns" && "Souveräner DNS-Manager"}
            {tab === "ca" && "Certificate Authority & Proxy"}
            {tab === "audit" && "Hash-Verkettetes Audit Log (NIS2 / DSGVO)"}
            {tab === "explorer" && "Open Graph API Explorer (/v1/*)"}
          </h1>

          <div className="token-box">
            <input
              className="input"
              type="password"
              placeholder="sb-auth Bearer Token..."
              value={token}
              onChange={(e) => saveToken(e.target.value)}
              style={{ width: 240 }}
            />
            <button className="btn" onClick={() => void refreshAll()}>
              <RefreshCw size={14} /> Refresh
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

            <div className="card">
              <div className="card-title">Registrierte Maschinen ({machines.length})</div>
              <table className="table">
                <thead>
                  <tr>
                    <th>FQDN</th>
                    <th>OS</th>
                    <th>Mesh IP</th>
                    <th>Joined By</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {machines.map((m) => (
                    <tr key={m.machine_id}>
                      <td>{m.fqdn}</td>
                      <td>{m.os}</td>
                      <td>{m.mesh_ip}</td>
                      <td>{m.joined_by}</td>
                      <td>
                        <span className={`badge ${m.revoked ? "badge-err" : "badge-ok"}`}>
                          {m.revoked ? "REVOKED" : "ACTIVE"}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {machines.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ color: "var(--muted)" }}>
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
        )}

        {tab === "dns" && (
          <div className="card">
            <div className="card-title">Souveräne DNS-Zonen (A / AAAA / CNAME / TXT / SRV)</div>
            <pre className="code-block">{JSON.stringify(dnsRecords, null, 2)}</pre>
          </div>
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
