import { useEffect, useMemo, useState } from "react";

export interface ActiveElevationItem {
  elevation_id: string;
  username: string;
  rule_id: string;
  granted_capabilities: string[];
  reason: string;
  issued_at: string;
  expires_at: string;
}

interface TicketsPanelProps {
  token: string;
  refreshToken: string;
  autoRenew: boolean;
  onToggleAutoRenew: (next: boolean) => void;
  onRefreshSession: () => Promise<boolean>;
  elevations: ActiveElevationItem[];
  sshCertRaw: string;
  onIssueSshCert?: () => Promise<void>;
}

interface DecodedJwtClaims {
  sub?: string;
  exp?: number;
  iat?: number;
  roles?: string[];
  capabilities?: string[];
}

function parseJwtClaims(jwt: string): DecodedJwtClaims | null {
  const parts = jwt.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = decodeURIComponent(
      Array.from(atob(padded))
        .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join(""),
    );
    return JSON.parse(json) as DecodedJwtClaims;
  } catch {
    return null;
  }
}

function formatRemaining(targetMs: number | null, nowMs: number): { text: string; expired: boolean; soon: boolean } {
  if (!targetMs || Number.isNaN(targetMs)) {
    return { text: "Unbekannt", expired: false, soon: false };
  }
  const diffSec = Math.floor((targetMs - nowMs) / 1000);
  if (diffSec <= 0) {
    return { text: "Abgelaufen", expired: true, soon: true };
  }
  const hours = Math.floor(diffSec / 3600);
  const mins = Math.floor((diffSec % 3600) / 60);
  const secs = diffSec % 60;
  const text =
    hours > 0
      ? `${hours}h ${String(mins).padStart(2, "0")}m`
      : `${mins}m ${String(secs).padStart(2, "0")}s`;
  return {
    text,
    expired: false,
    soon: diffSec < 180,
  };
}

function formatDateTime(ms: number | null): string {
  if (!ms || Number.isNaN(ms)) return "—";
  return new Date(ms).toLocaleString("de-DE", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function TicketsPanel({
  token,
  refreshToken,
  autoRenew,
  onToggleAutoRenew,
  onRefreshSession,
  elevations,
  sshCertRaw,
  onIssueSshCert,
}: TicketsPanelProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [liveMsg, setLiveMsg] = useState("");

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const jwtClaims = useMemo(() => parseJwtClaims(token), [token]);
  const sessionExpMs = typeof jwtClaims?.exp === "number" ? jwtClaims.exp * 1000 : null;
  const sessionRemaining = formatRemaining(sessionExpMs, nowMs);

  const sshCertInfo = useMemo(() => {
    if (!sshCertRaw.trim()) return null;
    try {
      const parsed = JSON.parse(sshCertRaw) as Record<string, unknown>;
      const validUntil = typeof parsed.valid_until === "string" ? parsed.valid_until : null;
      const validMs = validUntil ? Date.parse(validUntil) : null;
      const principals = Array.isArray(parsed.principals) ? parsed.principals.map(String) : [];
      return { validUntil, validMs, principals };
    } catch {
      return { validUntil: null, validMs: null, principals: [] };
    }
  }, [sshCertRaw]);

  const activeTicketCount =
    (token.trim() ? 1 : 0) +
    elevations.length +
    (sshCertInfo ? 1 : 0);

  async function handleManualRefresh() {
    setBusyAction("session");
    try {
      const ok = await onRefreshSession();
      setLiveMsg(ok ? "Sitzungs-Ticket erfolgreich erneuert." : "Sitzungs-Ticket konnte nicht erneuert werden.");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSshRenew() {
    if (!onIssueSshCert) return;
    setBusyAction("ssh");
    try {
      await onIssueSshCert();
      setLiveMsg("8h SSH-Zertifikat neu ausgestellt.");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <section className="card" style={{ marginBottom: 16 }} aria-labelledby="tickets-heading">
      <div className="visually-hidden" aria-live="polite">
        {liveMsg}
      </div>

      <div className="ca-toolbar">
        <div>
          <h2 id="tickets-heading" className="card-title" style={{ marginBottom: 4 }}>
            Aktive Tickets, Leases &amp; Zertifikate ({activeTicketCount})
          </h2>
          <p className="ca-muted">
            Übersicht über Gültigkeitsdauer, Verwendungszweck und Auto-Renewal-Status.
          </p>
        </div>
        <div className="ca-badge-group" style={{ marginTop: 0 }}>
          <span className={`badge ${refreshToken && autoRenew ? "badge-ok" : "badge-warn"}`}>
            {refreshToken
              ? autoRenew
                ? "Auto-Renewal: EIN"
                : "Auto-Renewal: AUS"
              : "Kein Refresh-Token"}
          </span>
        </div>
      </div>

      <div
        tabIndex={0}
        role="region"
        aria-labelledby="tickets-table-caption"
        className="table-wrapper"
      >
        <table className="table responsive-table tickets-table">
          <caption id="tickets-table-caption" className="visually-hidden">
            Gültige Tickets mit Zweck, Restlaufzeit, Auto-Renewal-Status und Aktionen
          </caption>
          <thead>
            <tr>
              <th scope="col">Ticket / Typ</th>
              <th scope="col">Wofür (Zweck &amp; Rechte)</th>
              <th scope="col">Dauer &amp; Ablauf</th>
              <th scope="col">Auto-Renewal</th>
              <th scope="col">Aktion</th>
            </tr>
          </thead>
          <tbody>
            {/* 1. Browser Session Ticket */}
            {token.trim() && (
              <tr>
                <th scope="row">
                  <div className="ca-route-domain">Browser-Sitzung (JWT)</div>
                  <div className="ca-route-id">
                    Benutzer: {jwtClaims?.sub ?? "aktuell"}
                  </div>
                </th>
                <td>
                  <div>Web-Konsole &amp; Open Graph API Zugriff</div>
                  <div className="ca-muted" style={{ marginTop: 2 }}>
                    Rollen: {jwtClaims?.roles?.length ? jwtClaims.roles.join(", ") : "Standard"} ·{" "}
                    Capabilities: {jwtClaims?.capabilities?.length ? jwtClaims.capabilities.join(", ") : "Basis"}
                  </div>
                </td>
                <td>
                  <div>
                    <span
                      className={`badge ${
                        sessionRemaining.expired
                          ? "badge-err"
                          : sessionRemaining.soon
                            ? "badge-warn"
                            : "badge-ok"
                      }`}
                    >
                      {sessionRemaining.text}
                    </span>
                  </div>
                  <div className="ca-muted" style={{ marginTop: 4 }}>
                    Läuft ab: {formatDateTime(sessionExpMs)}
                  </div>
                </td>
                <td>
                  {refreshToken ? (
                    <button
                      type="button"
                      className={`btn-secondary btn-compact`}
                      aria-pressed={autoRenew}
                      onClick={() => {
                        const next = !autoRenew;
                        onToggleAutoRenew(next);
                        setLiveMsg(`Auto-Renewal wurde ${next ? "aktiviert" : "deaktiviert"}.`);
                      }}
                    >
                      {autoRenew ? "Aktiv (Ausschalten)" : "Aus (Aktivieren)"}
                    </button>
                  ) : (
                    <span className="badge badge-warn">Nicht verfügbar</span>
                  )}
                </td>
                <td>
                  <button
                    type="button"
                    className="btn-secondary btn-compact"
                    disabled={!refreshToken || busyAction === "session"}
                    onClick={() => void handleManualRefresh()}
                  >
                    {busyAction === "session" ? "Erneuere…" : "Jetzt erneuern"}
                  </button>
                </td>
              </tr>
            )}

            {/* 2. Aktive JIT Admin Elevations */}
            {elevations.map((el) => {
              const expMs = Date.parse(el.expires_at);
              const rem = formatRemaining(expMs, nowMs);
              return (
                <tr key={el.elevation_id}>
                  <th scope="row">
                    <div className="ca-route-domain">JIT Admin-Ticket</div>
                    <div className="ca-route-id">Regel: {el.rule_id}</div>
                  </th>
                  <td>
                    <div>{el.reason || "Temporäre Privilegien-Eskalation"}</div>
                    <div className="ca-muted" style={{ marginTop: 2 }}>
                      Capabilities:{" "}
                      {el.granted_capabilities.length
                        ? el.granted_capabilities.join(", ")
                        : "—"}
                    </div>
                  </td>
                  <td>
                    <div>
                      <span
                        className={`badge ${
                          rem.expired ? "badge-err" : rem.soon ? "badge-warn" : "badge-ok"
                        }`}
                      >
                        {rem.text}
                      </span>
                    </div>
                    <div className="ca-muted" style={{ marginTop: 4 }}>
                      Läuft ab: {formatDateTime(expMs)}
                    </div>
                  </td>
                  <td>
                    <span className="badge badge-warn">Nein (Festes Zeitfenster)</span>
                  </td>
                  <td>
                    <span className="ca-muted">Läuft automatisch ab</span>
                  </td>
                </tr>
              );
            })}

            {/* 3. 8h SSH Zertifikat (falls in dieser Session abgerufen) */}
            {sshCertInfo && (
              <tr>
                <th scope="row">
                  <div className="ca-route-domain">8h SSH-Zertifikat</div>
                  <div className="ca-route-id">OpenSSH User Cert</div>
                </th>
                <td>
                  <div>Passwortloser SSH-Zugriff auf Mesh- &amp; Domänen-Server</div>
                  <div className="ca-muted" style={{ marginTop: 2 }}>
                    Principals:{" "}
                    {sshCertInfo.principals.length ? sshCertInfo.principals.join(", ") : "Standard"}
                  </div>
                </td>
                <td>
                  <div>
                    <span className="badge badge-ok">
                      {sshCertInfo.validMs
                        ? formatRemaining(sshCertInfo.validMs, nowMs).text
                        : "8 Stunden"}
                    </span>
                  </div>
                  <div className="ca-muted" style={{ marginTop: 4 }}>
                    Gültig bis: {sshCertInfo.validMs ? formatDateTime(sshCertInfo.validMs) : "8h ab Ausstellung"}
                  </div>
                </td>
                <td>
                  <span className="badge badge-warn">Nein (On-Demand)</span>
                </td>
                <td>
                  {onIssueSshCert && (
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      disabled={busyAction === "ssh"}
                      onClick={() => void handleSshRenew()}
                    >
                      {busyAction === "ssh" ? "Erneuere…" : "Erneuern"}
                    </button>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
