import { useMemo, useState } from "react";

export interface CaStatusData {
  ssh_ca_initialized?: boolean;
  ssh_ca_pubkey?: string | null;
  x509_root_initialized?: boolean;
  x509_root_path?: string | null;
}

export interface ProxyRouteItem {
  id: string;
  domain: string;
  aliases?: string[];
  node_callsign?: string | null;
  public_port?: number | null;
  target_port?: number | null;
  static_root?: string | null;
  status?: string | null;
  tls_enabled?: boolean;
  auth_required?: boolean;
  mesh_isolated?: boolean;
  is_tunnel?: boolean;
  tunnel_peer?: string | null;
  rate_limit_rpm?: number | null;
  required_role?: string | null;
  required_capability?: string | null;
  maintenance_msg?: string | null;
  created_at?: string | null;
  expires_at?: string | null;
  cert_expires_at?: string | null;
}

interface CaProxyPanelProps {
  caStatus: CaStatusData | null;
  routes: ProxyRouteItem[];
  knownDnsDomains?: Set<string>;
  onOpenDns?: () => void;
  onCreateRoute?: (payload: {
    domain: string;
    target_port: number;
    node_callsign: string;
    is_tunnel: boolean;
  }) => Promise<void>;
  onToggleRouteStatus?: (id: string, active: boolean) => Promise<void>;
  onDeleteRoute?: (id: string) => Promise<void>;
}

type StatusFilter = "all" | "active" | "paused" | "tunnel";

function formatShortDate(iso?: string | null): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString("de-DE", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function statusBadgeClass(status?: string | null): string {
  const normalized = (status ?? "").toLowerCase();
  if (normalized === "active") return "badge badge-ok";
  if (normalized === "paused" || normalized === "maintenance") return "badge badge-warn";
  return "badge badge-err";
}

export function CaProxyPanel({
  caStatus,
  routes,
  knownDnsDomains,
  onOpenDns,
  onCreateRoute,
  onToggleRouteStatus,
  onDeleteRoute,
}: CaProxyPanelProps) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [copiedKey, setCopiedKey] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [liveMessage, setLiveMessage] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [newPort, setNewPort] = useState("8080");
  const [newNode, setNewNode] = useState("srv490042");
  const [newIsTunnel, setNewIsTunnel] = useState(false);
  const [busyRoute, setBusyRoute] = useState(false);

  const normalizedRoutes = useMemo(
    () => (Array.isArray(routes) ? routes : []),
    [routes],
  );

  const stats = useMemo(() => {
    let active = 0;
    let tls = 0;
    let isolated = 0;
    let tunnels = 0;
    for (const r of normalizedRoutes) {
      if ((r.status ?? "").toLowerCase() === "active") active += 1;
      if (r.tls_enabled) tls += 1;
      if (r.mesh_isolated) isolated += 1;
      if (r.is_tunnel) tunnels += 1;
    }
    return { total: normalizedRoutes.length, active, tls, isolated, tunnels };
  }, [normalizedRoutes]);

  const filteredRoutes = useMemo(() => {
    const q = query.trim().toLowerCase();
    return normalizedRoutes.filter((r) => {
      const st = (r.status ?? "").toLowerCase();
      if (statusFilter === "active" && st !== "active") return false;
      if (statusFilter === "paused" && st === "active") return false;
      if (statusFilter === "tunnel" && !r.is_tunnel) return false;
      if (!q) return true;
      const haystack = [
        r.domain,
        r.id,
        r.node_callsign ?? "",
        ...(Array.isArray(r.aliases) ? r.aliases : []),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [normalizedRoutes, query, statusFilter]);

  async function handleCopyPubkey() {
    const pubkey = caStatus?.ssh_ca_pubkey;
    if (!pubkey) return;
    try {
      await navigator.clipboard.writeText(pubkey);
      setCopiedKey(true);
      setLiveMessage("SSH CA Public Key in die Zwischenablage kopiert.");
      window.setTimeout(() => setCopiedKey(false), 2000);
    } catch {
      setLiveMessage("Kopieren in die Zwischenablage fehlgeschlagen.");
    }
  }

  return (
    <div className="ca-proxy-stack">
      <div className="visually-hidden" aria-live="polite">
        {liveMessage}
      </div>

      {/* Dual-CA Status Karten */}
      <section aria-labelledby="ca-section-heading">
        <h2 id="ca-section-heading" className="section-heading">
          Dual-CA Infrastruktur
        </h2>
        <div className="grid">
          <div className="card">
            <div className="card-header-row">
              <div className="card-title">SSH User &amp; Host CA</div>
              <span className={`badge ${caStatus?.ssh_ca_initialized ? "badge-ok" : "badge-err"}`}>
                {caStatus?.ssh_ca_initialized ? "INITIALISIERT" : "NICHT INITIALISIERT"}
              </span>
            </div>
            <div className="ca-meta-label">Ed25519 CA Public Key</div>
            {caStatus?.ssh_ca_pubkey ? (
              <div className="ca-key-row">
                <code className="ca-mono-pill" title={caStatus.ssh_ca_pubkey}>
                  {caStatus.ssh_ca_pubkey}
                </code>
                <button
                  type="button"
                  className="btn-secondary btn-compact"
                  onClick={handleCopyPubkey}
                >
                  {copiedKey ? "Kopiert" : "Kopieren"}
                </button>
              </div>
            ) : (
              <div className="ca-muted">Kein SSH-CA Public Key vorhanden.</div>
            )}
          </div>

          <div className="card">
            <div className="card-header-row">
              <div className="card-title">X.509 Root CA</div>
              <span className={`badge ${caStatus?.x509_root_initialized ? "badge-ok" : "badge-err"}`}>
                {caStatus?.x509_root_initialized ? "INITIALISIERT" : "NICHT INITIALISIERT"}
              </span>
            </div>
            <div className="ca-meta-label">Root-Zertifikatspfad</div>
            <code className="ca-mono-pill">
              {caStatus?.x509_root_path ?? "—"}
            </code>
          </div>

          <div className="card">
            <div className="card-title">Reverse-Proxy Übersicht</div>
            <div className="card-value">{stats.active} / {stats.total}</div>
            <div className="ca-badge-group">
              <span className="badge badge-ok">{stats.tls} TLS</span>
              <span className="badge badge-warn">{stats.isolated} Mesh-isoliert</span>
              {stats.tunnels > 0 && <span className="badge badge-ok">{stats.tunnels} Tunnel</span>}
            </div>
          </div>
        </div>
      </section>

      {/* Reverse-Proxy Routen Tabelle */}
      <section className="card" aria-labelledby="proxy-routes-heading">
        {onCreateRoute && (
          <div style={{ marginBottom: 16, paddingBottom: 14, borderBottom: "1px solid var(--border)" }}>
            <div className="card-title" style={{ marginBottom: 8 }}>Neue Reverse-Proxy Route</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
              <div className="ca-field">
                <label htmlFor="new-route-domain" className="ca-field-label">Domain</label>
                <input
                  id="new-route-domain"
                  className="ca-input"
                  placeholder="app.skulls-and-bones.org"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                />
              </div>
              {!newIsTunnel && (
                <div className="ca-field">
                  <label htmlFor="new-route-port" className="ca-field-label">Ziel-Port</label>
                  <input
                    id="new-route-port"
                    type="number"
                    min={1}
                    max={65535}
                    className="ca-input"
                    style={{ width: 96 }}
                    value={newPort}
                    onChange={(e) => setNewPort(e.target.value)}
                  />
                </div>
              )}
              <div className="ca-field">
                <label htmlFor="new-route-node" className="ca-field-label">Node-Callsign</label>
                <input
                  id="new-route-node"
                  className="ca-input"
                  value={newNode}
                  onChange={(e) => setNewNode(e.target.value)}
                />
              </div>
              <label style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5, minBlockSize: 32 }}>
                <input
                  type="checkbox"
                  checked={newIsTunnel}
                  onChange={(e) => setNewIsTunnel(e.target.checked)}
                />
                Mesh-Tunnel
              </label>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busyRoute || !newDomain.trim()}
                onClick={async () => {
                  setBusyRoute(true);
                  try {
                    await onCreateRoute({
                      domain: newDomain.trim(),
                      target_port: Number(newPort) || 8080,
                      node_callsign: newNode.trim() || "local-dc",
                      is_tunnel: newIsTunnel,
                    });
                    setNewDomain("");
                  } finally {
                    setBusyRoute(false);
                  }
                }}
              >
                Route anlegen
              </button>
            </div>
          </div>
        )}

        <div className="ca-toolbar">
          <div>
            <h2 id="proxy-routes-heading" className="card-title" style={{ marginBottom: 4 }}>
              Reverse-Proxy Routen ({filteredRoutes.length})
            </h2>
            <p className="ca-muted">
              Aktive Ingress-Routen, TLS-Terminierung und Mesh-Isolation.
            </p>
          </div>
          <div className="ca-filter-controls">
            <div className="ca-field">
              <label htmlFor="route-search" className="ca-field-label">
                Suche
              </label>
              <input
                id="route-search"
                type="search"
                className="ca-input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Domain, ID oder Node…"
              />
            </div>
            <div className="ca-field">
              <label htmlFor="route-status-filter" className="ca-field-label">
                Filter
              </label>
              <select
                id="route-status-filter"
                className="ca-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
              >
                <option value="all">Alle ({stats.total})</option>
                <option value="active">Aktiv ({stats.active})</option>
                <option value="paused">Pausiert / Inaktiv ({stats.total - stats.active})</option>
                <option value="tunnel">Tunnel ({stats.tunnels})</option>
              </select>
            </div>
            <button
              type="button"
              className="btn-secondary btn-compact"
              aria-expanded={showRawJson}
              onClick={() => setShowRawJson((prev) => !prev)}
            >
              {showRawJson ? "JSON ausblenden" : "JSON anzeigen"}
            </button>
          </div>
        </div>

        <div
          tabIndex={0}
          role="region"
          aria-labelledby="proxy-routes-caption"
          className="table-wrapper"
        >
          <table className="table responsive-table ca-routes-table">
            <caption id="proxy-routes-caption" className="visually-hidden">
              Konfigurierte Reverse-Proxy Routen mit Ziel-Node, Sicherheit und Status
            </caption>
            <thead>
              <tr>
                <th scope="col">Domain &amp; ID</th>
                <th scope="col">Ziel &amp; Node</th>
                <th scope="col">Sicherheit &amp; TLS</th>
                <th scope="col">Limits &amp; Erstellt</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredRoutes.length === 0 ? (
                <tr>
                  <td colSpan={5} className="ca-empty-cell">
                    Keine passenden Reverse-Proxy Routen gefunden.
                  </td>
                </tr>
              ) : (
                filteredRoutes.map((route) => {
                  const aliases = Array.isArray(route.aliases) ? route.aliases : [];
                  return (
                    <tr key={route.id}>
                      <th scope="row">
                        <div className="ca-route-domain">{route.domain}</div>
                        <div className="ca-route-id">ID: {route.id}</div>
                        {aliases.length > 0 && (
                          <div className="ca-route-aliases">
                            Aliase: {aliases.join(", ")}
                          </div>
                        )}
                      </th>
                      <td>
                        <div>
                          <strong>{route.node_callsign ?? "lokal"}</strong>
                        </div>
                        <div className="ca-muted">
                          {route.static_root
                            ? `Static: ${route.static_root}`
                            : `:${route.public_port ?? 443} → :${route.target_port ?? "—"}`}
                        </div>
                        {route.is_tunnel && route.tunnel_peer && (
                          <div className="ca-muted">Tunnel: {route.tunnel_peer}</div>
                        )}
                      </td>
                      <td>
                        <div className="ca-badge-group">
                          <span className={`badge ${route.tls_enabled ? "badge-ok" : "badge-warn"}`}>
                            {route.tls_enabled ? "TLS" : "HTTP"}
                          </span>
                          <span className={`badge ${route.auth_required ? "badge-ok" : "badge-warn"}`}>
                            {route.auth_required ? "Auth" : "Public"}
                          </span>
                          {route.mesh_isolated && (
                            <span className="badge badge-ok">Mesh-isoliert</span>
                          )}
                          {knownDnsDomains && (
                            knownDnsDomains.has(route.domain.toLowerCase()) ? (
                              <span className="badge badge-ok">DNS OK</span>
                            ) : (
                              <button
                                type="button"
                                className="badge badge-warn"
                                style={{ border: "none", cursor: onOpenDns ? "pointer" : "default" }}
                                onClick={onOpenDns}
                                title="Im DNS-Manager einen A-Record für diese Domain anlegen"
                              >
                                DNS fehlt
                              </button>
                            )
                          )}
                        </div>
                        {(route.required_role || route.required_capability) && (
                          <div className="ca-muted" style={{ marginTop: 4 }}>
                            {route.required_role ? `Rolle: ${route.required_role}` : ""}
                            {route.required_role && route.required_capability ? " · " : ""}
                            {route.required_capability ? `Cap: ${route.required_capability}` : ""}
                          </div>
                        )}
                      </td>
                      <td>
                        <div>
                          {route.rate_limit_rpm != null
                            ? `${route.rate_limit_rpm} req/min`
                            : "Unbegrenzt"}
                        </div>
                        <div className="ca-muted">
                          Erstellt: {formatShortDate(route.created_at)}
                        </div>
                        {route.expires_at && (
                          <div className="ca-muted">
                            Läuft ab: {formatShortDate(route.expires_at)}
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={statusBadgeClass(route.status)}>
                          {(route.status ?? "Unbekannt").toUpperCase()}
                        </span>
                        {route.maintenance_msg && (
                          <div className="ca-muted" style={{ marginTop: 4 }}>
                            {route.maintenance_msg}
                          </div>
                        )}
                        {(onToggleRouteStatus || onDeleteRoute) && (
                          <div className="ca-badge-group" style={{ marginTop: 8 }}>
                            {onToggleRouteStatus && (
                              <button
                                type="button"
                                className="btn-secondary btn-compact"
                                onClick={() =>
                                  void onToggleRouteStatus(
                                    route.id,
                                    (route.status ?? "").toLowerCase() !== "active",
                                  )
                                }
                              >
                                {(route.status ?? "").toLowerCase() === "active"
                                  ? "Pausieren"
                                  : "Aktivieren"}
                              </button>
                            )}
                            {onDeleteRoute && (
                              <button
                                type="button"
                                className="btn-secondary btn-compact"
                                onClick={() => void onDeleteRoute(route.id)}
                              >
                                Löschen
                              </button>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {showRawJson && (
          <div style={{ marginTop: 16 }}>
            <div className="card-title">Rohdaten (CA Status &amp; Routen)</div>
            <pre className="code-block">
              {JSON.stringify({ ca_status: caStatus, routes: normalizedRoutes }, null, 2)}
            </pre>
          </div>
        )}
      </section>
    </div>
  );
}
