import { useMemo, useState } from "react";

interface DnsIpamPanelProps {
  dnsRecords: Record<string, unknown> | null;
  ipamData: Record<string, unknown> | null;
}

type RecordTypeFilter = "ALL" | "A" | "AAAA" | "CNAME" | "TXT" | "SRV";

interface FlatDnsRecord {
  type: Exclude<RecordTypeFilter, "ALL">;
  name: string;
  value: string;
}

function stringifyRecordValue(val: unknown): string {
  if (typeof val === "string") return val;
  if (Array.isArray(val)) return val.map((item) => stringifyRecordValue(item)).join(", ");
  if (val && typeof val === "object") return JSON.stringify(val);
  return String(val ?? "—");
}

function extractDnsRows(dnsRecords: Record<string, unknown> | null): FlatDnsRecord[] {
  if (!dnsRecords || typeof dnsRecords !== "object") return [];
  const types: Array<{ key: string; label: Exclude<RecordTypeFilter, "ALL"> }> = [
    { key: "a", label: "A" },
    { key: "aaaa", label: "AAAA" },
    { key: "cname", label: "CNAME" },
    { key: "txt", label: "TXT" },
    { key: "srv", label: "SRV" },
  ];
  const rows: FlatDnsRecord[] = [];
  for (const { key, label } of types) {
    const section = dnsRecords[key];
    if (!section || typeof section !== "object" || Array.isArray(section)) continue;
    for (const [name, value] of Object.entries(section as Record<string, unknown>)) {
      rows.push({
        type: label,
        name,
        value: stringifyRecordValue(value),
      });
    }
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
}

export function DnsIpamPanel({ dnsRecords, ipamData }: DnsIpamPanelProps) {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<RecordTypeFilter>("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);
  const [liveMessage, setLiveMessage] = useState("");

  const allRecords = useMemo(() => extractDnsRows(dnsRecords), [dnsRecords]);

  const counts = useMemo(() => {
    const map: Record<Exclude<RecordTypeFilter, "ALL">, number> = {
      A: 0,
      AAAA: 0,
      CNAME: 0,
      TXT: 0,
      SRV: 0,
    };
    for (const r of allRecords) {
      map[r.type] += 1;
    }
    return map;
  }, [allRecords]);

  const filteredRecords = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allRecords.filter((r) => {
      if (typeFilter !== "ALL" && r.type !== typeFilter) return false;
      if (!q) return true;
      return r.name.toLowerCase().includes(q) || r.value.toLowerCase().includes(q);
    });
  }, [allRecords, query, typeFilter]);

  const subnets = useMemo(() => {
    const raw = ipamData?.subnets;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
    return Object.entries(raw as Record<string, unknown>).map(([cidr, meta]) => ({
      cidr,
      meta: meta && typeof meta === "object" ? (meta as Record<string, unknown>) : null,
    }));
  }, [ipamData]);

  const leases = useMemo(() => {
    const raw = ipamData?.leases;
    if (!Array.isArray(raw)) return [];
    return raw.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"));
  }, [ipamData]);

  async function copyValue(id: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      setLiveMessage(`Wert ${value} in die Zwischenablage kopiert.`);
      window.setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
    } catch {
      setLiveMessage("Kopieren in die Zwischenablage fehlgeschlagen.");
    }
  }

  return (
    <div className="ca-proxy-stack">
      <div className="visually-hidden" aria-live="polite">
        {liveMessage}
      </div>

      {/* Übersichtskarten */}
      <div className="grid">
        <div className="card">
          <div className="card-title">DNS-Einträge gesamt</div>
          <div className="card-value">{allRecords.length}</div>
          <div className="ca-badge-group">
            <span className="badge badge-ok">{counts.A} A</span>
            <span className="badge badge-ok">{counts.AAAA} AAAA</span>
            <span className="badge badge-warn">{counts.CNAME} CNAME</span>
            <span className="badge badge-warn">{counts.TXT} TXT</span>
            <span className="badge badge-warn">{counts.SRV} SRV</span>
          </div>
        </div>
        <div className="card">
          <div className="card-title">IPAM Subnets</div>
          <div className="card-value">{subnets.length}</div>
          <p className="ca-muted" style={{ marginTop: 8 }}>
            Verwaltete Mesh- &amp; LAN-Adressbereiche
          </p>
        </div>
        <div className="card">
          <div className="card-title">Aktive DHCP-Leases</div>
          <div className="card-value">{leases.length}</div>
          <p className="ca-muted" style={{ marginTop: 8 }}>
            Zugewiesene Knoten-Adressen
          </p>
        </div>
      </div>

      {/* DNS Records Tabelle */}
      <section className="card" aria-labelledby="dns-zones-heading">
        <div className="ca-toolbar">
          <div>
            <h2 id="dns-zones-heading" className="card-title" style={{ marginBottom: 4 }}>
              Souveräne DNS-Zonen ({filteredRecords.length})
            </h2>
            <p className="ca-muted">
              A, AAAA, CNAME, TXT und SRV Einträge im Split-DNS Resolver.
            </p>
          </div>
          <div className="ca-filter-controls">
            <div className="ca-field">
              <label htmlFor="dns-search" className="ca-field-label">
                Suche
              </label>
              <input
                id="dns-search"
                type="search"
                className="ca-input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Domain oder Zielwert…"
              />
            </div>
            <div className="ca-field">
              <label htmlFor="dns-type-filter" className="ca-field-label">
                Typ
              </label>
              <select
                id="dns-type-filter"
                className="ca-select"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value as RecordTypeFilter)}
              >
                <option value="ALL">Alle ({allRecords.length})</option>
                <option value="A">A ({counts.A})</option>
                <option value="AAAA">AAAA ({counts.AAAA})</option>
                <option value="CNAME">CNAME ({counts.CNAME})</option>
                <option value="TXT">TXT ({counts.TXT})</option>
                <option value="SRV">SRV ({counts.SRV})</option>
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
          aria-labelledby="dns-records-caption"
          className="table-wrapper"
        >
          <table className="table responsive-table dns-records-table">
            <caption id="dns-records-caption" className="visually-hidden">
              Souveräne DNS-Einträge nach Typ, Domain und Zielwert
            </caption>
            <thead>
              <tr>
                <th scope="col">Domain</th>
                <th scope="col">Typ</th>
                <th scope="col">Zielwert</th>
                <th scope="col">Aktion</th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={4} className="ca-empty-cell">
                    Keine passenden DNS-Einträge vorhanden.
                  </td>
                </tr>
              ) : (
                filteredRecords.map((rec) => {
                  const rowKey = `${rec.type}:${rec.name}`;
                  return (
                    <tr key={rowKey}>
                      <th scope="row">
                        <span className="ca-route-domain">{rec.name}</span>
                      </th>
                      <td>
                        <span className="badge badge-ok">{rec.type}</span>
                      </td>
                      <td>
                        <code className="ca-mono-pill" title={rec.value}>
                          {rec.value}
                        </code>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-secondary btn-compact"
                          onClick={() => void copyValue(rowKey, rec.value)}
                        >
                          {copiedId === rowKey ? "Kopiert" : "Kopieren"}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* IPAM Subnets & Leases */}
      <section className="card" aria-labelledby="ipam-heading">
        <h2 id="ipam-heading" className="card-title" style={{ marginBottom: 12 }}>
          DHCP &amp; IPAM Subnets / Leases
        </h2>

        {subnets.length === 0 && leases.length === 0 ? (
          <p className="ca-muted">Noch keine IPAM-Subnets oder DHCP-Leases konfiguriert.</p>
        ) : (
          <div className="grid" style={{ marginBottom: 0 }}>
            {subnets.length > 0 && (
              <div className="table-wrapper" tabIndex={0} role="region" aria-label="IPAM Subnets">
                <table className="table responsive-table">
                  <thead>
                    <tr>
                      <th scope="col">Subnet / CIDR</th>
                      <th scope="col">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {subnets.map((s) => (
                      <tr key={s.cidr}>
                        <th scope="row"><code>{s.cidr}</code></th>
                        <td className="ca-muted">
                          {s.meta ? JSON.stringify(s.meta) : "Aktiv"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {leases.length > 0 && (
              <div className="table-wrapper" tabIndex={0} role="region" aria-label="DHCP Leases">
                <table className="table responsive-table">
                  <thead>
                    <tr>
                      <th scope="col">IP-Adresse</th>
                      <th scope="col">Hostname / Node</th>
                      <th scope="col">Ablauf</th>
                    </tr>
                  </thead>
                  <tbody>
                    {leases.map((lease, idx) => (
                      <tr key={String(lease.ip ?? lease.address ?? idx)}>
                        <th scope="row">
                          <code>{String(lease.ip ?? lease.address ?? "—")}</code>
                        </th>
                        <td>{String(lease.hostname ?? lease.node ?? lease.mac ?? "—")}</td>
                        <td className="ca-muted">
                          {String(lease.expires_at ?? lease.lease_until ?? "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {showRawJson && (
          <div style={{ marginTop: 16 }}>
            <div className="card-title">Rohdaten (DNS &amp; IPAM)</div>
            <pre className="code-block">
              {JSON.stringify({ dns: dnsRecords, ipam: ipamData }, null, 2)}
            </pre>
          </div>
        )}
      </section>
    </div>
  );
}
