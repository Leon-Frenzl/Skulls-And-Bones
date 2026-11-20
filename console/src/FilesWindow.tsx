import { useEffect, useState } from "react";
import { ArrowUp, Download, File, Folder, RefreshCw, Upload } from "lucide-react";
import { NoticeBanner } from "./ui/NoticeBanner";
import type { ConsoleNotice } from "./ui/errors";

interface FileEntry {
  name: string;
  is_dir: boolean;
  size: number;
}

interface FilesWindowProps {
  machineId: string;
  fqdn: string;
  authHeaders: () => Record<string, string>;
  onStatus?: (msg: string) => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function joinRemotePath(base: string, child: string): string {
  const cleanBase = base.replace(/[\\/]+$/, "");
  const sep = cleanBase.includes("\\") || /^[A-Za-z]:/.test(cleanBase) ? "\\" : "/";
  if (!cleanBase) return child;
  return `${cleanBase}${sep}${child}`;
}

function parentRemotePath(p: string): string {
  const clean = p.replace(/[\\/]+$/, "");
  const idx = Math.max(clean.lastIndexOf("\\"), clean.lastIndexOf("/"));
  if (idx <= 0) return clean;
  const parent = clean.slice(0, idx);
  if (/^[A-Za-z]:$/.test(parent)) return `${parent}\\`;
  return parent;
}

export function FilesWindow({ machineId, fqdn, authHeaders, onStatus }: FilesWindowProps) {
  const [cwd, setCwd] = useState<string>("");
  const [pathInput, setPathInput] = useState<string>("");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [busy, setBusy] = useState<boolean>(false);
  const [notice, setNotice] = useState<ConsoleNotice | null>(null);
  const setErr = (msg: string) => {
    if (!msg) {
      setNotice(null);
      return;
    }
    setNotice({
      id: `files-${Date.now()}`,
      scope: "files",
      severity: "error",
      title: "Dateivorgang fehlgeschlagen",
      detail: msg,
      nextStep: "Prüfen Sie den Pfad, die Berechtigung und ob der Ziel-Agent online ist.",
    });
  };

  const loadDir = async (targetPath: string) => {
    setBusy(true);
    setErr("");
    try {
      const r = await fetch(`/v1/machines/${encodeURIComponent(machineId)}/files/list`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ path: targetPath }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const msg = data.error || `Dateifehler (${r.status})`;
        setErr(msg);
        onStatus?.(msg);
        return;
      }
      setCwd(data.path || targetPath);
      setPathInput(data.path || targetPath);
      setEntries(Array.isArray(data.entries) ? data.entries : []);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void loadDir("");
  }, [machineId]);

  const downloadFile = async (name: string) => {
    const full = joinRemotePath(cwd, name);
    setBusy(true);
    try {
      const r = await fetch(`/v1/machines/${encodeURIComponent(machineId)}/files/read`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ path: full }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        setErr(data.error || `Download fehlgeschlagen (${r.status})`);
        return;
      }
      const bin = atob(data.data_b64 || "");
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = data.name || name;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  };

  const uploadFile = async (file: globalThis.File) => {
    if (file.size > 2 * 1024 * 1024) {
      setErr("Datei größer als 2 MiB Relay-Limit");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = "";
      for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
      const data_b64 = btoa(bin);
      const target = joinRemotePath(cwd, file.name);
      const r = await fetch(`/v1/machines/${encodeURIComponent(machineId)}/files/write`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ path: target, data_b64 }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        setErr(data.error || `Upload fehlgeschlagen (${r.status})`);
        return;
      }
      onStatus?.(`Datei ${file.name} nach ${fqdn} hochgeladen`);
      await loadDir(cwd);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 10 }}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void loadDir(pathInput);
        }}
        style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}
      >
        <button
          type="button"
          className="btn"
          disabled={busy || !cwd}
          onClick={() => void loadDir(parentRemotePath(cwd))}
          title="Übergeordneter Ordner"
        >
          <ArrowUp size={14} /> Hoch
        </button>
        <input
          className="input"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          placeholder="Pfad eingeben..."
          style={{ flex: 1, minWidth: 200 }}
        />
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Öffnen
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() => void loadDir(cwd)}
          title="Aktualisieren"
        >
          <RefreshCw size={14} />
        </button>
        <label className="btn" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 6 }}>
          <Upload size={14} /> Upload
          <input
            type="file"
            style={{ display: "none" }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void uploadFile(f);
              e.target.value = "";
            }}
          />
        </label>
      </form>

      {notice && (
        <NoticeBanner notice={notice} compact onDismiss={() => setNotice(null)} />
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Typ</th>
              <th>Größe</th>
              <th>Aktion</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.name}>
                <td>
                  {e.is_dir ? (
                    <button
                      type="button"
                      onClick={() => void loadDir(joinRemotePath(cwd, e.name))}
                      style={{
                        background: "none",
                        border: "none",
                        color: "#58a6ff",
                        cursor: "pointer",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        padding: 0,
                        fontSize: "0.9rem",
                      }}
                    >
                      <Folder size={15} /> {e.name}
                    </button>
                  ) : (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <File size={15} color="#8b949e" /> {e.name}
                    </span>
                  )}
                </td>
                <td>{e.is_dir ? "Ordner" : "Datei"}</td>
                <td>{e.is_dir ? "—" : formatSize(e.size)}</td>
                <td>
                  {!e.is_dir && (
                    <button
                      type="button"
                      className="btn"
                      disabled={busy}
                      onClick={() => void downloadFile(e.name)}
                    >
                      <Download size={13} /> Download
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {entries.length === 0 && !busy && (
              <tr>
                <td colSpan={4} style={{ color: "var(--muted)" }}>
                  Ordner ist leer.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
