import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

interface XtermTerminalProps {
  machineId: string;
  fqdn: string;
  sshUser?: string;
  authHeaders: () => Record<string, string>;
  onStatus?: (msg: string) => void;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function XtermTerminal({
  machineId,
  fqdn,
  sshUser,
  authHeaders,
  onStatus,
}: XtermTerminalProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const [connState, setConnState] = useState<"connecting" | "connected" | "closed" | "error">(
    "connecting"
  );
  const [errMsg, setErrMsg] = useState<string>("");
  const [termTitle, setTermTitle] = useState<string>("");

  useEffect(() => {
    const el = hostRef.current;
    if (!el) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13.5,
      fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace",
      theme: {
        background: "#090d12",
        foreground: "#e2ebf4",
        cursor: "#58a6ff",
        selectionBackground: "rgba(88, 166, 255, 0.3)",
        black: "#0b0f14",
        brightBlack: "#6e7681",
        red: "#ff7b72",
        green: "#3fb950",
        yellow: "#d29922",
        blue: "#58a6ff",
        magenta: "#bc8cff",
        cyan: "#39c5cf",
        white: "#d9e6f2",
      },
      scrollback: 5000,
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(el);
    termRef.current = term;
    fitAddon.fit();
    term.focus();

    let cancelled = false;
    let ptyId = "";
    let wsConn: WebSocket | null = null;
    const encoder = new TextEncoder();

    let pendingInput = "";
    let flushing = false;
    const flushInput = async () => {
      if (wsConn && wsConn.readyState === WebSocket.OPEN) {
        if (pendingInput) {
          const chunk = pendingInput;
          pendingInput = "";
          wsConn.send(encoder.encode(chunk));
        }
        return;
      }
      if (flushing || !ptyId || !pendingInput || cancelled) return;
      flushing = true;
      try {
        while (pendingInput && !cancelled) {
          const chunk = pendingInput;
          pendingInput = "";
          const data_b64 = bytesToBase64(encoder.encode(chunk));
          await fetch(`/v1/ssh/pty/${encodeURIComponent(ptyId)}/input`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...authHeaders() },
            body: JSON.stringify({ data_b64 }),
          }).catch(() => {});
        }
      } finally {
        flushing = false;
      }
    };

    const dataSub = term.onData((data) => {
      if (wsConn && wsConn.readyState === WebSocket.OPEN) {
        wsConn.send(encoder.encode(data));
        return;
      }
      pendingInput += data;
      if (!flushing) {
        void flushInput();
      }
    });

    const titleSub = term.onTitleChange((title) => {
      setTermTitle(title.trim());
    });

    const resizeObserver = new ResizeObserver(() => {
      try {
        fitAddon.fit();
        if (wsConn && wsConn.readyState === WebSocket.OPEN) {
          wsConn.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
        } else if (ptyId && !cancelled) {
          void fetch(`/v1/ssh/pty/${encodeURIComponent(ptyId)}/input`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...authHeaders() },
            body: JSON.stringify({ data_b64: "", cols: term.cols, rows: term.rows }),
          }).catch(() => {});
        }
      } catch {
        // ignore resize errors while unmounting
      }
    });
    resizeObserver.observe(el);

    (async () => {
      term.writeln(`\x1b[90mVerbinde interaktive ConPTY/PTY-Shell mit ${fqdn} (${machineId})...\x1b[0m`);
      const openResp = await fetch(`/v1/machines/${encodeURIComponent(machineId)}/ssh/pty`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          ssh_user: sshUser || undefined,
          cols: term.cols || 100,
          rows: term.rows || 30,
        }),
      }).catch((e) => {
        setConnState("error");
        setErrMsg(String(e));
        return null;
      });

      if (!openResp || cancelled) return;
      const openData = await openResp.json().catch(() => ({}));
      if (!openResp.ok) {
        const msg = openData.error || `PTY-Fehler (${openResp.status})`;
        setConnState("error");
        setErrMsg(msg);
        term.writeln(`\x1b[31m[Fehler] ${msg}\x1b[0m`);
        onStatus?.(msg);
        return;
      }

      ptyId = openData.pty_id;
      setConnState("connected");
      term.writeln(
        `\x1b[32m✓ Verbunden als ${openData.ssh_user}@${openData.fqdn} (${openData.cols}x${openData.rows})\x1b[0m\r\n`
      );
      setTimeout(() => {
        try {
          fitAddon.fit();
          term.focus();
        } catch {
          // ignore
        }
      }, 60);

      const ticketResp = await fetch(`/v1/ssh/pty/${encodeURIComponent(ptyId)}/ticket`, {
        method: "POST",
        headers: { ...authHeaders() },
      }).catch(() => null);
      const ticketData = ticketResp && ticketResp.ok ? await ticketResp.json().catch(() => ({})) : {};
      const wsTicket = typeof ticketData.ticket === "string" ? ticketData.ticket : "";
      const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${wsProto}//${window.location.host}/v1/ssh/pty/${encodeURIComponent(ptyId)}/ws?ticket=${encodeURIComponent(wsTicket)}`;

      const wsWorked = wsTicket
        ? await new Promise<boolean>((resolve) => {
        let opened = false;
        const ws = new WebSocket(wsUrl);
        ws.binaryType = "arraybuffer";
        wsConn = ws;

        ws.onopen = () => {
          opened = true;
          if (pendingInput) {
            ws.send(encoder.encode(pendingInput));
            pendingInput = "";
          }
          ws.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
        };
        ws.onmessage = (ev) => {
          if (ev.data instanceof ArrayBuffer) {
            term.write(new Uint8Array(ev.data));
          } else if (typeof ev.data === "string") {
            term.write(ev.data);
          }
        };
        ws.onerror = () => {
          if (!opened) resolve(false);
        };
        ws.onclose = () => {
          if (!opened) {
            wsConn = null;
            resolve(false);
            return;
          }
          if (!cancelled) {
            setConnState("closed");
            term.writeln(`\r\n\x1b[33m[Shell beendet]\x1b[0m`);
          }
          resolve(true);
        };
      })
        : false;

      if (wsWorked || cancelled) return;

      while (!cancelled) {
        try {
          const pullResp = await fetch(
            `/v1/ssh/pty/${encodeURIComponent(ptyId)}/output?wait=15`,
            { headers: { ...authHeaders() } }
          );
          if (!pullResp.ok) {
            if (!cancelled) {
              setConnState("closed");
              term.writeln(`\r\n\x1b[33m[Verbindung beendet (${pullResp.status})]\x1b[0m`);
            }
            break;
          }
          const payload = await pullResp.json().catch(() => ({}));
          if (payload.data_b64) {
            term.write(base64ToBytes(payload.data_b64));
          }
          if (payload.closed) {
            if (!cancelled) {
              setConnState("closed");
              term.writeln(`\r\n\x1b[33m[Shell beendet]\x1b[0m`);
            }
            break;
          }
        } catch {
          if (!cancelled) {
            await new Promise((r) => setTimeout(r, 1000));
          }
        }
      }
    })();

    return () => {
      cancelled = true;
      dataSub.dispose();
      titleSub.dispose();
      resizeObserver.disconnect();
      if (wsConn) {
        try {
          wsConn.close();
        } catch {
          // ignore
        }
      }
      if (ptyId) {
        void fetch(`/v1/ssh/pty/${encodeURIComponent(ptyId)}`, {
          method: "DELETE",
          headers: { ...authHeaders() },
        }).catch(() => {});
      }
      term.dispose();
    };
  }, [machineId, fqdn, sshUser]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 320 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "4px 10px",
          background: "#0d131a",
          borderBottom: "1px solid rgba(255,255,255,0.08)",
          fontSize: "0.75rem",
          color: "#8b949e",
        }}
      >
        <span>
          {connState === "connected" && "● Live PTY"}
          {connState === "connecting" && "◌ Verbinde PTY..."}
          {connState === "closed" && "○ Beendet"}
          {connState === "error" && `✕ ${errMsg}`}
          {termTitle ? ` · ${termTitle}` : ""}
        </span>
        <span>Ctrl+C · Tab · Pfeiltasten · Vollbild-Resize aktiv</span>
      </div>
      <div
        ref={hostRef}
        onClick={() => termRef.current?.focus()}
        onPointerDown={() => setTimeout(() => termRef.current?.focus(), 0)}
        style={{
          flex: 1,
          width: "100%",
          height: "100%",
          background: "#090d12",
          padding: 6,
          overflow: "hidden",
          cursor: "text",
        }}
      />
    </div>
  );
}
