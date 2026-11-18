import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  AppWindow,
  FolderKey,
  Globe,
  HardDrive,
  Maximize2,
  Minimize2,
  Minus,
  Power,
  Server,
  Settings,
  Shield,
  Terminal as TerminalIcon,
  Users,
  X,
} from "lucide-react";

export interface DesktopWindowItem {
  id: string;
  title: string;
  kind: "app" | "terminal" | "files";
  tabId?: string;
  icon?: React.ReactNode;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  minimized: boolean;
  maximized: boolean;
  content: React.ReactNode;
}

export interface DesktopShortcut {
  id: string;
  label: string;
  tabId: string;
  icon: React.ReactNode;
}

export const DESKTOP_SHORTCUTS: DesktopShortcut[] = [
  { id: "overview", label: "System-Übersicht", tabId: "overview", icon: <Activity size={24} /> },
  { id: "machines", label: "Maschinen & SSH", tabId: "machines", icon: <Server size={24} /> },
  { id: "users", label: "Benutzer & AD", tabId: "users", icon: <Users size={24} /> },
  { id: "me", label: "Mein Konto", tabId: "me", icon: <HardDrive size={24} /> },
  { id: "vault", label: "Passwort-Tresor", tabId: "vault", icon: <FolderKey size={24} /> },
  { id: "policies", label: "GPO Policies", tabId: "policies", icon: <Shield size={24} /> },
  { id: "dns", label: "DNS Manager", tabId: "dns", icon: <Globe size={24} /> },
  { id: "ca", label: "CA & Proxy", tabId: "ca", icon: <Settings size={24} /> },
  { id: "audit", label: "Audit Log", tabId: "audit", icon: <AppWindow size={24} /> },
  { id: "explorer", label: "API Explorer", tabId: "explorer", icon: <TerminalIcon size={24} /> },
];

interface DesktopWindowProps {
  win: DesktopWindowItem;
  isFocused: boolean;
  onFocus: (id: string) => void;
  onClose: (id: string) => void;
  onMinimize: (id: string) => void;
  onToggleMaximize: (id: string) => void;
  onMove: (id: string, x: number, y: number) => void;
  onResize: (id: string, w: number, h: number) => void;
}

function DesktopWindow({
  win,
  isFocused,
  onFocus,
  onClose,
  onMinimize,
  onToggleMaximize,
  onMove,
  onResize,
}: DesktopWindowProps) {
  const dragRef = useRef<{ startX: number; startY: number; origX: number; origY: number } | null>(
    null
  );
  const resizeRef = useRef<{ startX: number; startY: number; origW: number; origH: number } | null>(
    null
  );

  useEffect(() => {
    const onPointerMove = (e: PointerEvent) => {
      if (dragRef.current) {
        const dx = e.clientX - dragRef.current.startX;
        const dy = e.clientY - dragRef.current.startY;
        onMove(win.id, Math.max(0, dragRef.current.origX + dx), Math.max(0, dragRef.current.origY + dy));
      } else if (resizeRef.current) {
        const dx = e.clientX - resizeRef.current.startX;
        const dy = e.clientY - resizeRef.current.startY;
        onResize(
          win.id,
          Math.max(420, resizeRef.current.origW + dx),
          Math.max(280, resizeRef.current.origH + dy)
        );
      }
    };
    const onPointerUp = () => {
      dragRef.current = null;
      resizeRef.current = null;
    };
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
    };
  }, [win.id, onMove, onResize]);

  if (win.minimized) return null;

  const style: React.CSSProperties = win.maximized
    ? {
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 48,
        zIndex: win.z,
        borderRadius: 0,
      }
    : {
        position: "fixed",
        left: win.x,
        top: win.y,
        width: win.w,
        height: win.h,
        zIndex: win.z,
        borderRadius: 12,
      };

  return (
    <div
      onPointerDown={() => onFocus(win.id)}
      style={{
        ...style,
        display: "flex",
        flexDirection: "column",
        background: win.kind === "terminal" ? "#090d12" : "rgba(15, 22, 32, 0.96)",
        border: isFocused
          ? "1px solid rgba(88, 166, 255, 0.55)"
          : "1px solid rgba(255, 255, 255, 0.12)",
        boxShadow: isFocused
          ? "0 20px 55px rgba(0, 0, 0, 0.65)"
          : "0 10px 30px rgba(0, 0, 0, 0.45)",
        backdropFilter: "blur(14px)",
        overflow: "hidden",
      }}
    >
      <div
        onPointerDown={(e) => {
          if (win.maximized || (e.target as HTMLElement).closest("button")) return;
          dragRef.current = {
            startX: e.clientX,
            startY: e.clientY,
            origX: win.x,
            origY: win.y,
          };
        }}
        onDoubleClick={() => onToggleMaximize(win.id)}
        style={{
          height: 38,
          minHeight: 38,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 10px 0 12px",
          background: isFocused
            ? "linear-gradient(90deg, rgba(29, 53, 87, 0.72), rgba(16, 25, 38, 0.92))"
            : "rgba(18, 25, 36, 0.92)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
          cursor: win.maximized ? "default" : "grab",
          userSelect: "none",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
          <span style={{ color: "#58a6ff", display: "flex", alignItems: "center" }}>
            {win.icon || (win.kind === "terminal" ? <TerminalIcon size={15} /> : <AppWindow size={15} />)}
          </span>
          <span
            style={{
              fontSize: "0.84rem",
              fontWeight: 600,
              color: "#e6edf3",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {win.title}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <button
            title="Minimieren"
            onClick={() => onMinimize(win.id)}
            style={winBtnStyle}
          >
            <Minus size={14} />
          </button>
          <button
            title={win.maximized ? "Wiederherstellen" : "Maximieren"}
            onClick={() => onToggleMaximize(win.id)}
            style={winBtnStyle}
          >
            {win.maximized ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
          <button
            title="Schließen"
            onClick={() => onClose(win.id)}
            style={{ ...winBtnStyle, color: "#ff7b72" }}
          >
            <X size={14} />
          </button>
        </div>
      </div>

      <div
        style={{
          flex: 1,
          overflow: win.kind === "terminal" ? "hidden" : "auto",
          padding: win.kind === "terminal" ? 0 : 16,
        }}
      >
        {win.content}
      </div>

      {!win.maximized && (
        <div
          onPointerDown={(e) => {
            e.stopPropagation();
            resizeRef.current = {
              startX: e.clientX,
              startY: e.clientY,
              origW: win.w,
              origH: win.h,
            };
          }}
          title="Größe ändern"
          style={{
            position: "absolute",
            right: 0,
            bottom: 0,
            width: 16,
            height: 16,
            cursor: "nwse-resize",
            background:
              "linear-gradient(135deg, transparent 50%, rgba(139, 148, 158, 0.45) 50%)",
          }}
        />
      )}
    </div>
  );
}

const winBtnStyle: React.CSSProperties = {
  background: "rgba(255, 255, 255, 0.06)",
  border: "1px solid rgba(255, 255, 255, 0.08)",
  color: "#c9d1d9",
  borderRadius: 6,
  width: 26,
  height: 24,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  cursor: "pointer",
};

interface DesktopShellProps {
  windows: DesktopWindowItem[];
  focusedId: string | null;
  domainName: string;
  username: string;
  statusMsg: string;
  onOpenShortcut: (shortcut: DesktopShortcut) => void;
  onFocusWindow: (id: string) => void;
  onCloseWindow: (id: string) => void;
  onMinimizeWindow: (id: string) => void;
  onToggleMaximizeWindow: (id: string) => void;
  onMoveWindow: (id: string, x: number, y: number) => void;
  onResizeWindow: (id: string, w: number, h: number) => void;
  onLogout: () => void;
}

export function DesktopShell({
  windows,
  focusedId,
  domainName,
  username,
  statusMsg,
  onOpenShortcut,
  onFocusWindow,
  onCloseWindow,
  onMinimizeWindow,
  onToggleMaximizeWindow,
  onMoveWindow,
  onResizeWindow,
  onLogout,
}: DesktopShellProps) {
  const [startOpen, setStartOpen] = useState(false);
  const [clock, setClock] = useState(() =>
    new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setClock(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div
      onPointerDown={() => setStartOpen(false)}
      style={{
        position: "fixed",
        inset: 0,
        background:
          "radial-gradient(circle at 18% 20%, rgba(30, 64, 120, 0.34), transparent 45%), radial-gradient(circle at 82% 75%, rgba(16, 110, 95, 0.22), transparent 50%), #070b11",
        overflow: "hidden",
      }}
    >
      {/* Desktop Icons Grid */}
      <div
        style={{
          position: "absolute",
          top: 16,
          left: 16,
          bottom: 64,
          display: "grid",
          gridAutoFlow: "column",
          gridTemplateRows: "repeat(auto-fill, 92px)",
          gap: 10,
          alignContent: "start",
        }}
      >
        {DESKTOP_SHORTCUTS.map((sc) => (
          <button
            key={sc.id}
            onClick={() => onOpenShortcut(sc)}
            style={{
              width: 92,
              height: 86,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 6,
              padding: 8,
              borderRadius: 10,
              border: "1px solid transparent",
              background: "transparent",
              color: "#e6edf3",
              cursor: "pointer",
              textShadow: "0 1px 4px rgba(0,0,0,0.9)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(88, 166, 255, 0.14)";
              e.currentTarget.style.borderColor = "rgba(88, 166, 255, 0.3)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.borderColor = "transparent";
            }}
          >
            <span
              style={{
                width: 42,
                height: 42,
                borderRadius: 10,
                background: "rgba(22, 33, 49, 0.85)",
                border: "1px solid rgba(255,255,255,0.12)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#58a6ff",
              }}
            >
              {sc.icon}
            </span>
            <span style={{ fontSize: "0.73rem", lineHeight: 1.15, textAlign: "center" }}>
              {sc.label}
            </span>
          </button>
        ))}
      </div>

      {/* Status Toast Banner */}
      {statusMsg && (
        <div
          style={{
            position: "fixed",
            top: 14,
            right: 18,
            zIndex: 9999,
            maxWidth: 520,
            padding: "8px 14px",
            borderRadius: 8,
            background: "rgba(17, 25, 37, 0.96)",
            border: "1px solid rgba(88, 166, 255, 0.45)",
            color: "#e6edf3",
            fontSize: "0.82rem",
            boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
          }}
        >
          {statusMsg}
        </div>
      )}

      {/* Open Windows */}
      {windows.map((win) => (
        <DesktopWindow
          key={win.id}
          win={win}
          isFocused={focusedId === win.id}
          onFocus={onFocusWindow}
          onClose={onCloseWindow}
          onMinimize={onMinimizeWindow}
          onToggleMaximize={onToggleMaximizeWindow}
          onMove={onMoveWindow}
          onResize={onResizeWindow}
        />
      ))}

      {/* Start Menu */}
      {startOpen && (
        <div
          onPointerDown={(e) => e.stopPropagation()}
          style={{
            position: "fixed",
            left: 10,
            bottom: 56,
            width: 280,
            zIndex: 10000,
            background: "rgba(15, 22, 32, 0.97)",
            border: "1px solid rgba(255,255,255,0.14)",
            borderRadius: 12,
            padding: 12,
            boxShadow: "0 18px 45px rgba(0,0,0,0.65)",
            backdropFilter: "blur(16px)",
          }}
        >
          <div style={{ fontSize: "0.78rem", color: "#8b949e", marginBottom: 8 }}>
            Sovereign OS · {domainName}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {DESKTOP_SHORTCUTS.map((sc) => (
              <button
                key={sc.id}
                onClick={() => {
                  onOpenShortcut(sc);
                  setStartOpen(false);
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "7px 10px",
                  borderRadius: 8,
                  border: "none",
                  background: "transparent",
                  color: "#e6edf3",
                  cursor: "pointer",
                  textAlign: "left",
                  fontSize: "0.85rem",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(88, 166, 255, 0.16)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "transparent";
                }}
              >
                <span style={{ color: "#58a6ff", display: "flex" }}>{sc.icon}</span>
                {sc.label}
              </button>
            ))}
          </div>
          <div
            style={{
              marginTop: 10,
              paddingTop: 10,
              borderTop: "1px solid rgba(255,255,255,0.08)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: "0.8rem", color: "#8b949e" }}>{username}</span>
            <button
              className="btn"
              onClick={onLogout}
              style={{ display: "flex", alignItems: "center", gap: 6, color: "#ff7b72" }}
            >
              <Power size={13} /> Abmelden
            </button>
          </div>
        </div>
      )}

      {/* Taskbar */}
      <div
        onPointerDown={(e) => e.stopPropagation()}
        style={{
          position: "fixed",
          left: 0,
          right: 0,
          bottom: 0,
          height: 48,
          zIndex: 9998,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 10px",
          background: "rgba(11, 16, 24, 0.94)",
          borderTop: "1px solid rgba(255, 255, 255, 0.1)",
          backdropFilter: "blur(14px)",
          gap: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, overflowX: "auto", flex: 1 }}>
          <button
            onClick={() => setStartOpen((v) => !v)}
            style={{
              height: 34,
              padding: "0 12px",
              borderRadius: 8,
              border: "1px solid rgba(88, 166, 255, 0.35)",
              background: startOpen ? "rgba(88, 166, 255, 0.25)" : "rgba(88, 166, 255, 0.14)",
              color: "#e6edf3",
              fontWeight: 700,
              fontSize: "0.82rem",
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            ⊞ Sovereign
          </button>

          {windows.map((w) => {
            const active = focusedId === w.id && !w.minimized;
            return (
              <button
                key={w.id}
                onClick={() => {
                  if (active) {
                    onMinimizeWindow(w.id);
                  } else {
                    onFocusWindow(w.id);
                  }
                }}
                style={{
                  height: 34,
                  maxWidth: 210,
                  padding: "0 10px",
                  borderRadius: 8,
                  border: active
                    ? "1px solid rgba(88, 166, 255, 0.5)"
                    : "1px solid rgba(255, 255, 255, 0.08)",
                  background: active ? "rgba(88, 166, 255, 0.18)" : "rgba(255, 255, 255, 0.04)",
                  color: w.minimized ? "#8b949e" : "#e6edf3",
                  fontSize: "0.8rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                <span style={{ color: "#58a6ff", display: "flex" }}>
                  {w.kind === "terminal" ? <TerminalIcon size={13} /> : <AppWindow size={13} />}
                </span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{w.title}</span>
              </button>
            );
          })}
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            fontSize: "0.78rem",
            color: "#8b949e",
            whiteSpace: "nowrap",
          }}
        >
          <span style={{ color: "#3fb950" }}>● {domainName}</span>
          <span>{username}</span>
          <span style={{ color: "#e6edf3", fontWeight: 600 }}>{clock}</span>
        </div>
      </div>
    </div>
  );
}
