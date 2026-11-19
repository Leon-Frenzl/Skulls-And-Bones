import React, { useEffect, useId, useRef, useState } from "react";
import {
  Activity,
  AppWindow,
  FolderKey,
  Globe,
  HardDrive,
  Maximize2,
  Minimize2,
  Minus,
  PanelLeft,
  PanelRight,
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

const TASKBAR_HEIGHT = 48;

function clampWindowPosition(left: number, top: number, w: number, h: number): [number, number] {
  const maxLeft = Math.max(0, window.innerWidth - Math.min(w, window.innerWidth));
  const maxTop = Math.max(0, window.innerHeight - TASKBAR_HEIGHT - Math.min(h, window.innerHeight - TASKBAR_HEIGHT));
  return [
    Math.round(Math.max(0, Math.min(left, maxLeft))),
    Math.round(Math.max(0, Math.min(top, maxTop))),
  ];
}

interface DesktopWindowProps {
  win: DesktopWindowItem;
  isFocused: boolean;
  onFocus: (id: string) => void;
  onClose: (id: string) => void;
  onMinimize: (id: string) => void;
  onToggleMaximize: (id: string) => void;
  onMove: (id: string, x: number, y: number) => void;
  onResize: (id: string, w: number, h: number) => void;
  onAnnounce: (msg: string) => void;
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
  onAnnounce,
}: DesktopWindowProps) {
  const winRef = useRef<HTMLDivElement | null>(null);
  const handleRef = useRef<HTMLButtonElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const dragStateRef = useRef<{
    pointerId: number;
    offsetX: number;
    offsetY: number;
    startX: number;
    startY: number;
  } | null>(null);
  const resizeRef = useRef<{
    startX: number;
    startY: number;
    origW: number;
    origH: number;
  } | null>(null);

  useEffect(() => {
    const onPointerMove = (e: PointerEvent) => {
      if (resizeRef.current) {
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
      resizeRef.current = null;
    };
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
    };
  }, [win.id, onResize]);

  useEffect(() => {
    const onViewportResize = () => {
      if (win.maximized) return;
      const [nx, ny] = clampWindowPosition(win.x, win.y, win.w, win.h);
      if (nx !== win.x || ny !== win.y) {
        onMove(win.id, nx, ny);
      }
    };
    window.addEventListener("resize", onViewportResize);
    return () => window.removeEventListener("resize", onViewportResize);
  }, [win.id, win.x, win.y, win.w, win.h, win.maximized, onMove]);

  if (win.minimized) return null;

  const style: React.CSSProperties = win.maximized
    ? {
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: TASKBAR_HEIGHT,
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

  const dockSide = (side: "left" | "right") => {
    const halfW = Math.max(420, Math.floor((window.innerWidth - 130) / 2));
    const fullH = Math.max(320, window.innerHeight - TASKBAR_HEIGHT - 16);
    if (win.maximized) onToggleMaximize(win.id);
    if (side === "left") {
      onMove(win.id, 120, 8);
      onResize(win.id, halfW, fullH);
      onAnnounce(`${win.title} links angedockt`);
    } else {
      onMove(win.id, Math.max(120, window.innerWidth - halfW - 8), 8);
      onResize(win.id, halfW, fullH);
      onAnnounce(`${win.title} rechts angedockt`);
    }
  };

  return (
    <section
      ref={winRef}
      aria-label={win.title}
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
        onDoubleClick={() => onToggleMaximize(win.id)}
        style={{
          height: 38,
          minHeight: 38,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 8px 0 6px",
          background: isFocused
            ? "linear-gradient(90deg, rgba(29, 53, 87, 0.72), rgba(16, 25, 38, 0.92))"
            : "rgba(18, 25, 36, 0.92)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
          gap: 6,
        }}
      >
        <button
          ref={handleRef}
          type="button"
          className={`desktop-drag-handle${dragging ? " dragging" : ""}`}
          aria-label={`Fenster ${win.title} verschieben. Pfeiltasten zum Bewegen nutzen.`}
          onPointerDown={(e) => {
            if (win.maximized || e.button !== 0 || !winRef.current) return;
            const rect = winRef.current.getBoundingClientRect();
            dragStateRef.current = {
              pointerId: e.pointerId,
              offsetX: e.clientX - rect.left,
              offsetY: e.clientY - rect.top,
              startX: e.clientX,
              startY: e.clientY,
            };
            handleRef.current?.setPointerCapture(e.pointerId);
          }}
          onPointerMove={(e) => {
            const st = dragStateRef.current;
            if (!st || !handleRef.current?.hasPointerCapture(e.pointerId)) return;
            if (
              !dragging &&
              Math.hypot(e.clientX - st.startX, e.clientY - st.startY) >= 4
            ) {
              setDragging(true);
            }
            const [nx, ny] = clampWindowPosition(
              e.clientX - st.offsetX,
              e.clientY - st.offsetY,
              win.w,
              win.h
            );
            onMove(win.id, nx, ny);
          }}
          onLostPointerCapture={() => {
            dragStateRef.current = null;
            setDragging(false);
          }}
          onKeyDown={(e) => {
            if (win.maximized) return;
            const step = 15;
            let dx = 0;
            let dy = 0;
            let dirLabel = "";
            if (e.key === "ArrowLeft") {
              dx = -step;
              dirLabel = "nach links verschoben";
            } else if (e.key === "ArrowRight") {
              dx = step;
              dirLabel = "nach rechts verschoben";
            } else if (e.key === "ArrowUp") {
              dy = -step;
              dirLabel = "nach oben verschoben";
            } else if (e.key === "ArrowDown") {
              dy = step;
              dirLabel = "nach unten verschoben";
            } else {
              return;
            }
            e.preventDefault();
            const [nx, ny] = clampWindowPosition(win.x + dx, win.y + dy, win.w, win.h);
            onMove(win.id, nx, ny);
            onAnnounce(`${win.title} ${dirLabel}`);
          }}
        >
          <span style={{ color: "#58a6ff", display: "flex", alignItems: "center" }}>
            {win.icon ||
              (win.kind === "terminal" ? <TerminalIcon size={15} /> : <AppWindow size={15} />)}
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
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <button
            type="button"
            className="desktop-win-btn"
            title="Links andocken"
            aria-label="Fenster links andocken"
            onClick={() => dockSide("left")}
            style={winBtnStyle}
          >
            <PanelLeft size={13} />
          </button>
          <button
            type="button"
            className="desktop-win-btn"
            title="Rechts andocken"
            aria-label="Fenster rechts andocken"
            onClick={() => dockSide("right")}
            style={winBtnStyle}
          >
            <PanelRight size={13} />
          </button>
          <button
            type="button"
            className="desktop-win-btn"
            title="Minimieren"
            aria-label="Fenster minimieren"
            onClick={() => onMinimize(win.id)}
            style={winBtnStyle}
          >
            <Minus size={14} />
          </button>
          <button
            type="button"
            className="desktop-win-btn"
            title={win.maximized ? "Wiederherstellen" : "Maximieren"}
            aria-label={win.maximized ? "Fenster wiederherstellen" : "Fenster maximieren"}
            onClick={() => onToggleMaximize(win.id)}
            style={winBtnStyle}
          >
            {win.maximized ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
          <button
            type="button"
            className="desktop-win-btn"
            title="Schließen"
            aria-label="Fenster schließen"
            onClick={() => onClose(win.id)}
            style={{ ...winBtnStyle, color: "#ff7b72" }}
          >
            <X size={14} />
          </button>
        </div>
      </div>

      <div
        className={win.kind === "terminal" ? undefined : "desktop-window-body"}
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
    </section>
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
  const startTriggerId = useId();
  const startMenuId = useId();
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const menuPopoverRef = useRef<HTMLDivElement | null>(null);
  const focusgroupRef = useRef<HTMLDivElement | null>(null);
  const [startOpen, setStartOpen] = useState(false);
  const [liveMsg, setLiveMsg] = useState("");
  const liveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pointerPressedRef = useRef(false);
  const [clock, setClock] = useState(() =>
    new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );

  const announce = (msg: string) => {
    setLiveMsg(msg);
    if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
    liveTimerRef.current = setTimeout(() => setLiveMsg(""), 1000);
  };

  useEffect(() => {
    const timer = setInterval(() => {
      setClock(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  // Progressive enhancement: feature-detect popover, invoker commands, and focusgroup.
  useEffect(() => {
    const menuEl = menuPopoverRef.current;
    const fgEl = focusgroupRef.current;
    if (!menuEl || !fgEl) return;

    const onToggle = (ev: Event) => {
      const open = (ev as ToggleEvent).newState === "open";
      setStartOpen(open);
      if (open && !pointerPressedRef.current) {
        const firstBtn = fgEl.querySelector<HTMLButtonElement>("button:not(:disabled)");
        firstBtn?.focus({ preventScroll: true });
      }
      pointerPressedRef.current = false;
    };
    menuEl.addEventListener("toggle", onToggle);

    let cleanupFallback: (() => void) | undefined;
    if (!("focusGroup" in HTMLElement.prototype)) {
      fgEl.setAttribute("role", "menu");
      fgEl.querySelectorAll("button:not([role])").forEach((item) => {
        item.setAttribute("role", "menuitem");
      });
      const onKeyDown = (event: KeyboardEvent) => {
        if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
        const items = Array.from(fgEl.querySelectorAll<HTMLButtonElement>("button")).filter(
          (b) => !b.disabled
        );
        if (items.length === 0) return;
        const idx = items.indexOf(document.activeElement as HTMLButtonElement);
        const next =
          event.key === "Home"
            ? 0
            : event.key === "End"
              ? items.length - 1
              : idx < 0
                ? 0
                : (idx + (event.key === "ArrowUp" ? -1 : 1) + items.length) % items.length;
        event.preventDefault();
        event.stopImmediatePropagation();
        items[next].focus({ preventScroll: true });
      };
      fgEl.addEventListener("keydown", onKeyDown, true);
      cleanupFallback = () => fgEl.removeEventListener("keydown", onKeyDown, true);
    }

    return () => {
      menuEl.removeEventListener("toggle", onToggle);
      cleanupFallback?.();
    };
  }, []);

  const closeStartMenu = (fromPointer: boolean) => {
    const menuEl = menuPopoverRef.current as (HTMLDivElement & {
      hidePopover?: () => void;
    }) | null;
    const triggerEl = triggerRef.current as (HTMLButtonElement & {
      focus: (opts?: { focusVisible?: boolean }) => void;
    }) | null;
    if (fromPointer) {
      triggerEl?.focus({ focusVisible: false });
    } else {
      triggerEl?.focus();
    }
    menuEl?.hidePopover?.();
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background:
          "radial-gradient(circle at 18% 20%, rgba(30, 64, 120, 0.34), transparent 45%), radial-gradient(circle at 82% 75%, rgba(16, 110, 95, 0.22), transparent 50%), #070b11",
        overflow: "hidden",
      }}
    >
      <div className="visually-hidden" aria-live="polite">
        {liveMsg}
      </div>

      {/* Desktop Icons Grid */}
      <nav
        aria-label="Desktop-Verknüpfungen"
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
            type="button"
            className="desktop-focusable"
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
              aria-hidden="true"
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
      </nav>

      {/* Status Toast Banner */}
      {statusMsg && (
        <div
          role="status"
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
          onAnnounce={announce}
        />
      ))}

      {/* Taskbar */}
      <footer
        aria-label="Taskleiste"
        style={{
          position: "fixed",
          left: 0,
          right: 0,
          bottom: 0,
          height: TASKBAR_HEIGHT,
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
            id={startTriggerId}
            ref={triggerRef}
            type="button"
            className="desktop-start-trigger"
            aria-haspopup="menu"
            aria-expanded={startOpen}
            {...({ commandfor: startMenuId, command: "toggle-popover" } as Record<string, string>)}
            onPointerDown={() => {
              pointerPressedRef.current = true;
            }}
            onClick={(e) => {
              if (!("commandForElement" in HTMLButtonElement.prototype)) {
                e.preventDefault();
                const menuEl = menuPopoverRef.current as (HTMLDivElement & {
                  showPopover?: (opts?: { source?: HTMLElement }) => void;
                  hidePopover?: () => void;
                  matches?: (sel: string) => boolean;
                }) | null;
                if (!menuEl) return;
                const isOpen = menuEl.matches?.(":popover-open") ?? startOpen;
                if (isOpen) {
                  menuEl.hidePopover?.();
                } else {
                  menuEl.showPopover?.({ source: e.currentTarget });
                }
              }
            }}
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

          {/* Popover immediately after its trigger (avoids implicit aria-details) */}
          <div
            id={startMenuId}
            ref={menuPopoverRef}
            className="desktop-start-popover"
            {...({ popover: "auto" } as Record<string, string>)}
          >
            <div style={{ fontSize: "0.78rem", color: "#8b949e", marginBottom: 8 }}>
              Sovereign OS · {domainName}
            </div>
            <div
              ref={focusgroupRef}
              aria-labelledby={startTriggerId}
              {...({ focusgroup: "menu nomemory" } as Record<string, string>)}
            >
              {DESKTOP_SHORTCUTS.map((sc) => (
                <button
                  key={sc.id}
                  type="button"
                  onClick={(e) => {
                    const fromPtr = e.detail !== 0;
                    onOpenShortcut(sc);
                    closeStartMenu(fromPtr);
                  }}
                >
                  <span aria-hidden="true" style={{ color: "#58a6ff", display: "flex" }}>
                    {sc.icon}
                  </span>
                  <span>{sc.label}</span>
                </button>
              ))}
              <hr />
              <button
                type="button"
                onClick={(e) => {
                  const fromPtr = e.detail !== 0;
                  closeStartMenu(fromPtr);
                  onLogout();
                }}
                style={{ color: "#ff7b72" }}
              >
                <Power size={15} aria-hidden="true" />
                <span>Abmelden</span>
                <span className="hint" aria-hidden="true">
                  {username}
                </span>
              </button>
            </div>
          </div>

          {windows.map((w) => {
            const active = focusedId === w.id && !w.minimized;
            return (
              <button
                key={w.id}
                type="button"
                className="desktop-task-btn"
                aria-pressed={active}
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
                <span aria-hidden="true" style={{ color: "#58a6ff", display: "flex" }}>
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
      </footer>
    </div>
  );
}
