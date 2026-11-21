import React, { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { DesktopShell, DesktopShortcut, DesktopWindowItem, DESKTOP_SHORTCUTS } from "./DesktopShell";
import { NoticeBanner } from "./ui/NoticeBanner";
import { DEFAULT_WORKBENCH_THEMES, ThemeProvider } from "./ui";
import { buildNotice, ConsoleNotice, formatHttpError, formatNetworkError } from "./ui/errors";
import { LoginView } from "./views/LoginView";
import { PasskeyPanel } from "./components/PasskeyPanel";
import { CaProxyPanel, CaStatusData, ProxyRouteItem } from "./components/CaProxyPanel";
import { DnsIpamPanel } from "./components/DnsIpamPanel";
import { ActiveElevationItem, TicketsPanel } from "./components/TicketsPanel";
const FilesWindow = lazy(() => import("./FilesWindow").then((m) => ({ default: m.FilesWindow })));
const XtermTerminal = lazy(() => import("./XtermTerminal").then((m) => ({ default: m.XtermTerminal })));
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

type TabId = "overview" | "directory" | "machines" | "network" | "workspace" | "security";

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
  const [directorySub, setDirectorySub] = useState<"users" | "policies">("users");
  const [networkSub, setNetworkSub] = useState<"ca" | "dns">("ca");
  const [workspaceSub, setWorkspaceSub] = useState<"account" | "vault">("account");
  const [securitySub, setSecuritySub] = useState<"audit" | "explorer">("audit");
  const [dirFilterOu, setDirFilterOu] = useState<string>("");
  const [dirFilterGroup, setDirFilterGroup] = useState<string>("");
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
  const [newUserOu, setNewUserOu] = useState<string>("/");
  const [newGroups, setNewGroups] = useState<string>("engineering");
  const [ous, setOus] = useState<Array<{ path: string; description: string }>>([]);
  const [secGroups, setSecGroups] = useState<
    Array<{
      name: string;
      description: string;
      ou: string;
      is_local_admin: boolean;
      allowed_machines: string[];
      members: string[];
    }>
  >([]);
  const [newOuPath, setNewOuPath] = useState<string>("/Engineering");
  const [newOuDesc, setNewOuDesc] = useState<string>("");
  const [newGrpName, setNewGrpName] = useState<string>("");
  const [newGrpOu, setNewGrpOu] = useState<string>("/");
  const [newGrpAdmin, setNewGrpAdmin] = useState<boolean>(false);
  const [newGrpMachines, setNewGrpMachines] = useState<string>("");
  const [policies, setPolicies] = useState<PolicyDocument[]>([]);
  const [dnsRecords, setDnsRecords] = useState<Record<string, unknown> | null>(null);
  const [caStatus, setCaStatus] = useState<Record<string, unknown> | null>(null);
  const [routes, setRoutes] = useState<unknown[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [auditQuery, setAuditQuery] = useState("");
  const [elevations, setElevations] = useState<ActiveElevationItem[]>([]);
  const [autoRenew, setAutoRenew] = useState<boolean>(() => localStorage.getItem("sb_auto_renew") !== "false");
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
  const [dnsNewType, setDnsNewType] = useState<"A" | "AAAA" | "CNAME" | "TXT" | "SRV">("A");
  const [dnsNewDomain, setDnsNewDomain] = useState<string>("");
  const [dnsNewIp, setDnsNewIp] = useState<string>("");
  const [backupStatus, setBackupStatus] = useState<{
    backup_count: number;
    last_backup_at: string | null;
    latest_path: string | null;
    size_bytes: number;
    encrypted: boolean;
  } | null>(null);
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
  const [notices, setNotices] = useState<Partial<Record<string, ConsoleNotice>>>({});
  const pushNotice = (scope: string, data: Omit<ConsoleNotice, "id" | "scope">) => {
    setNotices((prev) => ({
      ...prev,
      [scope]: { ...data, scope, id: `${scope}-${Date.now()}` },
    }));
  };
  const dismissNotice = (scope: string) => {
    setNotices((prev) => {
      const next = { ...prev };
      delete next[scope];
      return next;
    });
  };
  const pushHttpError = async (scope: string, actionLabel: string, res: Response) => {
    const body = await res.text().catch(() => "");
    pushNotice(scope, formatHttpError(actionLabel, res.status, body));
  };
  const setStatusMsg = (msg: string) => {
    if (!msg.trim()) {
      dismissNotice("global");
      return;
    }
    const lower = msg.toLowerCase();
    const isErr = lower.includes("fehler") || lower.includes("fehlgeschlagen") || lower.includes("ungültig");
    pushNotice(
      "global",
      buildNotice(
        isErr ? "error" : "info",
        isErr ? "Vorgang fehlgeschlagen" : "Status",
        msg,
        isErr ? "Prüfen Sie Ihre Eingaben oder die Serververbindung." : undefined
      )
    );
  };
  const [sshSession, setSshSession] = useState<{
    session_id: string;
    fqdn: string;
    mesh_ip: string;
    ssh_user: string;
    principals: string[];
    expires_at: string;
    cli_fallback: string;
  } | null>(null);
  const [sshCmd, setSshCmd] = useState<string>("");
  const [sshLog, setSshLog] = useState<string>("");
  const [sshCwd, setSshCwd] = useState<string>("~");
  const [sshBusy, setSshBusy] = useState<boolean>(false);
  const [sshHistory, setSshHistory] = useState<string[]>([]);
  const [sshHistoryIdx, setSshHistoryIdx] = useState<number>(-1);
  const [zCounter, setZCounter] = useState<number>(20);
  const [focusedWinId, setFocusedWinId] = useState<string | null>("app:overview");
  const [desktopWins, setDesktopWins] = useState<
    Array<Omit<DesktopWindowItem, "content"> & { machineId?: string; fqdn?: string }>
  >([
    {
      id: "app:overview",
      title: "DC-Leitstand",
      kind: "app",
      tabId: "overview",
      x: 136,
      y: 28,
      w: 960,
      h: 640,
      z: 10,
      minimized: false,
      maximized: false,
    },
  ]);

  const focusWindow = (id: string) => {
    setZCounter((z) => {
      const next = z + 1;
      setDesktopWins((prev) =>
        prev.map((w) => (w.id === id ? { ...w, minimized: false, z: next } : w))
      );
      return next;
    });
    setFocusedWinId(id);
  };

  const openShortcutWindow = (sc: DesktopShortcut) => {
    const winId = `app:${sc.tabId}`;
    setTab(sc.tabId as TabId);
    const exists = desktopWins.some((w) => w.id === winId);
    if (exists) {
      focusWindow(winId);
      return;
    }
    setZCounter((z) => {
      const next = z + 1;
      const offset = (desktopWins.length % 6) * 26;
      setDesktopWins((prev) => [
        ...prev,
        {
          id: winId,
          title: sc.label,
          kind: "app",
          tabId: sc.tabId,
          icon: sc.icon,
          x: 136 + offset,
          y: 28 + offset,
          w: 980,
          h: 660,
          z: next,
          minimized: false,
          maximized: false,
        },
      ]);
      return next;
    });
    setFocusedWinId(winId);
  };

  const openWorkspaceTab = (target: TabId, sub?: string) => {
    if (target === "directory" && (sub === "users" || sub === "policies")) setDirectorySub(sub);
    if (target === "network" && (sub === "ca" || sub === "dns")) setNetworkSub(sub);
    if (target === "workspace" && (sub === "account" || sub === "vault")) setWorkspaceSub(sub);
    if (target === "security" && (sub === "audit" || sub === "explorer")) setSecuritySub(sub);
    const sc = DESKTOP_SHORTCUTS.find((s) => s.tabId === target);
    if (sc) {
      openShortcutWindow(sc);
    } else {
      setTab(target);
    }
  };

  const knownDnsDomains = useMemo(() => {
    const set = new Set<string>();
    if (!dnsRecords || typeof dnsRecords !== "object") return set;
    for (const sectionKey of ["a", "aaaa", "cname", "txt", "srv"]) {
      const section = dnsRecords[sectionKey];
      if (!section || typeof section !== "object" || Array.isArray(section)) continue;
      for (const domain of Object.keys(section as Record<string, unknown>)) {
        set.add(domain.toLowerCase());
      }
    }
    return set;
  }, [dnsRecords]);

  const createDnsARecord = async (domain: string, ip: string, noticeTab: TabId) => {
    const res = await fetch("/v1/dns/records", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ domain, ip }),
    });
    if (res.ok) {
      pushNotice(noticeTab, buildNotice("success", "DNS A-Record angelegt", `${domain} → ${ip}`));
      await refreshAll();
    } else {
      await pushHttpError(noticeTab, "DNS A-Record anlegen", res);
    }
  };

  const openFilesWindow = (m: MachineRecord) => {
    const winId = `files:${m.machine_id}`;
    if (desktopWins.some((w) => w.id === winId)) {
      focusWindow(winId);
      return;
    }
    setZCounter((z) => {
      const next = z + 1;
      const offset = (desktopWins.length % 6) * 28;
      setDesktopWins((prev) => [
        ...prev,
        {
          id: winId,
          title: `Dateien — ${m.fqdn}`,
          kind: "files",
          machineId: m.machine_id,
          fqdn: m.fqdn,
          x: 160 + offset,
          y: 44 + offset,
          w: 820,
          h: 540,
          z: next,
          minimized: false,
          maximized: false,
        },
      ]);
      return next;
    });
    setFocusedWinId(winId);
  };

  const openTerminalWindow = (m: MachineRecord) => {
    const winId = `term:${m.machine_id}:${Date.now()}`;
    setZCounter((z) => {
      const next = z + 1;
      const offset = (desktopWins.length % 6) * 28;
      setDesktopWins((prev) => [
        ...prev,
        {
          id: winId,
          title: `Terminal — ${m.fqdn} (${m.mesh_ip})`,
          kind: "terminal",
          machineId: m.machine_id,
          fqdn: m.fqdn,
          x: 180 + offset,
          y: 52 + offset,
          w: 840,
          h: 520,
          z: next,
          minimized: false,
          maximized: false,
        },
      ]);
      return next;
    });
    setFocusedWinId(winId);
  };

  const closeWindow = (id: string) => {
    setDesktopWins((prev) => prev.filter((w) => w.id !== id));
    if (focusedWinId === id) setFocusedWinId(null);
  };

  const minimizeWindow = (id: string) => {
    setDesktopWins((prev) => prev.map((w) => (w.id === id ? { ...w, minimized: true } : w)));
  };

  const toggleMaximizeWindow = (id: string) => {
    setDesktopWins((prev) =>
      prev.map((w) => (w.id === id ? { ...w, maximized: !w.maximized } : w))
    );
    focusWindow(id);
  };

  const moveWindow = (id: string, x: number, y: number) => {
    setDesktopWins((prev) => prev.map((w) => (w.id === id ? { ...w, x, y } : w)));
  };

  const resizeWindow = (id: string, w: number, h: number) => {
    setDesktopWins((prev) => prev.map((win) => (win.id === id ? { ...win, w, h } : win)));
  };

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
      const [ouRes, grpRes, elRes, bkRes] = await Promise.all([
        fetch("/v1/ous", { headers }),
        fetch("/v1/groups", { headers }),
        fetch("/v1/me/elevations", { headers }).catch(() => null),
        fetch("/v1/dc/backup-status", { headers }).catch(() => null),
      ]);
      if (ouRes.ok) {
        const ouJson = await ouRes.json();
        setOus(Array.isArray(ouJson.ous) ? ouJson.ous : []);
      }
      if (grpRes.ok) {
        const grpJson = await grpRes.json();
        setSecGroups(Array.isArray(grpJson.groups) ? grpJson.groups : []);
      }
      if (elRes && elRes.ok) {
        const elJson = await elRes.json();
        setElevations(Array.isArray(elJson.elevations) ? elJson.elevations : []);
      }
      if (bkRes && bkRes.ok) {
        setBackupStatus(await bkRes.json());
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
      pushNotice("global", formatNetworkError("Datenabruf", err));
    }
  };

  useEffect(() => {
    if (!token || !refreshToken || !autoRenew) return;
    const interval = window.setInterval(() => {
      const parts = token.split(".");
      if (parts.length !== 3) return;
      try {
        const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
        const payload = JSON.parse(atob(padded)) as { exp?: number };
        if (typeof payload.exp === "number") {
          const remainingSec = payload.exp - Math.floor(Date.now() / 1000);
          if (remainingSec < 120) {
            void tryRefreshSession();
          }
        }
      } catch {
        // Ignore malformed JWT
      }
    }, 30000);
    return () => window.clearInterval(interval);
  }, [token, refreshToken, autoRenew]);

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
      await pushHttpError("directory", "Offboarding", res);
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
      await pushHttpError("directory", "Policy löschen", res);
    }
  };

  if (!token.trim()) {
    return (
      <ThemeProvider theme={DEFAULT_WORKBENCH_THEMES.dark}>
        <LoginView
          onSuccess={async (acc, ref) => {
            saveSession(acc, ref);
            await refreshAll(acc);
          }}
        />
      </ThemeProvider>
    );
  }

  const renderTabContent = (tab: TabId) => (
    <>
        <div className="topbar" style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "var(--muted)" }}>
            {tab === "overview" && "DC-Leitstand & Domänen-Gesundheit"}
            {tab === "directory" && "Verzeichnis, OUs, Gruppen & GPOs"}
            {tab === "machines" && "Flotte, LAPS & Enrollment"}
            {tab === "network" && "Netzwerk, DNS, PKI & Reverse-Proxy"}
            {tab === "workspace" && "Mein Konto, Tickets & Tresor"}
            {tab === "security" && "Sicherheit, Audit Log & API Explorer"}
          </div>

          <div className="token-box">
            {meUser && (
              <span className="badge badge-ok" style={{ padding: "6px 10px" }}>
                {meUser.username} ({meUser.groups.join(", ")})
              </span>
            )}
            <button className="btn" onClick={() => void refreshAll()}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        </div>

        {notices[tab] && (
          <NoticeBanner notice={notices[tab]!} onDismiss={() => dismissNotice(tab)} />
        )}

        {tab === "overview" && (() => {
          const activeUsers = users.filter((u) => u.enabled).length;
          const activeMachines = machines.filter((m) => !m.revoked).length;
          const machinesMissingDns = machines.filter(
            (m) => !m.revoked && m.mesh_ip && !knownDnsDomains.has(m.fqdn.toLowerCase()),
          );
          const activeRoutes = (routes as ProxyRouteItem[]).filter(
            (r) => (r.status ?? "").toLowerCase() === "active",
          );
          const routesMissingDns = activeRoutes.filter(
            (r) => !knownDnsDomains.has(r.domain.toLowerCase()),
          );
          const lapsPending = fleetHealth?.laps_rotate_pending ?? 0;

          return (
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
                <button
                  type="button"
                  className="card dc-kpi-btn"
                  onClick={() => openWorkspaceTab("directory", "users")}
                >
                  <div className="card-title">Verzeichnis &amp; GPOs</div>
                  <div className="card-value">{activeUsers} / {users.length}</div>
                  <div className="ca-muted">{secGroups.length} Gruppen · {policies.length} GPOs</div>
                </button>
                <button
                  type="button"
                  className="card dc-kpi-btn"
                  onClick={() => openWorkspaceTab("machines")}
                >
                  <div className="card-title">Flotte &amp; LAPS</div>
                  <div className="card-value">{activeMachines} / {machines.length}</div>
                  <div className="ca-muted">
                    {fleetHealth ? `${fleetHealth.heartbeats.length} Heartbeats · ${lapsPending} LAPS offen` : "—"}
                  </div>
                </button>
                <button
                  type="button"
                  className="card dc-kpi-btn"
                  onClick={() => openWorkspaceTab("network", "ca")}
                >
                  <div className="card-title">Netzwerk &amp; PKI</div>
                  <div className="card-value">{activeRoutes.length} Routen</div>
                  <div className="ca-muted">
                    X.509 {caStatus?.x509_root_initialized ? "OK" : "Offen"} · SSH {caStatus?.ssh_ca_initialized ? "OK" : "Offen"}
                  </div>
                </button>
                <button
                  type="button"
                  className="card dc-kpi-btn"
                  onClick={() => openWorkspaceTab("workspace", "account")}
                >
                  <div className="card-title">Aktive Tickets</div>
                  <div className="card-value">{1 + elevations.length + (meSshCert ? 1 : 0)}</div>
                  <div className="ca-muted">
                    {refreshToken && autoRenew ? "Auto-Renewal EIN" : "Manuell"}
                  </div>
                </button>
                <div className="card">
                  <div className="card-title">DC-Backup</div>
                  <div className="card-value">
                    {backupStatus && backupStatus.backup_count > 0 ? (
                      <span className="badge badge-ok">
                        {backupStatus.backup_count} ARCHIV(E){backupStatus.encrypted ? " · SBBK1" : ""}
                      </span>
                    ) : (
                      <span className="badge badge-warn">KEIN BACKUP</span>
                    )}
                  </div>
                  <div className="ca-muted">
                    {backupStatus?.last_backup_at
                      ? `Letztes: ${new Date(backupStatus.last_backup_at).toLocaleString("de-DE")}`
                      : "Täglicher Timer oder 'sb server backup --encrypt'"}
                  </div>
                </div>
              </div>

              {/* Handlungsbedarf & Domänen-Synergien */}
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-header-row">
                  <div className="card-title">Domänen-Handlungsbedarf &amp; Synergie-Checks</div>
                  {machinesMissingDns.length === 0 && routesMissingDns.length === 0 && lapsPending === 0 && (
                    <span className="badge badge-ok">ALLE CHECKS GRÜN</span>
                  )}
                </div>
                <div className="ca-badge-group" style={{ marginTop: 4 }}>
                  {machinesMissingDns.length > 0 && (
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("machines")}
                    >
                      {machinesMissingDns.length} Maschine(n) ohne DNS A-Record → In Flotte beheben
                    </button>
                  )}
                  {routesMissingDns.length > 0 && (
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("network", "ca")}
                    >
                      {routesMissingDns.length} Proxy-Route(n) ohne DNS-Record → Im Netzwerk prüfen
                    </button>
                  )}
                  {lapsPending > 0 && (
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("machines")}
                    >
                      {lapsPending} LAPS-Rotation(en) ausstehend → Flotte öffnen
                    </button>
                  )}
                  {auditValid === false && (
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("security", "audit")}
                    >
                      Audit-Hash-Kette prüfen!
                    </button>
                  )}
                  {machinesMissingDns.length === 0 && routesMissingDns.length === 0 && lapsPending === 0 && auditValid !== false && (
                    <span className="ca-muted">
                      Alle aktiven Maschinen und Proxy-Routen sind im Split-DNS registriert und keine LAPS-Rotation steht aus.
                    </span>
                  )}
                </div>
              </div>

              {/* Letzte Audit-Events & Schnellzugriff */}
              <div className="grid" style={{ marginBottom: 16 }}>
                <div className="card">
                  <div className="card-header-row">
                    <div className="card-title">Letzte Audit-Events</div>
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("security", "audit")}
                    >
                      Alle ({auditEvents.length})
                    </button>
                  </div>
                  {auditEvents.slice(0, 5).length === 0 ? (
                    <p className="ca-muted">Keine Audit-Events geladen.</p>
                  ) : (
                    <ul className="dc-mini-list">
                      {auditEvents.slice(0, 5).map((ev) => (
                        <li key={ev.seq}>
                          <code>{ev.actor}</code> → <strong>{ev.action}</strong> ({ev.target})
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="card">
                  <div className="card-header-row">
                    <div className="card-title">Eigene Tickets &amp; Sicherheit</div>
                    <button
                      type="button"
                      className="btn-secondary btn-compact"
                      onClick={() => openWorkspaceTab("workspace", "account")}
                    >
                      Tickets verwalten
                    </button>
                  </div>
                  <ul className="dc-mini-list">
                    <li>
                      Browser-Sitzung: <strong>{refreshToken && autoRenew ? "Auto-Renewal aktiv" : "Manuell"}</strong>
                    </li>
                    <li>
                      Aktive JIT-Admin-Tickets: <strong>{elevations.length}</strong>
                    </li>
                    <li>
                      SSH User Cert: <strong>{meSshCert ? "Ausgestellt (8h)" : "Bei Bedarf anfordern"}</strong>
                    </li>
                  </ul>
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
                      await pushHttpError("overview", "App speichern", res);
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
          );
        })()}

        {tab === "workspace" && (
          <>
            <div className="dc-subtabs" role="tablist" aria-label="Konto und Tresor">
              <button
                type="button"
                role="tab"
                aria-selected={workspaceSub === "account"}
                className={`dc-subtab ${workspaceSub === "account" ? "active" : ""}`}
                onClick={() => setWorkspaceSub("account")}
              >
                Konto, Tickets &amp; Passkeys
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={workspaceSub === "vault"}
                className={`dc-subtab ${workspaceSub === "vault" ? "active" : ""}`}
                onClick={() => setWorkspaceSub("vault")}
              >
                Passwort-Tresor ({vaultEntries.length + teamEntries.length})
              </button>
            </div>

            {workspaceSub === "account" && (
              <>
            <TicketsPanel
              token={token}
              refreshToken={refreshToken}
              autoRenew={autoRenew}
              onToggleAutoRenew={(next) => {
                setAutoRenew(next);
                localStorage.setItem("sb_auto_renew", next ? "true" : "false");
              }}
              onRefreshSession={async () => {
                const next = await tryRefreshSession();
                if (next) {
                  pushNotice("workspace", buildNotice("success", "Sitzung erneuert", "Neues Access-Token ausgestellt."));
                  return true;
                }
                pushNotice("workspace", buildNotice("error", "Erneuerung fehlgeschlagen", "Bitte erneut anmelden."));
                return false;
              }}
              elevations={elevations}
              sshCertRaw={meSshCert}
              onIssueSshCert={async () => {
                const res = await fetch("/v1/me/ssh-cert", {
                  method: "POST",
                  headers: { "Content-Type": "application/json", ...authHeaders() },
                  body: JSON.stringify({ ttl_seconds: 28800 }),
                });
                if (res.ok) {
                  setMeSshCert(await res.text());
                  pushNotice("workspace", buildNotice("success", "SSH-Zertifikat erneuert", "Neues 8h-Zertifikat ausgestellt."));
                } else {
                  await pushHttpError("workspace", "SSH-Zertifikat erneuern", res);
                }
              }}
            />

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
                      await pushHttpError("me", "SSH-Key hinterlegen", res);
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
                    if (res.ok) {
                      const text = await res.text();
                      setMeSshCert(text);
                      pushNotice("me", buildNotice("success", "SSH-Zertifikat ausgestellt", "Das 8h-Zertifikat ist bereit."));
                    } else {
                      await pushHttpError("me", "SSH-Zertifikat anfordern", res);
                    }
                  }}
                >
                  8h SSH-Zertifikat holen
                </button>
              </div>
              {meSshCert && (() => {
                let parsed: Record<string, unknown> | null = null;
                try {
                  parsed = JSON.parse(meSshCert) as Record<string, unknown>;
                } catch {
                  parsed = null;
                }
                const certText = typeof parsed?.certificate === "string" ? parsed.certificate : meSshCert;
                const principals = Array.isArray(parsed?.principals) ? parsed.principals.join(", ") : null;
                const validUntil = typeof parsed?.valid_until === "string" ? parsed.valid_until : null;
                return (
                  <div className="ca-key-row" style={{ marginTop: 10, alignItems: "flex-start", flexDirection: "column" }}>
                    <div className="ca-badge-group" style={{ marginTop: 0 }}>
                      <span className="badge badge-ok">8h SSH-Zertifikat aktiv</span>
                      {principals && <span className="badge badge-warn">Principals: {principals}</span>}
                      {validUntil && <span className="ca-muted">Gültig bis: {validUntil}</span>}
                    </div>
                    <div className="ca-key-row" style={{ width: "100%" }}>
                      <code className="ca-mono-pill" title={certText}>{certText}</code>
                      <button
                        type="button"
                        className="btn-secondary btn-compact"
                        onClick={async () => {
                          await navigator.clipboard.writeText(certText);
                          pushNotice("me", buildNotice("success", "Kopiert", "SSH-Zertifikat in die Zwischenablage kopiert."));
                        }}
                      >
                        Kopieren
                      </button>
                    </div>
                  </div>
                );
              })()}
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
                      pushNotice("me", buildNotice("success", "Passwort aktualisiert", "Ihr neues Domänen-Passwort ist sofort aktiv."));
                    } else {
                      await pushHttpError("me", "Passwort ändern", res);
                    }
                  }}
                >
                  Passwort speichern
                </button>
              </div>
            </div>

            <PasskeyPanel
              authHeaders={authHeaders}
              onStatus={(ok, title, detail) =>
                pushNotice("me", buildNotice(ok ? "success" : "error", title, detail))
              }
            />

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
                    if (res.ok) {
                      setElevOut(await res.text());
                      pushNotice("me", buildNotice("success", "JIT-Rechte aktiviert", `Regel '${elevRuleId}' für 30 Minuten aktiv.`));
                      await refreshAll();
                    } else {
                      await pushHttpError("me", "JIT-Rechte anfordern", res);
                    }
                  }}
                >
                  30 Min anfordern
                </button>
              </div>
              {elevOut && (
                <div className="ca-badge-group">
                  <span className="badge badge-ok">Elevation aktiv (30 Min)</span>
                  <span className="ca-muted">Regel: {elevRuleId}</span>
                </div>
              )}
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

            {workspaceSub === "vault" && (
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
                      await pushHttpError("vault", "Tresor-Aktion", res);
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
                      await pushHttpError("vault", "Team-Tresor-Aktion", res);
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
          </>
        )}

        {tab === "directory" && (
          <>
            <div className="dc-subtabs" role="tablist" aria-label="Verzeichnis und Policies">
              <button
                type="button"
                role="tab"
                aria-selected={directorySub === "users"}
                className={`dc-subtab ${directorySub === "users" ? "active" : ""}`}
                onClick={() => setDirectorySub("users")}
              >
                Benutzer, OUs &amp; Gruppen ({users.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={directorySub === "policies"}
                className={`dc-subtab ${directorySub === "policies" ? "active" : ""}`}
                onClick={() => setDirectorySub("policies")}
              >
                GPO Policies ({policies.length})
              </button>
            </div>

            {directorySub === "users" && (
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
                  placeholder="OU (z. B. /Engineering)"
                  value={newUserOu}
                  onChange={(e) => setNewUserOu(e.target.value)}
                  style={{ width: 150 }}
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
                        ou: newUserOu || "/",
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
                      await pushHttpError("users", "Benutzer anlegen", res);
                    }
                  }}
                >
                  Speichern
                </button>
              </div>
            </div>

            <div className="grid" style={{ marginBottom: 16 }}>
              <div className="card">
                <div className="card-title">Organisationseinheiten / OUs ({ous.length})</div>
                <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
                  <input
                    className="input"
                    placeholder="/Engineering/Backend"
                    value={newOuPath}
                    onChange={(e) => setNewOuPath(e.target.value)}
                  />
                  <input
                    className="input"
                    placeholder="Beschreibung"
                    value={newOuDesc}
                    onChange={(e) => setNewOuDesc(e.target.value)}
                  />
                  <button
                    className="btn btn-primary"
                    onClick={async () => {
                      const r = await fetch("/v1/ous", {
                        method: "POST",
                        headers: { "Content-Type": "application/json", ...authHeaders() },
                        body: JSON.stringify({ path: newOuPath, description: newOuDesc }),
                      });
                      if (r.ok) {
                        setNewOuDesc("");
                        await refreshAll();
                      } else {
                        await pushHttpError("users", "OU zuweisen", r);
                      }
                    }}
                  >
                    OU speichern
                  </button>
                </div>
                <table className="table">
                  <thead><tr><th>OU-Pfad</th><th>Beschreibung</th></tr></thead>
                  <tbody>
                    {ous.map((o) => (
                      <tr
                        key={o.path}
                        style={{
                          cursor: "pointer",
                          background: dirFilterOu === o.path ? "rgba(82, 199, 189, 0.1)" : undefined,
                        }}
                        onClick={() => setDirFilterOu((prev) => (prev === o.path ? "" : o.path))}
                      >
                        <td><code>{o.path}</code></td>
                        <td>{o.description || "—"}</td>
                      </tr>
                    ))}
                    {ous.length === 0 && (
                      <tr><td colSpan={2} style={{ color: "var(--muted)" }}>Nur Root-OU <code>/</code> aktiv.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="card">
                <div className="card-title">Sicherheitsgruppen ({secGroups.length})</div>
                <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <input
                    className="input"
                    placeholder="Gruppenname"
                    value={newGrpName}
                    onChange={(e) => setNewGrpName(e.target.value)}
                    style={{ width: 130 }}
                  />
                  <input
                    className="input"
                    placeholder="OU (/)"
                    value={newGrpOu}
                    onChange={(e) => setNewGrpOu(e.target.value)}
                    style={{ width: 110 }}
                  />
                  <input
                    className="input"
                    placeholder="Maschinen (kommagetrennt, leer = alle)"
                    value={newGrpMachines}
                    onChange={(e) => setNewGrpMachines(e.target.value)}
                  />
                  <label style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "0.82rem" }}>
                    <input
                      type="checkbox"
                      checked={newGrpAdmin}
                      onChange={(e) => setNewGrpAdmin(e.target.checked)}
                    />
                    Lokaler Admin
                  </label>
                  <button
                    className="btn btn-primary"
                    onClick={async () => {
                      const r = await fetch("/v1/groups", {
                        method: "POST",
                        headers: { "Content-Type": "application/json", ...authHeaders() },
                        body: JSON.stringify({
                          name: newGrpName,
                          description: "",
                          ou: newGrpOu || "/",
                          is_local_admin: newGrpAdmin,
                          allowed_machines: newGrpMachines.split(",").map((s) => s.trim()).filter(Boolean),
                          members: [],
                          updated_at: "",
                        }),
                      });
                      if (r.ok) {
                        setNewGrpName("");
                        setNewGrpMachines("");
                        await refreshAll();
                      } else {
                        await pushHttpError("users", "Gruppen zuweisen", r);
                      }
                    }}
                  >
                    Gruppe speichern
                  </button>
                </div>
                <table className="table">
                  <thead><tr><th>Gruppe</th><th>OU</th><th>OS-Admin</th><th>Maschinen</th></tr></thead>
                  <tbody>
                    {secGroups.map((g) => (
                      <tr
                        key={g.name}
                        style={{
                          cursor: "pointer",
                          background: dirFilterGroup === g.name ? "rgba(82, 199, 189, 0.1)" : undefined,
                        }}
                        onClick={() => setDirFilterGroup((prev) => (prev === g.name ? "" : g.name))}
                      >
                        <td><code>{g.name}</code></td>
                        <td><code>{g.ou || "/"}</code></td>
                        <td>{g.is_local_admin ? <span className="badge badge-ok">ADMIN</span> : "User"}</td>
                        <td>{g.allowed_machines?.length ? g.allowed_machines.join(", ") : "Alle"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {(() => {
              const filteredUsers = users.filter((u) => {
                if (dirFilterGroup && !u.groups.includes(dirFilterGroup)) return false;
                if (dirFilterOu) {
                  const matchingGroups = secGroups
                    .filter((g) => (g.ou || "/") === dirFilterOu)
                    .map((g) => g.name);
                  if (!u.groups.some((ug) => matchingGroups.includes(ug))) return false;
                }
                return true;
              });
              return (
                <div className="card">
                  <div className="ca-toolbar" style={{ marginBottom: 10 }}>
                    <div className="card-title" style={{ marginBottom: 0 }}>
                      Benutzer ({filteredUsers.length} / {users.length})
                    </div>
                    {(dirFilterOu || dirFilterGroup) && (
                      <div className="ca-badge-group" style={{ marginTop: 0 }}>
                        {dirFilterOu && <span className="badge badge-ok">OU: {dirFilterOu}</span>}
                        {dirFilterGroup && <span className="badge badge-ok">Gruppe: {dirFilterGroup}</span>}
                        <button
                          type="button"
                          className="btn-secondary btn-compact"
                          onClick={() => {
                            setDirFilterOu("");
                            setDirFilterGroup("");
                          }}
                        >
                          Filter zurücksetzen
                        </button>
                      </div>
                    )}
                  </div>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>E-Mail</th>
                        <th>Gruppen</th>
                        <th>Geräte</th>
                        <th>Status</th>
                        <th>Aktion</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredUsers.map((u) => {
                        const userMachines = machines.filter((m) => m.joined_by === u.username && !m.revoked);
                        return (
                          <tr key={u.username}>
                            <td><code>{u.username}</code></td>
                            <td>{u.email}</td>
                            <td>{u.groups.join(", ")}</td>
                            <td>
                              {userMachines.length > 0 ? (
                                <button
                                  type="button"
                                  className="btn-secondary btn-compact"
                                  onClick={() => openWorkspaceTab("machines")}
                                >
                                  {userMachines.length} Gerät(e)
                                </button>
                              ) : (
                                <span className="ca-muted">0</span>
                              )}
                            </td>
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
                        );
                      })}
                      {filteredUsers.length === 0 && (
                        <tr>
                          <td colSpan={6} style={{ color: "var(--muted)" }}>
                            {users.length === 0
                              ? "Keine Benutzer geladen (Bearer Token mit directory:read oder domain:admin erforderlich)."
                              : "Keine Benutzer für den gewählten OU-/Gruppen-Filter gefunden."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              );
            })()}
              </>
            )}

            {directorySub === "policies" && (
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
                        if (res.ok) {
                          setGpoOut(`Policy '${gpoId}' gespeichert.`);
                          pushNotice("directory", buildNotice("success", "GPO gespeichert", `Policy '${gpoId}' ist sofort aktiv.`));
                          await refreshAll();
                        } else {
                          await pushHttpError("directory", "GPO speichern", res);
                        }
                      }}
                    >
                      Speichern
                    </button>
                  </div>
                  {gpoOut && (
                    <div className="ca-badge-group" style={{ marginTop: 10 }}>
                      <span className="badge badge-ok">{gpoOut}</span>
                    </div>
                  )}
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
                            Noch keine GPO-Policies vorhanden. Erstelle eine über <code>sb-node policy put</code> oder den Editor oben.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}
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
              {enrollPkg && (
                <div className="grid" style={{ marginBottom: 0, marginTop: 8 }}>
                  <div className="card" style={{ padding: 14 }}>
                    <div className="card-header-row">
                      <span className="card-title">Enrollment-Token bereit</span>
                      <span className="badge badge-ok">BEREIT</span>
                    </div>
                    <div className="ca-muted" style={{ marginBottom: 8 }}>
                      Domäne: <strong>{String(enrollPkg.domain ?? enrollDomain)}</strong> · Endpunkt:{" "}
                      <code>{String(enrollPkg.api_endpoint ?? "/v1/machines/join")}</code>
                    </div>
                    {typeof enrollPkg.token === "string" && (
                      <div className="ca-key-row">
                        <code className="ca-mono-pill" title={enrollPkg.token}>{enrollPkg.token}</code>
                        <button
                          type="button"
                          className="btn-secondary btn-compact"
                          onClick={async () => {
                            await navigator.clipboard.writeText(String(enrollPkg.token));
                            pushNotice("machines", buildNotice("success", "Token kopiert", "Enrollment-Token in die Zwischenablage kopiert."));
                          }}
                        >
                          Kopieren
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}
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
                      await pushHttpError("machines", "Paket zuweisen", res);
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
                    <th>DNS &amp; Proxy-Synergie</th>
                    <th>Joined By</th>
                    <th>GPO / LAPS-Sync</th>
                    <th>Status</th>
                    <th>Aktionen</th>
                  </tr>
                </thead>
                <tbody>
                  {machines.map((m) => {
                    const hb = fleetHealth?.heartbeats.find((h) => h.machine_id === m.machine_id);
                    const hasDns = knownDnsDomains.has(m.fqdn.toLowerCase());
                    const shortHost = m.fqdn.split(".")[0].toLowerCase();
                    const machineRoutes = (routes as ProxyRouteItem[]).filter(
                      (r) =>
                        (r.node_callsign ?? "").toLowerCase() === shortHost ||
                        (r.node_callsign ?? "").toLowerCase() === m.fqdn.toLowerCase(),
                    );
                    return (
                    <tr key={m.machine_id}>
                      <td>{m.fqdn}</td>
                      <td>{m.os}</td>
                      <td>{m.mesh_ip}</td>
                      <td>
                        <div className="ca-badge-group" style={{ marginTop: 0 }}>
                          {hasDns ? (
                            <span className="badge badge-ok">DNS OK</span>
                          ) : m.mesh_ip ? (
                            <button
                              type="button"
                              className="btn-secondary btn-compact"
                              onClick={() => void createDnsARecord(m.fqdn, m.mesh_ip, "machines")}
                            >
                              + DNS A-Record
                            </button>
                          ) : (
                            <span className="badge badge-warn">Keine IP</span>
                          )}
                          {machineRoutes.length > 0 && (
                            <button
                              type="button"
                              className="badge badge-ok"
                              style={{ border: "none", cursor: "pointer" }}
                              onClick={() => openWorkspaceTab("network", "ca")}
                            >
                              {machineRoutes.length} Proxy-Route(n)
                            </button>
                          )}
                        </div>
                      </td>
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
                        <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
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
                              if (r.ok) {
                                pushNotice("machines", buildNotice("info", "Notfall-Passwort abgerufen", await r.text()));
                              } else {
                                await pushHttpError("machines", "Notfall-Passwort abrufen", r);
                              }
                            }}
                          >
                            Notfall-PW
                          </button>
                          <button
                            className="btn"
                            onClick={async () => {
                              const r = await fetch(`/v1/machines/${encodeURIComponent(m.machine_id)}/laps/rotate-request`, {
                                method: "POST",
                                headers: { ...authHeaders() },
                              });
                              if (r.ok) {
                                setStatusMsg(`LAPS-Rotation für ${m.fqdn} angefordert — Agent führt sie beim nächsten Sync (≤60s) aus.`);
                              } else {
                                if (r.ok) {
                                pushNotice("machines", buildNotice("info", "Notfall-Passwort abgerufen", await r.text()));
                              } else {
                                await pushHttpError("machines", "Notfall-Passwort abrufen", r);
                              }
                              }
                            }}
                          >
                            LAPS rotieren
                          </button>
                          <button
                            className="btn"
                            disabled={m.revoked}
                            onClick={() => openTerminalWindow(m)}
                          >
                            SSH Terminal
                          </button>
                          <button
                            className="btn"
                            disabled={m.revoked}
                            onClick={() => openFilesWindow(m)}
                          >
                            Dateien
                          </button>
                          <button
                            className="btn"
                            disabled={m.revoked}
                            onClick={() => {
                              const raw = window.prompt(
                                `Remote-Port auf ${m.fqdn} für den HTTPS-443 Tunnel (z. B. 3389 für RDP, 5432 für Postgres, 8080):`,
                                "3389"
                              );
                              if (!raw) return;
                              const port = Number(raw.trim());
                              if (!Number.isInteger(port) || port < 1 || port > 65535) {
                                setStatusMsg("Ungültiger Port (1–65535)");
                                return;
                              }
                              setStatusMsg(
                                `Tunnel-Befehl für ${m.fqdn}: sb tunnel ${m.machine_id} ${port}`
                              );
                            }}
                          >
                            Port tunneln
                          </button>
                        </div>
                      </td>
                    </tr>
                    );
                  })}
                  {machines.length === 0 && (
                    <tr>
                      <td colSpan={8} style={{ color: "var(--muted)" }}>
                        Keine Maschinen geladen (Bearer Token mit <code>domain:read</code> oben eintragen &amp; Refresh).
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {sshSession && (
              <div className="card" style={{ marginTop: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 8, flexWrap: "wrap" }}>
                  <div>
                    <div className="card-title" style={{ marginBottom: 2 }}>
                      Mesh-SSH Terminal: {sshSession.ssh_user}@{sshSession.fqdn} ({sshSession.mesh_ip})
                    </div>
                    <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                      Cert Principals: {sshSession.principals.join(", ")} · CLI: <code>{sshSession.cli_fallback}</code>
                    </div>
                  </div>
                  <button
                    className="btn"
                    onClick={async () => {
                      await fetch(`/v1/ssh/sessions/${encodeURIComponent(sshSession.session_id)}`, {
                        method: "DELETE",
                        headers: { ...authHeaders() },
                      }).catch(() => {});
                      setSshSession(null);
                      setSshLog("");
                    }}
                  >
                    Session schließen
                  </button>
                </div>

                <div style={{ display: "flex", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
                  {["whoami", "hostname", "dir", "sb-node domain status"].map((quick) => (
                    <button
                      key={quick}
                      className="btn"
                      disabled={sshBusy}
                      onClick={() => setSshCmd(quick)}
                    >
                      {quick}
                    </button>
                  ))}
                </div>

                <pre
                  style={{
                    background: "#0b0f14",
                    color: "#d9e6f2",
                    padding: 12,
                    borderRadius: 8,
                    minHeight: 180,
                    maxHeight: 340,
                    overflowY: "auto",
                    fontSize: "0.85rem",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    marginBottom: 10,
                  }}
                >
                  {sshLog}
                </pre>

                <form
                  style={{ display: "flex", gap: 8, alignItems: "center" }}
                  onSubmit={async (e) => {
                    e.preventDefault();
                    const cmd = sshCmd.trim();
                    if (!cmd || sshBusy) return;
                    setSshBusy(true);
                    setSshHistory((prev) => (prev[prev.length - 1] === cmd ? prev : [...prev, cmd]));
                    setSshHistoryIdx(-1);
                    const promptLabel = `${sshSession.ssh_user}@${sshSession.fqdn} ${sshCwd}>`;
                    setSshLog((prev) => `${prev}\n${promptLabel} ${cmd}\n`);
                    setSshCmd("");
                    try {
                      const r = await fetch(`/v1/ssh/sessions/${encodeURIComponent(sshSession.session_id)}/exec`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json", ...authHeaders() },
                        body: JSON.stringify({ command: cmd }),
                      });
                      const res = await r.json().catch(() => ({}));
                      if (res.cwd) {
                        setSshCwd(res.cwd);
                      }
                      if (!r.ok) {
                        setSshLog((prev) => `${prev}[Fehler ${r.status}] ${res.error || "Ausführung fehlgeschlagen"}\n`);
                      } else {
                        const out = [res.stdout, res.stderr].filter(Boolean).join("");
                        setSshLog((prev) => `${prev}${out}${out.endsWith("\n") || !out ? "" : "\n"}[exit ${res.exit_code}]\n`);
                      }
                    } finally {
                      setSshBusy(false);
                    }
                  }}
                >
                  <span style={{ fontFamily: "monospace", fontSize: "0.85rem", color: "var(--muted)", whiteSpace: "nowrap" }}>
                    {sshCwd}&gt;
                  </span>
                  <input
                    className="input"
                    style={{ flex: 1 }}
                    placeholder="Befehl eingeben (z. B. cd C:\Users\leonf oder dir) und Enter drücken..."
                    value={sshCmd}
                    onChange={(e) => {
                      setSshCmd(e.target.value);
                      setSshHistoryIdx(-1);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "ArrowUp") {
                        if (sshHistory.length === 0) return;
                        e.preventDefault();
                        const nextIdx =
                          sshHistoryIdx === -1
                            ? sshHistory.length - 1
                            : Math.max(0, sshHistoryIdx - 1);
                        setSshHistoryIdx(nextIdx);
                        setSshCmd(sshHistory[nextIdx]);
                      } else if (e.key === "ArrowDown") {
                        if (sshHistoryIdx === -1) return;
                        e.preventDefault();
                        const nextIdx = sshHistoryIdx + 1;
                        if (nextIdx >= sshHistory.length) {
                          setSshHistoryIdx(-1);
                          setSshCmd("");
                        } else {
                          setSshHistoryIdx(nextIdx);
                          setSshCmd(sshHistory[nextIdx]);
                        }
                      }
                    }}
                    disabled={sshBusy}
                  />
                  <button className="btn" type="submit" disabled={sshBusy}>
                    {sshBusy ? "Läuft..." : "Ausführen"}
                  </button>
                </form>
              </div>
            )}
          </>
        )}

        {tab === "network" && (
          <>
            <div className="dc-subtabs" role="tablist" aria-label="Netzwerk und PKI">
              <button
                type="button"
                role="tab"
                aria-selected={networkSub === "ca"}
                className={`dc-subtab ${networkSub === "ca" ? "active" : ""}`}
                onClick={() => setNetworkSub("ca")}
              >
                CA &amp; Reverse-Proxy ({routes.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={networkSub === "dns"}
                className={`dc-subtab ${networkSub === "dns" ? "active" : ""}`}
                onClick={() => setNetworkSub("dns")}
              >
                DNS-Manager &amp; IPAM ({knownDnsDomains.size})
              </button>
            </div>

            {networkSub === "ca" && (
              <CaProxyPanel
                caStatus={caStatus as CaStatusData | null}
                routes={routes as ProxyRouteItem[]}
                knownDnsDomains={knownDnsDomains}
                onOpenDns={() => setNetworkSub("dns")}
                onCreateRoute={async (payload) => {
                  const res = await fetch("/v1/proxy/routes", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", ...authHeaders() },
                    body: JSON.stringify(payload),
                  });
                  if (res.ok) {
                    pushNotice("network", buildNotice("success", "Proxy-Route erstellt", `${payload.domain} wurde registriert.`));
                    await refreshAll();
                  } else {
                    await pushHttpError("network", "Proxy-Route erstellen", res);
                  }
                }}
                onToggleRouteStatus={async (id, active) => {
                  const res = await fetch(`/v1/proxy/routes/${encodeURIComponent(id)}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json", ...authHeaders() },
                    body: JSON.stringify({ active }),
                  });
                  if (res.ok) {
                    pushNotice("network", buildNotice("success", active ? "Route aktiviert" : "Route pausiert", `Status für '${id}' aktualisiert.`));
                    await refreshAll();
                  } else {
                    await pushHttpError("network", "Proxy-Status ändern", res);
                  }
                }}
                onDeleteRoute={async (id) => {
                  const res = await fetch(`/v1/proxy/routes/${encodeURIComponent(id)}`, {
                    method: "DELETE",
                    headers: { ...authHeaders() },
                  });
                  if (res.ok) {
                    pushNotice("network", buildNotice("success", "Proxy-Route gelöscht", `Route '${id}' wurde entfernt.`));
                    await refreshAll();
                  } else {
                    await pushHttpError("network", "Proxy-Route löschen", res);
                  }
                }}
              />
            )}

            {networkSub === "dns" && (
              <>
                <div className="card" style={{ marginBottom: 16 }}>
                  <div className="card-title">DNS-Eintrag hinzufügen</div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                    <select
                      aria-label="DNS Record Typ"
                      className="ca-select"
                      value={dnsNewType}
                      onChange={(e) => setDnsNewType(e.target.value as "A" | "AAAA" | "CNAME" | "TXT" | "SRV")}
                    >
                      <option value="A">A</option>
                      <option value="AAAA">AAAA</option>
                      <option value="CNAME">CNAME</option>
                      <option value="TXT">TXT</option>
                      <option value="SRV">SRV</option>
                    </select>
                    <input className="input" placeholder="app.corp.eu" value={dnsNewDomain} onChange={(e) => setDnsNewDomain(e.target.value)} />
                    <input
                      className="input"
                      placeholder={dnsNewType === "A" ? "10.42.0.50" : dnsNewType === "AAAA" ? "fd00::1" : "Zielwert"}
                      value={dnsNewIp}
                      onChange={(e) => setDnsNewIp(e.target.value)}
                    />
                    <button
                      className="btn btn-primary"
                      onClick={async () => {
                        const res = await fetch("/v1/dns/records", {
                          method: "POST",
                          headers: { "Content-Type": "application/json", ...authHeaders() },
                          body: JSON.stringify({ type: dnsNewType, domain: dnsNewDomain, value: dnsNewIp }),
                        });
                        if (res.ok) {
                          setDnsNewDomain("");
                          setDnsNewIp("");
                          pushNotice("network", buildNotice("success", `DNS ${dnsNewType}-Record gespeichert`, `${dnsNewDomain} wurde registriert.`));
                          await refreshAll();
                        } else {
                          await pushHttpError("network", "DNS-Eintrag speichern", res);
                        }
                      }}
                    >
                      Eintrag speichern
                    </button>
                  </div>
                </div>
                <DnsIpamPanel
                  dnsRecords={dnsRecords}
                  ipamData={ipamData}
                  onDeleteRecord={async (type, domain) => {
                    const res = await fetch("/v1/dns/records", {
                      method: "DELETE",
                      headers: { "Content-Type": "application/json", ...authHeaders() },
                      body: JSON.stringify({ type, domain }),
                    });
                    if (res.ok) {
                      pushNotice("network", buildNotice("success", "DNS-Eintrag gelöscht", `${type} ${domain} wurde entfernt.`));
                      await refreshAll();
                    } else {
                      await pushHttpError("network", "DNS-Eintrag löschen", res);
                    }
                  }}
                />
              </>
            )}
          </>
        )}

        {tab === "security" && (
          <>
            <div className="dc-subtabs" role="tablist" aria-label="Sicherheit und API">
              <button
                type="button"
                role="tab"
                aria-selected={securitySub === "audit"}
                className={`dc-subtab ${securitySub === "audit" ? "active" : ""}`}
                onClick={() => setSecuritySub("audit")}
              >
                Audit Log ({auditEvents.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={securitySub === "explorer"}
                className={`dc-subtab ${securitySub === "explorer" ? "active" : ""}`}
                onClick={() => setSecuritySub("explorer")}
              >
                Open Graph API Explorer
              </button>
            </div>

            {securitySub === "audit" && (() => {
          const q = auditQuery.trim().toLowerCase();
          const filteredAudit = q
            ? auditEvents.filter((ev) =>
                [ev.actor, ev.action, ev.target, ev.outcome].join(" ").toLowerCase().includes(q),
              )
            : auditEvents;
          return (
            <div className="card">
              <div className="ca-toolbar">
                <div className="card-title" style={{ marginBottom: 0 }}>
                  Audit Events ({filteredAudit.length} / {auditEvents.length}){" "}
                  {auditValid !== null && (
                    <span className={`badge ${auditValid ? "badge-ok" : "badge-err"}`}>
                      {auditValid ? "HASH-KETTE INTACT" : "MANIPULATION ERKANNT"}
                    </span>
                  )}
                </div>
                <div className="ca-field">
                  <label htmlFor="audit-search" className="ca-field-label">
                    Suche
                  </label>
                  <input
                    id="audit-search"
                    type="search"
                    className="ca-input"
                    value={auditQuery}
                    onChange={(e) => setAuditQuery(e.target.value)}
                    placeholder="Akteur, Aktion oder Ziel…"
                  />
                </div>
              </div>
              <div tabIndex={0} role="region" aria-label="Audit Events" className="table-wrapper">
                <table className="table responsive-table">
                  <thead>
                    <tr>
                      <th scope="col">#</th>
                      <th scope="col">Zeitpunkt</th>
                      <th scope="col">Akteur</th>
                      <th scope="col">Aktion</th>
                      <th scope="col">Ziel</th>
                      <th scope="col">Ergebnis</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAudit.map((ev) => (
                      <tr key={ev.seq}>
                        <th scope="row">{ev.seq}</th>
                        <td>{ev.timestamp}</td>
                        <td><code>{ev.actor}</code></td>
                        <td><code>{ev.action}</code></td>
                        <td>{ev.target}</td>
                        <td><span className="badge badge-ok">{ev.outcome}</span></td>
                      </tr>
                    ))}
                    {filteredAudit.length === 0 && (
                      <tr>
                        <td colSpan={6} className="ca-empty-cell">
                          {auditEvents.length === 0
                            ? "Keine Audit-Events geladen (Bearer Token mit audit:read oder domain:admin erforderlich)."
                            : "Keine passenden Audit-Events gefunden."}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })()}

        {securitySub === "explorer" && (
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
          </>
        )}
    </>
  );

  const renderedWindows: DesktopWindowItem[] = desktopWins.map((w) => ({
    ...w,
    icon:
      w.kind === "app"
        ? DESKTOP_SHORTCUTS.find((s) => s.tabId === w.tabId)?.icon
        : undefined,
    content:
      w.kind === "terminal" && w.machineId && w.fqdn ? (
        <Suspense fallback={<div className="card">Terminal wird geladen…</div>}><XtermTerminal
          machineId={w.machineId}
          fqdn={w.fqdn}
          authHeaders={authHeaders}
          onStatus={setStatusMsg}
        /></Suspense>
      ) : w.kind === "files" && w.machineId && w.fqdn ? (
        <Suspense fallback={<div className="card">Dateimanager wird geladen…</div>}><FilesWindow
          machineId={w.machineId}
          fqdn={w.fqdn}
          authHeaders={authHeaders}
          onStatus={setStatusMsg}
        /></Suspense>
      ) : (
        renderTabContent((w.tabId as TabId) || "overview")
      ),
  }));

  return (
    <ThemeProvider theme={DEFAULT_WORKBENCH_THEMES.dark}>
      <DesktopShell
      windows={renderedWindows}
      focusedId={focusedWinId}
      domainName="skulls-and-bones.sb"
      username={meUser?.username || loginUser}
      statusMsg=""
      globalNotice={notices.global || null}
      onDismissGlobalNotice={() => dismissNotice("global")}
      onOpenShortcut={openShortcutWindow}
      onFocusWindow={focusWindow}
      onCloseWindow={closeWindow}
      onMinimizeWindow={minimizeWindow}
      onToggleMaximizeWindow={toggleMaximizeWindow}
      onMoveWindow={moveWindow}
      onResizeWindow={resizeWindow}
      onLogout={() => {
        saveSession("", "");
        setMeUser(null);
      }}
    />
    </ThemeProvider>
  );
}
