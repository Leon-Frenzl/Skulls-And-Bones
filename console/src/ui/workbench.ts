export const WORKBENCH_KINDS = [
  "button",
  "badge",
  "card",
  "field",
  "alert",
] as const;

export type WorkbenchKind = (typeof WORKBENCH_KINDS)[number];
export type WorkbenchViewport = "desktop" | "tablet" | "mobile";
export type WorkbenchGap = "compact" | "normal" | "loose";
export type WorkbenchAlignment = "start" | "center" | "end" | "stretch";
export type WorkbenchThemeMode = "dark" | "light";

export interface WorkbenchTheme {
  mode: WorkbenchThemeMode;
  colors: {
    ink: string;
    panel: string;
    panelRaised: string;
    border: string;
    text: string;
    textSoft: string;
    muted: string;
    accent: string;
  };
  radii: {
    sm: number;
    md: number;
    lg: number;
  };
}

export interface WorkbenchItem {
  id: string;
  kind: WorkbenchKind;
  label: string;
  text: string;
  variant: string;
  size: "sm" | "md";
  span: 1 | 2 | 3;
  alignment: WorkbenchAlignment;
  note: string;
}

export interface WorkbenchDesign {
  schemaVersion: 1;
  id: string;
  title: string;
  viewport: WorkbenchViewport;
  layout: {
    columns: 1 | 2 | 3;
    gap: WorkbenchGap;
  };
  theme: WorkbenchTheme;
  items: WorkbenchItem[];
}

export const DEFAULT_WORKBENCH_THEMES: Record<
  WorkbenchThemeMode,
  WorkbenchTheme
> = {
  dark: {
    mode: "dark",
    colors: {
      ink: "#0b1113",
      panel: "#11191c",
      panelRaised: "#192326",
      border: "#304042",
      text: "#e9e4d9",
      textSoft: "#c5c9c2",
      muted: "#98a39e",
      accent: "#52c7bd",
    },
    radii: { sm: 6, md: 10, lg: 14 },
  },
  light: {
    mode: "light",
    colors: {
      ink: "#f4f6f3",
      panel: "#ffffff",
      panelRaised: "#e9efec",
      border: "#c7d2ce",
      text: "#182321",
      textSoft: "#344540",
      muted: "#52635e",
      accent: "#167d75",
    },
    radii: { sm: 6, md: 10, lg: 14 },
  },
};

const VARIANTS: Record<WorkbenchKind, readonly string[]> = {
  button: ["primary", "secondary", "ghost", "danger"],
  badge: ["neutral", "accent", "success", "warning", "danger"],
  card: ["default"],
  field: ["default"],
  alert: ["info", "success", "warning", "danger"],
};

const ALIGNMENTS: readonly WorkbenchAlignment[] = [
  "start",
  "center",
  "end",
  "stretch",
];
const VIEWPORTS: readonly WorkbenchViewport[] = ["desktop", "tablet", "mobile"];
const GAPS: readonly WorkbenchGap[] = ["compact", "normal", "loose"];
const THEME_MODES: readonly WorkbenchThemeMode[] = ["dark", "light"];
const THEME_COLOR_KEYS = [
  "ink",
  "panel",
  "panelRaised",
  "border",
  "text",
  "textSoft",
  "muted",
  "accent",
] as const;
const RADIUS_KEYS = ["sm", "md", "lg"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length <= maxLength;
}

function isColor(value: unknown): value is string {
  return typeof value === "string" && /^#[\da-f]{6}$/i.test(value);
}

export function validateWorkbenchDesign(
  value: unknown,
): value is WorkbenchDesign {
  if (!isRecord(value) || value.schemaVersion !== 1) return false;
  const anyVal = value as Record<string, any>;
  if (
    !isBoundedString(value.id, 64) ||
    !/^[a-z0-9][a-z0-9-]*$/.test(value.id) ||
    !isBoundedString(value.title, 100) ||
    value.title.trim().length === 0 ||
    !VIEWPORTS.includes(value.viewport as WorkbenchViewport) ||
    !isRecord(value.layout) ||
    ![1, 2, 3].includes(value.layout.columns as number) ||
    !GAPS.includes(value.layout.gap as WorkbenchGap) ||
    !isRecord(anyVal.theme) ||
    !THEME_MODES.includes(anyVal.theme.mode as WorkbenchThemeMode) ||
    !isRecord(anyVal.theme.colors) ||
    !THEME_COLOR_KEYS.every((key) => isColor(anyVal.theme.colors[key])) ||
    !isRecord(anyVal.theme.radii) ||
    !RADIUS_KEYS.every(
      (key) =>
        typeof anyVal.theme.radii[key] === "number" &&
        Number.isInteger(anyVal.theme.radii[key]) &&
        anyVal.theme.radii[key] >= 0 &&
        anyVal.theme.radii[key] <= 24,
    ) ||
    !Array.isArray(value.items) ||
    value.items.length > 40
  ) {
    return false;
  }

  const itemIds = new Set<string>();
  return value.items.every((item) => {
    if (!isRecord(item) || !WORKBENCH_KINDS.includes(item.kind as WorkbenchKind)) {
      return false;
    }

    const kind = item.kind as WorkbenchKind;
    if (
      !isBoundedString(item.id, 64) ||
      !/^[a-z0-9][a-z0-9-]*$/.test(item.id) ||
      itemIds.has(item.id) ||
      !isBoundedString(item.label, 80) ||
      !isBoundedString(item.text, 240) ||
      !isBoundedString(item.variant, 20) ||
      !VARIANTS[kind].includes(item.variant) ||
      (item.size !== "sm" && item.size !== "md") ||
      typeof item.span !== "number" ||
      !Number.isInteger(item.span) ||
      item.span < 1 ||
      item.span > 3 ||
      !ALIGNMENTS.includes(item.alignment as WorkbenchAlignment) ||
      !isBoundedString(item.note, 500)
    ) {
      return false;
    }
    itemIds.add(item.id);
    return true;
  });
}

export function createWorkbenchItem(
  kind: WorkbenchKind,
  id: string,
): WorkbenchItem {
  const defaults: Record<WorkbenchKind, Omit<WorkbenchItem, "id" | "kind">> = {
    button: {
      label: "Primäre Aktion",
      text: "Weiter",
      variant: "primary",
      size: "md",
      span: 1,
      alignment: "start",
      note: "",
    },
    badge: {
      label: "Status",
      text: "Aktiv",
      variant: "accent",
      size: "md",
      span: 1,
      alignment: "start",
      note: "",
    },
    card: {
      label: "Karte",
      text: "Inhalt der Karte",
      variant: "default",
      size: "md",
      span: 1,
      alignment: "start",
      note: "",
    },
    field: {
      label: "Projektname",
      text: "Mein Projekt",
      variant: "default",
      size: "md",
      span: 1,
      alignment: "start",
      note: "",
    },
    alert: {
      label: "Hinweis",
      text: "Eine kurze Statusmeldung.",
      variant: "info",
      size: "md",
      span: 1,
      alignment: "start",
      note: "",
    },
  };
  return { id, kind, ...defaults[kind] };
}
