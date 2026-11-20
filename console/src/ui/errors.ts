export type NoticeSeverity = "error" | "warning" | "success" | "info";

export interface ConsoleNotice {
  id: string;
  scope: string;
  severity: NoticeSeverity;
  title: string;
  detail: string;
  nextStep?: string;
  statusCode?: number;
}

function extractRawMessage(rawBody?: string): string {
  const trimmed = (rawBody || "").trim();
  if (!trimmed) return "";
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    const candidate =
      parsed.detail || parsed.error || parsed.message || parsed.title;
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  } catch {
    // Plain-text error body; keep as-is
  }
  return trimmed.length > 220 ? `${trimmed.slice(0, 220)}…` : trimmed;
}

export function buildNotice(
  severity: NoticeSeverity,
  title: string,
  detail: string,
  nextStep?: string,
  statusCode?: number
): Omit<ConsoleNotice, "id" | "scope"> {
  return { severity, title, detail, nextStep, statusCode };
}

export function formatHttpError(
  actionLabel: string,
  status: number,
  rawBody?: string
): Omit<ConsoleNotice, "id" | "scope"> {
  const serverDetail = extractRawMessage(rawBody);

  switch (status) {
    case 400:
    case 422:
      return buildNotice(
        "error",
        `${actionLabel}: Ungültige Eingabe`,
        serverDetail || "Die gesendeten Daten erfüllen nicht das erwartete Format.",
        "Prüfen Sie alle Pflichtfelder und korrigieren Sie die Eingabe.",
        status
      );
    case 401:
      return buildNotice(
        "error",
        `${actionLabel}: Sitzung abgelaufen`,
        serverDetail || "Ihre Anmeldung ist ungültig oder abgelaufen.",
        "Melden Sie sich erneut an, um fortzufahren.",
        status
      );
    case 403:
      return buildNotice(
        "error",
        `${actionLabel}: Zugriff verweigert`,
        serverDetail || "Ihr Konto besitzt nicht die erforderliche Berechtigung.",
        "Fordern Sie ein passendes RBAC- oder JIT-Ticket an.",
        status
      );
    case 404:
      return buildNotice(
        "error",
        `${actionLabel}: Eintrag nicht gefunden`,
        serverDetail || "Das angeforderte Objekt existiert nicht oder wurde entfernt.",
        "Aktualisieren Sie die Ansicht und prüfen Sie die Auswahl.",
        status
      );
    case 409:
      return buildNotice(
        "warning",
        `${actionLabel}: Konflikt erkannt`,
        serverDetail || "Ein Eintrag mit diesem Namen oder dieser ID existiert bereits.",
        "Wählen Sie einen eindeutigen Namen oder aktualisieren Sie die Liste.",
        status
      );
    case 429:
      return buildNotice(
        "warning",
        `${actionLabel}: Zu viele Anfragen`,
        serverDetail || "Das Rate-Limit des Servers wurde vorübergehend erreicht.",
        "Warten Sie einige Sekunden und wiederholen Sie den Vorgang.",
        status
      );
    default:
      if (status >= 500) {
        return buildNotice(
          "error",
          `${actionLabel}: Serverfehler (${status})`,
          serverDetail || "Der Domain Controller konnte die Anfrage nicht verarbeiten.",
          "Prüfen Sie den Status von sb-node und die Server-Logs.",
          status
        );
      }
      return buildNotice(
        "error",
        `${actionLabel} fehlgeschlagen (${status})`,
        serverDetail || "Die Anfrage wurde vom Server abgewiesen.",
        "Prüfen Sie Ihre Eingaben und versuchen Sie es erneut.",
        status
      );
  }
}

export function formatNetworkError(
  actionLabel: string,
  err: unknown
): Omit<ConsoleNotice, "id" | "scope"> {
  const raw = err instanceof Error ? err.message : String(err || "");
  return buildNotice(
    "error",
    `${actionLabel}: Verbindung fehlgeschlagen`,
    raw && raw !== "Failed to fetch"
      ? raw
      : "Der Domain Controller antwortet nicht auf die Anfrage.",
    "Prüfen Sie Ihre Netzwerkverbindung sowie den Status von sb-node und sb-proxy."
  );
}
