import React from "react";
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { Alert, Badge, IconButton } from "./index";
import type { ConsoleNotice } from "./errors";

interface NoticeBannerProps {
  notice: ConsoleNotice;
  onDismiss: () => void;
  compact?: boolean;
}

const VARIANT_MAP = {
  error: { variant: "danger" as const, badge: "danger" as const, Icon: AlertCircle },
  warning: { variant: "warning" as const, badge: "warning" as const, Icon: AlertTriangle },
  success: { variant: "success" as const, badge: "success" as const, Icon: CheckCircle2 },
  info: { variant: "info" as const, badge: "accent" as const, Icon: Info },
} as const;

export function NoticeBanner({ notice, onDismiss, compact = false }: NoticeBannerProps) {
  const cfg = VARIANT_MAP[notice.severity];
  const Icon = cfg.Icon;
  const isAlert = notice.severity === "error" || notice.severity === "warning";

  return (
    <Alert
      variant={cfg.variant}
      role={isAlert ? "alert" : "status"}
      aria-live={isAlert ? "assertive" : "polite"}
      style={{
        marginBottom: compact ? 0 : 14,
        padding: compact ? "10px 12px" : "12px 14px",
        boxShadow: "0 8px 24px rgba(0, 0, 0, 0.42)",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
        <Icon size={18} aria-hidden="true" style={{ flexShrink: 0, marginTop: 2 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
              fontWeight: 600,
              fontSize: "0.86rem",
            }}
          >
            <span>{notice.title}</span>
            {typeof notice.statusCode === "number" && (
              <Badge variant={cfg.badge}>
                HTTP {notice.statusCode}
              </Badge>
            )}
          </div>
          <div
            style={{
              marginTop: 4,
              fontSize: "0.81rem",
              lineHeight: 1.4,
              overflowWrap: "anywhere",
            }}
          >
            {notice.detail}
          </div>
          {notice.nextStep && (
            <div
              style={{
                marginTop: 5,
                fontSize: "0.78rem",
                lineHeight: 1.35,
                opacity: 0.85,
              }}
            >
              Nächster Schritt: {notice.nextStep}
            </div>
          )}
        </div>
        <IconButton
          aria-label="Meldung schließen"
          title="Schließen"
          variant="ghost"
          size="sm"
          onClick={onDismiss}
        >
          <X size={15} aria-hidden="true" />
        </IconButton>
      </div>
    </Alert>
  );
}
