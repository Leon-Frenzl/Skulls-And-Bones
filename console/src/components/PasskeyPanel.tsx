import React, { useEffect, useState } from "react";
import { KeyRound } from "lucide-react";
import {
  isPasskeySupported,
  registerPasskeyInBrowser,
  type PasskeyCredentialSummary,
} from "../api/webauthn";

interface PasskeyPanelProps {
  authHeaders: () => Record<string, string>;
  onStatus: (ok: boolean, title: string, detail: string) => void;
}

export function PasskeyPanel({ authHeaders, onStatus }: PasskeyPanelProps) {
  const [supported, setSupported] = useState(false);
  const [label, setLabel] = useState("Workstation Passkey");
  const [busy, setBusy] = useState(false);
  const [passkeys, setPasskeys] = useState<PasskeyCredentialSummary[]>([]);

  const loadPasskeys = async () => {
    const res = await fetch("/v1/auth/passkey/list", {
      headers: { ...authHeaders() },
    });
    if (res.ok) {
      const data = (await res.json()) as { passkeys?: PasskeyCredentialSummary[] };
      setPasskeys(data.passkeys || []);
    }
  };

  useEffect(() => {
    void isPasskeySupported().then(setSupported);
    void loadPasskeys();
  }, []);

  const handleRegister = async () => {
    setBusy(true);
    try {
      const startRes = await fetch("/v1/auth/passkey/register/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: "{}",
      });
      if (!startRes.ok) {
        const msg = await startRes.text().catch(() => "");
        onStatus(false, "Passkey-Start fehlgeschlagen", msg || `HTTP ${startRes.status}`);
        return;
      }
      const options = (await startRes.json()) as Record<string, unknown>;
      const created = await registerPasskeyInBrowser(options, label, authHeaders());
      onStatus(true, "Passkey registriert", `Passkey '${created.label}' ist jetzt für MFA aktiv.`);
      await loadPasskeys();
    } catch (err) {
      onStatus(
        false,
        "Passkey-Registrierung",
        err instanceof Error ? err.message : "Unbekannter Fehler"
      );
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (cred: PasskeyCredentialSummary) => {
    setBusy(true);
    try {
      const res = await fetch(`/v1/auth/passkey/${encodeURIComponent(cred.credential_id_b64)}`, {
        method: "DELETE",
        headers: { ...authHeaders() },
      });
      if (!res.ok) {
        const msg = await res.text().catch(() => "");
        onStatus(false, "Passkey löschen fehlgeschlagen", msg || `HTTP ${res.status}`);
        return;
      }
      const pkc = PublicKeyCredential as unknown as {
        signalUnknownCredential?: (opts: { rpId: string; credentialId: string }) => Promise<void>;
      };
      if (typeof pkc?.signalUnknownCredential === "function" && cred.rp_id) {
        try {
          await pkc.signalUnknownCredential({
            rpId: cred.rp_id,
            credentialId: cred.credential_id_b64,
          });
        } catch {
          // Best-effort browser credential signal
        }
      }
      onStatus(true, "Passkey entfernt", `Passkey '${cred.label}' wurde gelöscht.`);
      await loadPasskeys();
    } catch (err) {
      onStatus(
        false,
        "Passkey löschen",
        err instanceof Error ? err.message : "Unbekannter Fehler"
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <KeyRound size={16} aria-hidden="true" />
        Passkeys (FIDO2 / WebAuthn MFA)
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <input
          className="input"
          placeholder="Passkey-Bezeichnung (z. B. YubiKey)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          style={{ width: 260 }}
        />
        <button
          className="btn btn-primary"
          disabled={!supported || busy}
          onClick={() => void handleRegister()}
        >
          {busy ? "Warte auf Gerät..." : "Passkey registrieren"}
        </button>
      </div>
      {!supported && (
        <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8 }}>
          Passkeys erfordern einen WebAuthn-fähigen Browser über HTTPS oder localhost.
        </div>
      )}
      {passkeys.length > 0 ? (
        <div style={{ display: "grid", gap: 6 }}>
          {passkeys.map((pk) => (
            <div
              key={pk.credential_id_b64}
              style={{
                display: "flex",
                justifyContent: "space-between",
                fontSize: 13,
                padding: "6px 10px",
                borderRadius: 6,
                background: "rgba(255,255,255,0.03)",
              }}
            >
              <span>
                <strong>{pk.label}</strong> ({pk.rp_id})
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ color: "var(--muted)" }}>
                  Zähler: {pk.sign_count} · Erstellt: {pk.created_at.slice(0, 10)}
                </span>
                <button
                  type="button"
                  className="btn-secondary btn-compact"
                  disabled={busy}
                  onClick={() => void handleDelete(pk)}
                >
                  Löschen
                </button>
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          Noch kein Passkey registriert. Nach Registrierung wird beim Login automatisch Passkey-MFA verlangt.
        </div>
      )}
    </div>
  );
}
