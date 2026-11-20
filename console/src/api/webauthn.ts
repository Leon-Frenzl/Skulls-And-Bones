export interface PasskeyCredentialSummary {
  credential_id_b64: string;
  username: string;
  label: string;
  rp_id: string;
  alg: number;
  sign_count: number;
  created_at: string;
  last_used_at: string | null;
}

function b64UrlToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function bytesToB64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function isPasskeySupported(): Promise<boolean> {
  if (typeof window === "undefined" || typeof PublicKeyCredential === "undefined") {
    return false;
  }
  const pkc = PublicKeyCredential as unknown as {
    getClientCapabilities?: () => Promise<Record<string, boolean>>;
  };
  if (typeof pkc.getClientCapabilities === "function") {
    try {
      const caps = await pkc.getClientCapabilities();
      if (caps.passkeyPlatformAuthenticator === false && caps.conditionalGet === false) {
        return true; // External security keys (CTAP2) still work via navigator.credentials
      }
    } catch {
      // Ignore capability probe errors and fall back to standard WebAuthn check
    }
  }
  return typeof navigator.credentials?.create === "function";
}

function parseCreationOptions(raw: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const pkc = PublicKeyCredential as unknown as {
    parseCreationOptionsFromJSON?: (json: Record<string, unknown>) => PublicKeyCredentialCreationOptions;
  };
  if (typeof pkc.parseCreationOptionsFromJSON === "function") {
    return pkc.parseCreationOptionsFromJSON(raw);
  }
  const user = raw.user as Record<string, unknown>;
  const exclude = Array.isArray(raw.excludeCredentials)
    ? (raw.excludeCredentials as Array<Record<string, unknown>>).map((c) => ({
        type: "public-key" as const,
        id: b64UrlToBytes(String(c.id)),
      }))
    : [];
  return {
    ...(raw as unknown as PublicKeyCredentialCreationOptions),
    challenge: b64UrlToBytes(String(raw.challenge)),
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: b64UrlToBytes(String(user.id)),
    },
    excludeCredentials: exclude,
  };
}

function parseRequestOptions(raw: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const pkc = PublicKeyCredential as unknown as {
    parseRequestOptionsFromJSON?: (json: Record<string, unknown>) => PublicKeyCredentialRequestOptions;
  };
  if (typeof pkc.parseRequestOptionsFromJSON === "function") {
    return pkc.parseRequestOptionsFromJSON(raw);
  }
  const allow = Array.isArray(raw.allowCredentials)
    ? (raw.allowCredentials as Array<Record<string, unknown>>).map((c) => ({
        type: "public-key" as const,
        id: b64UrlToBytes(String(c.id)),
      }))
    : [];
  return {
    ...(raw as unknown as PublicKeyCredentialRequestOptions),
    challenge: b64UrlToBytes(String(raw.challenge)),
    allowCredentials: allow,
  };
}

async function signalUnknownIfSupported(rpId: string | undefined, credentialId: string): Promise<void> {
  if (!rpId || typeof PublicKeyCredential === "undefined") {
    return;
  }
  const pkc = PublicKeyCredential as unknown as {
    signalUnknownCredential?: (opts: { rpId: string; credentialId: string }) => Promise<void>;
  };
  if (typeof pkc.signalUnknownCredential === "function") {
    try {
      await pkc.signalUnknownCredential({ rpId, credentialId });
    } catch {
      // Best-effort signal sync
    }
  }
}

export async function registerPasskeyInBrowser(
  optionsJson: Record<string, unknown>,
  label: string,
  authHeaders: Record<string, string>
): Promise<PasskeyCredentialSummary> {
  const publicKey = parseCreationOptions(optionsJson);
  const rpId = publicKey.rp?.id;

  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    if (name === "InvalidStateError") {
      throw new Error("Für dieses Konto ist bereits ein Passkey auf diesem Gerät registriert.");
    }
    if (name === "NotAllowedError" || name === "AbortError") {
      throw new Error("Passkey-Registrierung wurde abgebrochen.");
    }
    if (name === "SecurityError") {
      throw new Error("Passkeys erfordern eine sichere HTTPS- oder localhost-Verbindung.");
    }
    throw err instanceof Error ? err : new Error("Passkey-Erstellung fehlgeschlagen.");
  }

  if (!cred) {
    throw new Error("Keine Passkey-Antwort vom Browser erhalten.");
  }

  const att = cred.response as AuthenticatorAttestationResponse & {
    getAuthenticatorData?: () => ArrayBuffer;
    getPublicKey?: () => ArrayBuffer | null;
    getPublicKeyAlgorithm?: () => number;
  };
  const encodedJson =
    typeof (cred as unknown as { toJSON?: () => { id?: string } }).toJSON === "function"
      ? (cred as unknown as { toJSON: () => { id: string } }).toJSON()
      : { id: bytesToB64Url(cred.rawId) };

  const authDataBuf = att.getAuthenticatorData?.();
  const pubKeyBuf = att.getPublicKey?.();
  if (!authDataBuf || !pubKeyBuf) {
    throw new Error("Browser unterstützt getAuthenticatorData()/getPublicKey() nicht.");
  }

  const payload = {
    credential_id: encodedJson.id,
    client_data_json: bytesToB64Url(att.clientDataJSON),
    auth_data: bytesToB64Url(authDataBuf),
    public_key: bytesToB64Url(pubKeyBuf),
    alg: att.getPublicKeyAlgorithm ? att.getPublicKeyAlgorithm() : -7,
    label,
  };

  try {
    const res = await fetch("/v1/auth/passkey/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      await signalUnknownIfSupported(rpId, encodedJson.id);
      const errText = await res.text().catch(() => "");
      throw new Error(errText || `Passkey-Registrierung fehlgeschlagen (HTTP ${res.status}).`);
    }
    return (await res.json()) as PasskeyCredentialSummary;
  } catch (err) {
    await signalUnknownIfSupported(rpId, encodedJson.id);
    throw err instanceof Error ? err : new Error("Netzwerkfehler bei Passkey-Registrierung.");
  }
}

export async function authenticateWithPasskeyOptions(
  optionsJson: Record<string, unknown>
): Promise<{ access_token: string; refresh_token?: string }> {
  const publicKey = parseRequestOptions(optionsJson);
  const rpId = publicKey.rpId;

  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    if (name === "NotAllowedError" || name === "AbortError") {
      throw new Error("Passkey-Anmeldung wurde abgebrochen.");
    }
    if (name === "SecurityError") {
      throw new Error("Passkeys erfordern eine sichere HTTPS- oder localhost-Verbindung.");
    }
    throw err instanceof Error ? err : new Error("Passkey-Abfrage fehlgeschlagen.");
  }

  if (!cred) {
    throw new Error("Kein Passkey ausgewählt.");
  }

  const assertion = cred.response as AuthenticatorAssertionResponse;
  const encodedJson =
    typeof (cred as unknown as { toJSON?: () => { id?: string } }).toJSON === "function"
      ? (cred as unknown as { toJSON: () => { id: string } }).toJSON()
      : { id: bytesToB64Url(cred.rawId) };

  const payload = {
    credential_id: encodedJson.id,
    client_data_json: bytesToB64Url(assertion.clientDataJSON),
    authenticator_data: bytesToB64Url(assertion.authenticatorData),
    signature: bytesToB64Url(assertion.signature),
  };

  const res = await fetch("/v1/auth/passkey/login/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    if (res.status === 404) {
      await signalUnknownIfSupported(rpId, encodedJson.id);
    }
    const errText = await res.text().catch(() => "");
    throw new Error(errText || `Passkey-Verifikation fehlgeschlagen (HTTP ${res.status}).`);
  }
  return (await res.json()) as { access_token: string; refresh_token?: string };
}
