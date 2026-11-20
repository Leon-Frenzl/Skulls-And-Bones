import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildNotice, formatHttpError, formatNetworkError } from "./errors.ts";
import { apiRequest } from "../api/client.ts";

describe("console error formatting", () => {
  it("parses JSON error bodies and sets actionable nextStep for 403", () => {
    const notice = formatHttpError(
      "Benutzer anlegen",
      403,
      JSON.stringify({ detail: "Missing capability domain:admin" })
    );
    assert.equal(notice.severity, "error");
    assert.equal(notice.statusCode, 403);
    assert.equal(notice.title, "Benutzer anlegen: Zugriff verweigert");
    assert.equal(notice.detail, "Missing capability domain:admin");
    assert.ok(notice.nextStep && notice.nextStep.length > 0);
  });

  it("maps 409 conflicts to warning severity", () => {
    const notice = formatHttpError("DNS-Eintrag", 409, "");
    assert.equal(notice.severity, "warning");
    assert.equal(notice.statusCode, 409);
  });

  it("maps Failed to fetch to readable German network guidance", () => {
    const notice = formatNetworkError("Datenabruf", new TypeError("Failed to fetch"));
    assert.equal(notice.severity, "error");
    assert.equal(notice.title, "Datenabruf: Verbindung fehlgeschlagen");
    assert.ok(notice.detail.includes("Domain Controller"));
  });

  it("builds typed notices with buildNotice", () => {
    const ok = buildNotice("success", "Gespeichert", "Eintrag aktiv");
    assert.equal(ok.severity, "success");
    assert.equal(ok.title, "Gespeichert");
  });

  it("normalizes HTTP errors in apiRequest without throwing", async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ detail: "Duplicate hostname" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;
    try {
      const res = await apiRequest("/v1/machines", "Maschine registrieren");
      assert.equal(res.ok, false);
      assert.equal(res.status, 409);
      assert.equal(res.notice?.severity, "warning");
      assert.equal(res.notice?.detail, "Duplicate hostname");
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
