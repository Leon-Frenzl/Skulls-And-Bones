---
name: standards-compliance
description: "Use when implementing or changing a protocol, file format, algorithm or interface that is defined by a published standard such as IETF RFC, IEEE, ISO, NIST, X.509, DNS, TLS, ACME, SSH, HTTP, Ed25519, WireGuard. Keywords: RFC, IEEE, standard, specification, conformance, MUST, SHOULD, deviation, interoperability."
argument-hint: "Feature or protocol to implement (e.g. DNS TCP framing, ACME TLS-ALPN-01)"
---

# Standards Compliance

Defined standards are authoritative. Deviate **only** if following the standard creates a security vulnerability.

## Procedure

1. **Identify** the governing standards (RFC numbers incl. updates/errata via `https://www.rfc-editor.org/info/rfcNNNN`, IEEE/ISO/NIST titles and versions). Fetch the text with the `fetch` MCP; do not rely on memory for MUST/SHOULD wording. IEEE/ISO documents are often paywalled: cite what is publicly verifiable and ask the maintainer for the rest instead of guessing.
2. **Extract requirements** – list every MUST / MUST NOT / SHOULD / REQUIRED relevant to the change with section references.
3. **Implement** exactly as specified (field sizes, byte order, state machines, error codes, timeouts, limits).
4. **Annotate** compliance in code: `// RFC 1035 §4.2.2: TCP messages are prefixed by a two-byte length.`
5. **Test** with the standard's own test vectors or examples where they exist; add negative tests for MUST NOT cases.
6. **Security exception** – if literal compliance causes a vulnerability (verified CVE/RUSTSEC/CWE, see `security-cve-audit`):
   - patch the behavior and deviate only as far as necessary,
   - annotate: `// DEVIATION(RFC NNNN §x.y): <what differs>. Reason: <identifier + risk>. Interop impact: <...>.`
   - cover with a test proving the safe behavior,
   - list the deviation in the crate's `.typ` documentation, section "Abweichungen vom Standard".
7. Never deviate for convenience, performance or taste.
