# `sb-ca` — Sovereign Unified PKI & Certificate Authority Engine

`sb-ca` is the sovereign public key infrastructure engine for the Skulls & Bones ecosystem, providing dual-mode cryptographic certificate issuance for both **OpenSSH** and **X.509 mTLS** environments.

---

## 1. Architecture & Dual-Engine Capabilities

```
                      ┌────────────────────────────────────────┐
                      │                sb-ca                   │
                      │    S&B Sovereign Unified PKI Engine    │
                      └──────────────────┬─────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
   ┌───────────────────────────┐                   ┌───────────────────────────┐
   │    OpenSSH CA Engine      │                   │      X.509 CA Engine      │
   │      (`sb_ca::ssh`)       │                   │     (`sb_ca::x509`)       │
   └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                 │                                               │
   • Ed25519 Root CA (`~/.sb/ca/ssh/ca_key`)        • ECDSA P-256 Root CA (`~/.sb/ca/root_ca.crt`)
   • RFC 4251 / RFC 8709 Wire Format Public Key    • RFC 5280 / TLS 1.3 RFC 8446 Compliance
   • Short-lived User Certificates (TTL 1-8h)      • Wildcard & Mesh SANs (*.sbm, *.mesh)
   • Host Certificates for Server Provisioning     • ServerAuth & ClientAuth EKUs for mTLS
   • PROTOCOL.certkeys binary wire generation      • Dynamic On-Demand Issuance (<2ms)
   • Clock Drift Margin (-60s backdating)          • OS Trust Store Integration
```

### 1.1 OpenSSH CA (`sb_ca::ssh`)
- **Keypair**: Pure-Rust Ed25519 Root CA stored in `~/.sb/ca/ssh/ca_key` (POSIX mode 0600, memory zeroization).
- **Public Key**: Exported in standard OpenSSH RFC 4251 wire format (`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... sovereign-swarm-ca@local`) for `/etc/ssh/trusted_user_ca_keys`.
- **User Certificates**: Short-lived (default 1h, hard max 8h), bound to specific principals, with standard OpenSSH shell extensions (`permit-pty`, `permit-X11-forwarding`, `permit-agent-forwarding`, `permit-port-forwarding`, `permit-user-rc`).
- **Host Certificates**: Machine identity certificates bound to hostname principals.

### 1.2 X.509 CA (`sb_ca::x509`)
- **Root CA**: Self-signed ECDSA NIST P-256 with SHA-256 stored in `~/.sb/ca/root_ca.crt` and `~/.sb/ca/root_ca.key`.
- **SANs**: Supports wildcard mesh domains (`*.sbm`, `*.mesh`), explicit hostnames (`app.sbm`, `node-01.mesh`, `localhost`), and IP addresses (`127.0.0.1`).
- **mTLS**: Extended Key Usages include both `ServerAuth` (OID 1.3.6.1.5.5.7.3.1) and `ClientAuth` (OID 1.3.6.1.5.5.7.3.2).
- **On-Demand Issuance**: Sub-2ms dynamic leaf certificate generation and RAM/disk caching for reverse proxies (`sb-proxy`).
- **OS Trust Store**: Automated installation via `certutil` (Windows), `security` (macOS), or `trust anchor` (Linux).

---

## 2. CLI Reference (`sb-ca`)

```bash
# 1. Initialize both OpenSSH and X.509 Root CAs
sb-ca init

# 2. Check PKI Status
sb-ca status

# 3. Export OpenSSH Root CA Public Key (for sshd TrustedUserCAKeys)
sb-ca ssh ca-pubkey

# 4. Issue OpenSSH User Certificate
sb-ca ssh issue-user \
  --pubkey ~/.ssh/id_ed25519.pub \
  --key-id "operator-alice" \
  --principals "alice,sbadmin" \
  --ttl 3600 \
  --out ~/.ssh/id_ed25519-cert.pub

# 5. Issue OpenSSH Host Certificate
sb-ca ssh issue-host \
  --pubkey /etc/ssh/ssh_host_ed25519_key.pub \
  --hostname "node1.sbm" \
  --ttl 2592000

# 6. Issue X.509 Leaf Certificate for Mesh Domains
sb-ca x509 issue \
  --domains "*.sbm,*.mesh,localhost,127.0.0.1" \
  --ttl-days 90

# 7. Install Root CA into Operating System Trust Store
sb-ca install-root
```

---

## 3. Standards Compliance Radar

| Standard | Organization | Integration in `sb-ca` |
|:---|:---|:---|
| **RFC 4251** | IETF | SSH Protocol Architecture wire format public key serialization |
| **RFC 8709** | IETF | Ed25519 public key algorithm for SSH |
| **PROTOCOL.certkeys** | OpenSSH | OpenSSH certificate format, nonces, serials, and extensions |
| **RFC 5280** | IETF | X.509 PKI certificate profile, SANs, and EKUs |
| **RFC 8446** | IETF | TLS 1.3 mandatory-to-implement ECDSA P-256 certificate profiles |
| **ISO 8601** | ISO/IEC | Timestamps and UTC date serialization |

---

## 4. Dynamic Security & Threat Modeling

In accordance with the Skulls & Bones dynamic threat modeling framework:

1. **CA Key Theft & Memory Scrape (CWE-312 / CWE-316 / CWE-276)**:
   - Root keys are protected with POSIX mode `0o600`.
   - In-memory key buffers implement `zeroize::Zeroize` on drop.
2. **On-Demand CA Stampede DoS (CWE-400 / CWE-770)**:
   - Proxy integration performs eligibility check on SNI hostnames.
   - Cached responses resolve in sub-millisecond memory lookups.
3. **OpenSSH Principal Spoofing (CWE-287 / CWE-269)**:
   - Strict principal character validation; no shell meta-characters.
   - Hard TTL cap of 8 hours on user certificates.
4. **Clock Drift Desynchronization (CWE-294 / CWE-613)**:
   - Validity windows backdate `valid_after` / `not_before` by 60 seconds.
