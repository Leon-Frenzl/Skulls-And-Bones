# S&B Sovereign Key Engine (`sb-key`) — Tactical Roadmap & Architecture TODO

> **Central Cryptographic Identity & Ephemeral Lease Engine • Hardware TPM 2.0 & FIDO2 Security**  
> Das kryptographische Herzstück der Skulls & Bones Sovereign Suite.  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*  

---

## 1. Produkt-Vision & Kernprinzipien

In herkömmlichen Systemen sind private Schlüssel über unzählige Orte verstreut: `~/.ssh/id_ed25519`, GPG-Keyrings, OS-Keychains, `.env`-Dateien und Cloud-KMS-Provider. Diese Zersplitterung führt zu Key-Sprawl, unkontrollierten Daten-Leaks und erzwungenen Abhängigkeiten von proprietären Cloud-Diensten.

**`sb-key`** fungiert als **singuläre, autarke Vertrauens- und Identitäts-Engine** für die gesamte Suite (`sb`, `sb-mesh`, `sb-auth`, `sb-forge`, `sb-node` u. a.):

1. **Air-Gap & Hardware-Unabhängigkeit:**
   - Standardmäßig reine, dateibasierte Ed25519/X25519 Root-Identität (`~/.sb/identity.sbkey`) mit Argon2id + ChaCha20-Poly1305 Verschlüsselung.
   - Kein Zwang zu proprietären Cloud-HSMs oder OS-Keychains.
2. **Modulare Hardware-Verankerung (TPM 2.0 & FIDO2 / YubiKey):**
   - Physischer Diebstahlschutz: Privater Root-Schlüssel kann optional an das lokale **TPM 2.0** (Windows TBS / Linux `/dev/tpmrm0`) oder einen **FIDO2 / YubiKey** (HMAC-Secret / CTAP2) gebunden werden.
   - Alle anderen Werkzeuge (`sb-mesh`, `sb-node`, `sb-auth`) bleiben schlank und frei von Treiber-/Hardware-Logik.
3. **Flüchtige 8-Stunden RAM-Leases:**
   - Aus der Root-Identität werden temporäre, zweckgebundene Sitzungs-Leases im flüchtigen RAM geprägt:
     - `sb-mesh`: Ephemerer WireGuard Session-Key & zeitbegrenztes ZK-Capability-Token.
     - `sb-node`: Ephemeres OpenSSH/Noise Ed25519-Zertifikat bzw. Node-Key (8h Gültigkeit).
     - `sb-forge`: Einmaliger AES-256-GCM Master-Key zur Secret-Injektion im RAM.
4. **Zero Static Network Footprint:**
   - Die Root-Identität berührt niemals das Netzwerk. Alle Pakete und Handshakes nutzen ephemere, rotierende Sitzungsschlüssel.
5. **Instant Zeroize & Panik-Sperre (`sb lock`):**
   - Sofortiges, kryptographisches Schreddern aller flüchtigen Schlüssel im Arbeitsspeicher mit Nullen.

---

## 2. Geplante Modul-Architektur (`tools/sb-key/src/`)

```
tools/sb-key/
├── Cargo.toml
├── TODO.md
├── src/
│   ├── lib.rs                  # Öffentliche Crate-API & KeyManager Engine
│   ├── main.rs                 # Standalone CLI Daemon (`sb-key`)
│   ├── identity/               # Root Identity Management
│   │   ├── mod.rs
│   │   ├── root_key.rs         # Ed25519 + X25519 Dual-Identität
│   │   ├── format.rs           # Armored `.sbkey` Container (Argon2id + ChaCha20)
│   │   └── fingerprint.rs      # Deterministische Identity-Hashes (BLAKE3)
│   ├── lease/                  # Ephemeral Lease Engine
│   │   ├── mod.rs
│   │   ├── mint.rs             # Prägen von 8h-Sitzungsschlüsseln im RAM
│   │   ├── validator.rs        # TTL-Prüfung & mathematischer Verfall
│   │   └── ram_store.rs        # Memory-Locked RAM Puffer mit zeroize-Schutz
│   ├── hardware/               # Silicon Binding & Hardware Passports
│   │   ├── mod.rs
│   │   ├── tpm.rs              # TPM 2.0 Integration (Windows TBS / Linux /dev/tpmrm0)
│   │   └── fido.rs             # FIDO2 / CTAP2 YubiKey Hardware-Token Bindung
│   ├── threshold/              # Mehr-Parteien Krypto & Quorum
│   │   ├── mod.rs
│   │   ├── frost.rs            # FROST Schnorr Threshold Signatures
│   │   └── quorum.rs           # 4-Augen Quorum Policy Engine
│   └── ipc/                    # Lokale Schnittstelle für die Suite
│       ├── mod.rs
│       └── session_socket.rs   # Bereitstellung von RAM-Leases via Named Pipe / Unix Socket
└── tests/
    ├── test_identity_armor.rs
    ├── test_lease_expiry.rs
    └── test_hardware_stub.rs
```

---

## 3. Entwicklungs-Phasen & Meilensteine

### Phase 1: Core Root Identity & Armored Format (Implementiert in Suite)
- [x] **Dateibasierte Root-Identität (`identity.sbkey`):**
  - Erzeugung von Ed25519 (Signaturen) und X25519 (Key-Exchange) Schlüsselpaaren.
  - Schutz durch Argon2id (Memory-Hard KDF) und ChaCha20-Poly1305.
- [x] **Zero-Trace Memory Management:**
  - Automatische Nullung aller Passphrasen und privater Schlüssel im RAM via `zeroize`.

---

### Phase 2: Ephemeral Lease Engine & Suite-Kopplung (Status: 🟢 Implementiert)
- [x] **Unified Lease Minting (`sb lease`):**
  - Prägung von flüchtigen 8h-Sitzungsleases im flüchtigen RAM (`~/.sb/leases/active.ram`).
  - Bereitstellung ephemerer Schlüssel für `sb-node`, `sb-mesh` und `sb-forge` (historisch auch `sb-ssh`).
- [x] **Zeroize auf Lock (`sb lock`):**
  - Sofortiges atomares Schreddern aller flüchtigen Sitzungsdaten im RAM.

---

### Phase 3: Hardware-Verankerung — TPM 2.0 (Status: 🟡 In Planung)
- [ ] **Windows TPM 2.0 Binding (TBS API):**
  - Versiegeln (Sealing) des Entschlüsselungsschlüssels der `identity.sbkey` an das physische TPM des Rechners.
  - Schlüsselfreigabe nur bei unverändertem PCR-Integritätsstatus (Boot-Integrität).
- [ ] **Linux TPM 2.0 Driver Binding (`/dev/tpmrm0`):**
  - Direkte Kommunikation über den TPM-Resource-Manager unter Linux ohne externe Daemon-Abhängigkeiten.

---

### Phase 4: Hardware Security Keys — FIDO2 / YubiKey (Status: 🟡 In Planung)
- [ ] **CTAP2 HMAC-Secret Extension:**
  - Hardware-basierte Zweitfaktor-Entsperrung der Root-Identität via YubiKey / SoloKey Touch.
- [ ] **Resident Keys / Passwordless Mode:**
  - Speichern des Root-Key-Seeds direkt auf dem Secure Element des Hardware-Tokens.

---

### Phase 5: Threshold Signatures & 4-Augen Quorum (Status: 🟡 In Planung)
- [ ] **FROST Schnorr Threshold Signatures:**
  - $k$-aus-$n$ Signatur-Erzeugung für kritische Operationen (z. B. Root-CA-Signatur, Server-Revocation).
- [ ] **P2P Quorum Handshake:**
  - Freigabe-Anfragen werden über das verschlüsselte Sovereign Mesh an Peers gesendet.

